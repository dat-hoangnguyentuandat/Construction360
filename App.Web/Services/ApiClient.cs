using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

namespace App.Web.Services;

public class ApiClient
{
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IHttpClientFactory _httpClientFactory;

    private string? _accessToken;
    private string? _refreshToken;
    private bool _tokensLoaded;

    public ApiClient(IHttpContextAccessor httpContextAccessor, IHttpClientFactory httpClientFactory)
    {
        _httpContextAccessor = httpContextAccessor;
        _httpClientFactory = httpClientFactory;
    }

    private async Task EnsureTokensLoadedAsync()
    {
        if (_tokensLoaded) return;
        var ctx = _httpContextAccessor.HttpContext!;
        _accessToken = await ctx.GetTokenAsync("access_token");
        _refreshToken = await ctx.GetTokenAsync("refresh_token");
        _tokensLoaded = true;
    }

    // Gọi API với cơ chế tự động làm mới token:
    // 1. Gửi request với access_token hiện tại
    // 2. Nếu nhận 401 (AT hết hạn) → gọi RefreshTokenAsync để lấy AT mới
    // 3. Gửi lại request với AT mới
    // Nếu refresh cũng thất bại → trả về response 401 gốc (user cần đăng nhập lại)
    public async Task<HttpResponseMessage> CallApiAsync(
        HttpMethod method, string path, object? body = null)
    {
        await EnsureTokensLoadedAsync();

        var ctx = _httpContextAccessor.HttpContext!;
        var client = _httpClientFactory.CreateClient("api");

        async Task<HttpResponseMessage> Send()
        {
            var req = new HttpRequestMessage(method, path);
            req.Headers.Authorization = new AuthenticationHeaderValue("Bearer", _accessToken);
            if (body is not null)
                req.Content = new StringContent(
                    JsonSerializer.Serialize(body), Encoding.UTF8, "application/json");
            return await client.SendAsync(req);
        }

        var response = await Send();

        // AT còn hạn → trả về kết quả luôn
        if (response.StatusCode != System.Net.HttpStatusCode.Unauthorized)
            return response;

        // AT hết hạn → thử refresh, nếu thành công thì gọi lại API
        if (!await RefreshTokenAsync(ctx, client))
            return response;

        return await Send();
    }

    // Đổi refresh_token lấy cặp token mới từ App.API (/connect/token)
    // Sau khi nhận token mới: cập nhật _accessToken/_refreshToken trong memory
    // và ghi đè cookie để lần request tiếp theo dùng token mới
    // Token rotation: refresh_token cũ bị đánh dấu "redeemed" trong DB,
    private async Task<bool> RefreshTokenAsync(HttpContext ctx, HttpClient client)
    {
        if (string.IsNullOrWhiteSpace(_refreshToken)) return false;

        // Gọi POST /connect/token với grant_type=refresh_token
        var response = await client.PostAsync("/connect/token",
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                ["grant_type"] = "refresh_token",
                ["refresh_token"] = _refreshToken,
                ["client_id"] = "app-web",
                ["client_secret"] = "app-web-secret",
            }));

        if (!response.IsSuccessStatusCode) return false;

        using var payload = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        if (!payload.RootElement.TryGetProperty("access_token", out var at)) return false;
        var newAccessToken = at.GetString();
        if (string.IsNullOrWhiteSpace(newAccessToken)) return false;

        // Cập nhật token mới vào memory để dùng ngay cho request retry
        _accessToken = newAccessToken;

        if (payload.RootElement.TryGetProperty("refresh_token", out var rt))
        {
            var newRt = rt.GetString();
            if (!string.IsNullOrWhiteSpace(newRt)) _refreshToken = newRt;
        }

        // Ghi token mới vào cookie
        var authResult = await ctx.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        if (authResult.Succeeded && authResult.Properties is not null)
        {
            authResult.Properties.UpdateTokenValue("access_token", _accessToken);
            authResult.Properties.UpdateTokenValue("refresh_token", _refreshToken ?? "");

            if (payload.RootElement.TryGetProperty("expires_in", out var ei)
                && ei.TryGetInt32(out var expiresIn))
            {
                authResult.Properties.UpdateTokenValue(
                    "expires_at",
                    DateTimeOffset.UtcNow.AddSeconds(expiresIn).ToString("o"));
            }

            await ctx.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                authResult.Principal!,
                authResult.Properties);
        }

        return true;
    }
}
