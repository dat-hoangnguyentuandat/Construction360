using System.Collections.Immutable;
using System.Security.Claims;
using Construction360.Models;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Construction360.Controllers;

/// <summary>
/// Xử lý 4 OpenIddict passthrough endpoints:
///   GET/POST /connect/authorize   — Authorization endpoint (Phase 2 core)
///   POST      /connect/token      — Token exchange (auth code → tokens, refresh token)
///   GET/POST  /connect/logout     — OIDC logout
///   GET/POST  /connect/userinfo   — Trả về user claims theo scopes
/// </summary>
[ApiController]
public class AuthorizationController : ControllerBase
{
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictScopeManager       _scopeManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser>   _userManager;

    public AuthorizationController(
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictScopeManager       scopeManager,
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser>   userManager)
    {
        _applicationManager = applicationManager;
        _scopeManager       = scopeManager;
        _signInManager      = signInManager;
        _userManager        = userManager;
    }

    // ══════════════════════════════════════════════════════════════════
    //  GET/POST /connect/authorize
    // ══════════════════════════════════════════════════════════════════
    /// <summary>
    /// Client redirect đến đây để bắt đầu Authorization Code flow.
    /// Nếu user chưa đăng nhập → Challenge → redirect /account/login?returnUrl=...
    /// Nếu đã đăng nhập → tạo ClaimsPrincipal → SignIn OpenIddict scheme
    ///                   → OpenIddict tự redirect client kèm authorization code.
    /// </summary>
    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("Không thể lấy OpenIddict server request.");

        // Kiểm tra user đã đăng nhập chưa (qua Identity cookie)
        var result = await HttpContext.AuthenticateAsync(IdentityConstants.ApplicationScheme);

        if (!result.Succeeded)
        {
            // Chưa đăng nhập → Challenge: cookie handler sẽ redirect đến
            // /account/login?returnUrl=/connect/authorize?...
            // Sau khi login xong, LoginCallback redirect trở lại đây.
            return Challenge(
                authenticationSchemes: IdentityConstants.ApplicationScheme,
                properties: new AuthenticationProperties
                {
                    RedirectUri = Request.PathBase + Request.Path + Request.QueryString
                });
        }

        // Đã đăng nhập → lấy thông tin user
        var user = await _userManager.GetUserAsync(result.Principal)
            ?? throw new InvalidOperationException("Không tìm thấy thông tin user.");

        // Tạo ClaimsIdentity cho OpenIddict
        var identity = new ClaimsIdentity(
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType:           Claims.Name,
            roleType:           Claims.Role);

        // Thêm claims cơ bản
        identity
            .SetClaim(Claims.Subject,  await _userManager.GetUserIdAsync(user))
            .SetClaim(Claims.Email,    await _userManager.GetEmailAsync(user) ?? string.Empty)
            .SetClaim(Claims.Name,     user.FullName ?? user.UserName ?? string.Empty)
            .SetClaim(Claims.PreferredUsername, user.UserName ?? string.Empty)
            .SetClaims(Claims.Role,    (await _userManager.GetRolesAsync(user)).ToImmutableArray());

        // Áp dụng scopes được request
        identity.SetScopes(request.GetScopes());

        // Xác định resources (audiences) theo scopes
        var resources = new List<string>();
        await foreach (var resource in _scopeManager.ListResourcesAsync(identity.GetScopes()))
            resources.Add(resource);
        identity.SetResources(resources);

        // Gán destinations (AccessToken vs IdentityToken) cho từng claim
        identity.SetDestinations(GetDestinations);

        return SignIn(
            new ClaimsPrincipal(identity),
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    // ══════════════════════════════════════════════════════════════════
    //  POST /connect/token
    // ══════════════════════════════════════════════════════════════════
    /// <summary>
    /// Client gửi authorization code (+ code_verifier) để đổi lấy tokens.
    /// Cũng xử lý refresh_token grant để cấp access_token mới.
    /// </summary>
    [HttpPost("~/connect/token")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("Không thể lấy OpenIddict server request.");

        if (!request.IsAuthorizationCodeGrantType() && !request.IsRefreshTokenGrantType())
            throw new InvalidOperationException("Grant type không được hỗ trợ.");

        // Lấy ClaimsPrincipal từ authorization code / refresh token đã được validate bởi OpenIddict
        var result = await HttpContext.AuthenticateAsync(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        // Lấy userId từ Subject claim trong principal
        var userId = result.Principal!.GetClaim(Claims.Subject);
        var user   = userId is not null ? await _userManager.FindByIdAsync(userId) : null;

        if (user is null)
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error]            = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Token không còn hợp lệ."
                }));
        }

        if (!user.IsActive)
        {
            return Forbid(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error]            = Errors.InvalidGrant,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Tài khoản đã bị vô hiệu hoá."
                }));
        }

        // Tạo identity mới với claims cập nhật (user có thể đã đổi role kể từ khi cấp code)
        var identity = new ClaimsIdentity(
            result.Principal!.Claims,
            authenticationType: TokenValidationParameters.DefaultAuthenticationType,
            nameType:           Claims.Name,
            roleType:           Claims.Role);

        identity
            .SetClaim(Claims.Subject,  await _userManager.GetUserIdAsync(user))
            .SetClaim(Claims.Email,    await _userManager.GetEmailAsync(user) ?? string.Empty)
            .SetClaim(Claims.Name,     user.FullName ?? user.UserName ?? string.Empty)
            .SetClaim(Claims.PreferredUsername, user.UserName ?? string.Empty)
            .SetClaims(Claims.Role,    (await _userManager.GetRolesAsync(user)).ToImmutableArray());

        identity.SetDestinations(GetDestinations);

        return SignIn(
            new ClaimsPrincipal(identity),
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    // ══════════════════════════════════════════════════════════════════
    //  GET/POST /connect/logout  (OIDC logout)
    // ══════════════════════════════════════════════════════════════════
    /// <summary>
    /// OIDC end-session endpoint — khác với /account/logout (app-level).
    /// Xóa Identity cookie → OpenIddict redirect về post_logout_redirect_uri.
    /// </summary>
    [HttpGet("~/connect/logout")]
    [HttpPost("~/connect/logout")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> LogoutEndpoint()
    {
        // Xóa Identity authentication cookie
        await _signInManager.SignOutAsync();

        // SignOut OpenIddict scheme → tự redirect về post_logout_redirect_uri
        return SignOut(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties
            {
                RedirectUri = "/"
            });
    }

    // ══════════════════════════════════════════════════════════════════
    //  GET/POST /connect/userinfo
    // ══════════════════════════════════════════════════════════════════
    /// <summary>
    /// Trả về user claims tương ứng với scopes trong access token.
    /// </summary>
    [HttpGet("~/connect/userinfo")]
    [HttpPost("~/connect/userinfo")]
    public async Task<IActionResult> Userinfo()
    {
        var claimsPrincipal = (await HttpContext.AuthenticateAsync(
            OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal;

        var user = await _userManager.GetUserAsync(claimsPrincipal!);
        if (user is null)
        {
            return Challenge(
                authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                properties: new AuthenticationProperties(new Dictionary<string, string?>
                {
                    [OpenIddictServerAspNetCoreConstants.Properties.Error]            = Errors.InvalidToken,
                    [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = "Token không hợp lệ."
                }));
        }

        var claims = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            // Subject luôn được trả về
            [Claims.Subject] = await _userManager.GetUserIdAsync(user)
        };

        if (claimsPrincipal!.HasScope(Scopes.Email))
        {
            claims[Claims.Email]          = await _userManager.GetEmailAsync(user) ?? string.Empty;
            claims[Claims.EmailVerified]  = await _userManager.IsEmailConfirmedAsync(user);
        }

        if (claimsPrincipal.HasScope(Scopes.Profile))
        {
            claims[Claims.Name]              = user.FullName ?? user.UserName ?? string.Empty;
            claims[Claims.PreferredUsername] = user.UserName ?? string.Empty;

            if (user.DateOfBirth.HasValue)
                claims[Claims.Birthdate] = user.DateOfBirth.Value.ToString("yyyy-MM-dd");
        }

        if (claimsPrincipal.HasScope(Scopes.Phone))
        {
            var phone = await _userManager.GetPhoneNumberAsync(user);
            if (!string.IsNullOrEmpty(phone))
                claims[Claims.PhoneNumber] = phone;
        }

        if (claimsPrincipal.HasScope(Scopes.Roles))
        {
            var roles = await _userManager.GetRolesAsync(user);
            if (roles.Count > 0)
                claims[Claims.Role] = roles;
        }

        return Ok(claims);
    }

    // ══════════════════════════════════════════════════════════════════
    //  Helper: xác định claim đi vào token nào
    // ══════════════════════════════════════════════════════════════════
    private static IEnumerable<string> GetDestinations(Claim claim)
    {
        switch (claim.Type)
        {
            // Name / PreferredUsername
            case Claims.Name or Claims.PreferredUsername:
                yield return Destinations.AccessToken;
                if (claim.Subject!.HasScope(Scopes.Profile))
                    yield return Destinations.IdentityToken;
                yield break;

            // Email
            case Claims.Email:
                yield return Destinations.AccessToken;
                if (claim.Subject!.HasScope(Scopes.Email))
                    yield return Destinations.IdentityToken;
                yield break;

            // Role
            case Claims.Role:
                yield return Destinations.AccessToken;
                if (claim.Subject!.HasScope(Scopes.Roles))
                    yield return Destinations.IdentityToken;
                yield break;

            // SecurityStamp — KHÔNG bao giờ đưa vào token
            case "AspNet.Identity.SecurityStamp":
                yield break;

            // Mọi claim khác → chỉ vào AccessToken
            default:
                yield return Destinations.AccessToken;
                yield break;
        }
    }
}
