using System.Collections.Concurrent;
using System.Security.Cryptography;

namespace Construction360.Services;

/// <summary>
/// Quản lý OTP cho luồng quên mật khẩu.
/// - OTP: 6 ký tự alphanumeric (không gây nhầm lẫn O/0, I/l/1)
/// - TTL: 5 phút kể từ lần gửi cuối
/// - Resend cooldown: 60 giây
/// - One-time use: tự xóa sau khi ValidateAndConsume thành công
/// </summary>
public sealed class ForgotPasswordOtpService
{
    private record OtpEntry(
        string Code,
        string UserId,
        DateTime ExpiresAt,
        DateTime LastSentAt);

    // key = email lowercase
    private readonly ConcurrentDictionary<string, OtpEntry> _store = new();

    // Ký tự dễ đọc, tránh nhầm O/0, I/l/1
    private static readonly char[] Alphabet =
        "ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789".ToCharArray();

    // ── Tạo / gửi lại OTP ───────────────────────────────────────
    /// <summary>
    /// Tạo OTP mới cho email, ghi đè entry cũ nếu đã hết cooldown.
    /// Trả về (code, true) nếu thành công; (null, false) nếu vẫn trong cooldown.
    /// </summary>
    public (string? Code, bool Success) GenerateOtp(string email, string userId)
    {
        var key  = email.ToLowerInvariant();
        var now  = DateTime.UtcNow;

        if (_store.TryGetValue(key, out var existing))
        {
            if (now < existing.LastSentAt.AddSeconds(60))
                return (null, false); // còn trong cooldown
        }

        PurgeExpired();
        var code = CreateCode();
        _store[key] = new OtpEntry(code, userId, now.AddMinutes(5), now);
        return (code, true);
    }

    // ── Kiểm tra cooldown ────────────────────────────────────────
    /// <summary>Số giây còn lại của cooldown. 0 = có thể gửi lại.</summary>
    public int ResendCooldownSeconds(string email)
    {
        var key = email.ToLowerInvariant();
        if (!_store.TryGetValue(key, out var entry)) return 0;
        var remaining = (int)(entry.LastSentAt.AddSeconds(60) - DateTime.UtcNow).TotalSeconds;
        return remaining > 0 ? remaining : 0;
    }

    // ── Validate + consume (one-time use) ────────────────────────
    /// <summary>
    /// Kiểm tra OTP. Nếu đúng → xóa entry (one-time use) và trả về userId.
    /// </summary>
    public (bool Valid, string? UserId, string? Error) ValidateAndConsume(string email, string code)
    {
        var key = email.ToLowerInvariant();

        if (!_store.TryGetValue(key, out var entry))
            return (false, null, "Mã xác thực không chính xác. Vui lòng kiểm tra lại.");

        if (DateTime.UtcNow > entry.ExpiresAt)
        {
            _store.TryRemove(key, out _);
            return (false, null, "Mã xác thực đã hết hạn. Vui lòng gửi lại mã mới.");
        }

        if (!string.Equals(entry.Code, code.Trim(), StringComparison.Ordinal))
            return (false, null, "Mã xác thực không chính xác. Vui lòng kiểm tra lại.");

        // Hợp lệ → xóa để không dùng lại
        _store.TryRemove(key, out _);
        return (true, entry.UserId, null);
    }

    // ── Private helpers ─────────────────────────────────────────
    private static string CreateCode()
    {
        Span<byte> bytes = stackalloc byte[6];
        RandomNumberGenerator.Fill(bytes);
        var chars = new char[6];
        for (var i = 0; i < 6; i++)
            chars[i] = Alphabet[bytes[i] % Alphabet.Length];
        return new string(chars);
    }

    private void PurgeExpired()
    {
        var now = DateTime.UtcNow;
        foreach (var kv in _store)
            if (kv.Value.ExpiresAt < now)
                _store.TryRemove(kv.Key, out _);
    }
}
