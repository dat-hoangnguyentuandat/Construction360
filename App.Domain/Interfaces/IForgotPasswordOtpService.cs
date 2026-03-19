namespace App.Domain.Interfaces;

/// <summary>
/// Interface quản lý OTP cho luồng quên mật khẩu.
/// Tuân thủ DIP: Web layer phụ thuộc vào interface này, không phụ thuộc implementation.
/// </summary>
public interface IForgotPasswordOtpService
{
    /// <summary>
    /// Tạo OTP mới cho email, ghi đè entry cũ nếu đã hết cooldown.
    /// Trả về (code, true) nếu thành công; (null, false) nếu vẫn trong cooldown.
    /// </summary>
    (string? Code, bool Success) GenerateOtp(string email, string userId);

    /// <summary>Số giây còn lại của cooldown. 0 = có thể gửi lại.</summary>
    int ResendCooldownSeconds(string email);

    /// <summary>
    /// Kiểm tra OTP. Nếu đúng → xóa entry (one-time use) và trả về userId.
    /// </summary>
    (bool Valid, string? UserId, string? Error) ValidateAndConsume(string email, string code);
}
