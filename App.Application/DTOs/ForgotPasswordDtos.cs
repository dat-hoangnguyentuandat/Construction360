using System.ComponentModel.DataAnnotations;

namespace App.Application.DTOs;

// ── Step 1: nhập email ───────────────────────────────────────
public class ForgotPasswordEmailDto
{
    [Required(ErrorMessage = "Vui lòng nhập email của bạn")]
    [EmailAddress(ErrorMessage = "Vui lòng nhập đúng dạng email")]
    public string Email { get; set; } = string.Empty;
}

// ── Step 2: nhập OTP + mật khẩu mới ─────────────────────────
public class ResetPasswordDto : IValidatableObject
{
    [Required(ErrorMessage = "Vui lòng nhập mã xác thực")]
    [StringLength(6, MinimumLength = 6, ErrorMessage = "Mã xác thực gồm 6 ký tự")]
    public string Otp { get; set; } = string.Empty;

    [Required(ErrorMessage = "Vui lòng nhập mật khẩu")]
    [MinLength(8, ErrorMessage = "Sử dụng tối thiểu 8 ký tự, bao gồm chữ cái, chữ số và ký tự đặc biệt")]
    public string Password { get; set; } = string.Empty;

    [Required(ErrorMessage = "Vui lòng nhập mật khẩu")]
    public string ConfirmPassword { get; set; } = string.Empty;

    public IEnumerable<ValidationResult> Validate(ValidationContext validationContext)
    {
        if (!string.IsNullOrEmpty(Password)
            && !string.IsNullOrEmpty(ConfirmPassword)
            && Password != ConfirmPassword)
        {
            yield return new ValidationResult(
                "Mật khẩu không trùng khớp",
                new[] { nameof(ConfirmPassword) });
        }
    }
}
