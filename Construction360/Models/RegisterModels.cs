using System.ComponentModel.DataAnnotations;

namespace Construction360.Models;

// ── Step 1: thông tin cơ bản ────────────────────────────────
public class RegisterInfoModel
{
    [Required(ErrorMessage = "Vui lòng nhập email của bạn")]
    [EmailAddress(ErrorMessage = "Vui lòng nhập đúng định dạng email")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "Vui lòng nhập số điện thoại của bạn")]
    [RegularExpression(@"^(0[35789]\d{8})$",
        ErrorMessage = "Vui lòng nhập đúng định dạng số điện thoại")]
    public string PhoneNumber { get; set; } = string.Empty;

    public string? FullName { get; set; }

    public DateOnly? DateOfBirth { get; set; }

    public string? Company { get; set; }

    public string? Position { get; set; }
}

// ── Step 2: tạo mật khẩu ────────────────────────────────────
public class RegisterPasswordModel : IValidatableObject
{
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
