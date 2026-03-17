using System.ComponentModel.DataAnnotations;

namespace Construction360.Models;

public class LoginModel
{
    [Required(ErrorMessage = "Vui lòng nhập email của bạn")]
    [EmailAddress(ErrorMessage = "Vui lòng nhập đúng định dạng email")]
    public string Email { get; set; } = string.Empty;

    [Required(ErrorMessage = "Vui lòng nhập mật khẩu của bạn")]
    public string Password { get; set; } = string.Empty;

    public bool RememberMe { get; set; }
}
