using Microsoft.AspNetCore.Identity;

namespace App.Domain.Entities;

/// <summary>
/// Entity người dùng — mở rộng từ ASP.NET Core Identity IdentityUser.
/// Chứa các trường profile bổ sung cho hệ thống Construction360.
/// </summary>
public class ApplicationUser : IdentityUser
{
    public string? FullName { get; set; }
    public DateOnly? DateOfBirth { get; set; }
    public string? Company { get; set; }
    public string? Position { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastLoginAt { get; set; }
    public bool IsActive { get; set; } = true;
}
