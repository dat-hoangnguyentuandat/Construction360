using Microsoft.AspNetCore.Identity;

namespace Construction360.Models;

public class ApplicationUser : IdentityUser
{
    public string? FullName { get; set; }
    public DateTime? DateOfBirth { get; set; }
    public string? Company { get; set; }
    public string? Position { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastLoginAt { get; set; }
    public bool IsActive { get; set; } = true;
}
