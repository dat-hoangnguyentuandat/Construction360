using Construction360.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;

namespace Construction360.Pages.Account;

/// <summary>
/// Razor Page xử lý logout — không render HTML.
/// Được gọi bằng NavigationManager.NavigateTo("/account/logout", forceLoad: true)
/// từ bất kỳ Blazor component nào.
///
/// Thứ tự thực hiện:
///   1. Lấy userId từ HttpContext.User (còn hợp lệ trước khi sign out)
///   2. Revoke tất cả OpenIddict refresh/access tokens của user
///   3. SignInManager.SignOutAsync() — xóa authentication cookie
///   4. Redirect về trang login
/// </summary>
public sealed class LogoutModel : PageModel
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser>   _userManager;
    private readonly IOpenIddictTokenManager        _tokenManager;

    public LogoutModel(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser>   userManager,
        IOpenIddictTokenManager        tokenManager)
    {
        _signInManager = signInManager;
        _userManager   = userManager;
        _tokenManager  = tokenManager;
    }

    public async Task<IActionResult> OnGetAsync()
    {
        // 1. Lấy userId trước khi sign out (sau sign out User.Identity sẽ null)
        var userId = _userManager.GetUserId(User);

        // 2. Revoke tất cả OpenIddict tokens của user
        if (!string.IsNullOrEmpty(userId))
        {
            await foreach (var token in _tokenManager.FindBySubjectAsync(userId))
            {
                await _tokenManager.TryRevokeAsync(token);
            }
        }

        // 3. Xóa authentication cookie
        await _signInManager.SignOutAsync();

        return Redirect("/account/login");
    }

    // Hỗ trợ POST (anti-CSRF form submit) — cùng logic với GET
    public async Task<IActionResult> OnPostAsync() => await OnGetAsync();
}
