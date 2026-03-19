using App.Domain.Entities;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using OpenIddict.Abstractions;

namespace App.Web.Pages.Account;

/// <summary>
/// Razor Page xử lý logout — không render HTML.
/// Thứ tự: revoke OpenIddict tokens → SignOut cookie → redirect login.
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
        var userId = _userManager.GetUserId(User);

        if (!string.IsNullOrEmpty(userId))
        {
            await foreach (var token in _tokenManager.FindBySubjectAsync(userId))
            {
                await _tokenManager.TryRevokeAsync(token);
            }
        }

        await _signInManager.SignOutAsync();

        return Redirect("/account/login");
    }

    public async Task<IActionResult> OnPostAsync() => await OnGetAsync();
}
