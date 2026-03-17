using Construction360.Models;
using Construction360.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;

namespace Construction360.Pages.Account;

/// <summary>
/// Razor Page nhận one-time ticket từ Blazor Login component,
/// đổi ticket lấy userId → gọi SignInManager.SignInAsync (set cookie),
/// rồi redirect về trang chủ.
/// Không render HTML — chỉ xử lý GET và redirect.
/// </summary>
public class LoginCallbackModel : PageModel
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser>   _userManager;
    private readonly LoginTicketService             _ticketService;

    public LoginCallbackModel(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser>   userManager,
        LoginTicketService             ticketService)
    {
        _signInManager = signInManager;
        _userManager   = userManager;
        _ticketService = ticketService;
    }

    public async Task<IActionResult> OnGetAsync(string? ticket, string? returnUrl)
    {
        if (string.IsNullOrWhiteSpace(ticket))
            return Redirect("/account/login");

        var result = _ticketService.RedeemTicket(ticket);
        if (result is null)
            return Redirect("/account/login?error=expired");

        var user = await _userManager.FindByIdAsync(result.Value.UserId);
        if (user is null || !user.IsActive)
            return Redirect("/account/login?error=inactive");

        // Cập nhật LastLoginAt
        user.LastLoginAt = DateTime.UtcNow;
        await _userManager.UpdateAsync(user);

        await _signInManager.SignInAsync(user, isPersistent: result.Value.RememberMe);

        var destination = !string.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl)
            ? returnUrl
            : "/";

        return Redirect(destination);
    }
}
