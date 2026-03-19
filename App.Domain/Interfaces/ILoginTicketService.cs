namespace App.Domain.Interfaces;

/// <summary>
/// Interface quản lý one-time ticket cho luồng login của Blazor.
/// Blazor không thể set HTTP cookie trực tiếp → tạo ticket → Razor Page đổi lấy cookie.
/// Tuân thủ DIP: Web layer phụ thuộc vào interface này, không phụ thuộc implementation.
/// </summary>
public interface ILoginTicketService
{
    /// <summary>Tạo ticket mới, hợp lệ trong 30 giây.</summary>
    string CreateTicket(string userId, bool rememberMe);

    /// <summary>
    /// Đổi ticket lấy thông tin đăng nhập (one-time use).
    /// Trả về null nếu ticket không tồn tại hoặc đã hết hạn.
    /// </summary>
    (string UserId, bool RememberMe)? RedeemTicket(string ticket);
}
