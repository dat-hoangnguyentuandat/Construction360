namespace App.Domain.Interfaces;

/// <summary>
/// Interface gửi email — Domain định nghĩa contract, Infrastructure implement.
/// Tuân thủ DIP: domain không phụ thuộc vào implementation cụ thể.
/// Đặt tên IAppEmailSender để tránh xung đột với IEmailSender&lt;TUser&gt; của ASP.NET Identity.
/// </summary>
public interface IAppEmailSender
{
    Task SendEmailAsync(string toEmail, string subject, string htmlBody);
}
