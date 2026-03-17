namespace Construction360.Services;

/// <summary>
/// Dev-only email sender — không gửi email thật.
/// In nội dung ra console để dễ lấy OTP khi test.
/// Thay bằng SmtpEmailSender / SendGrid khi lên production.
/// </summary>
public sealed class DevEmailSender : IEmailSender
{
    private readonly ILogger<DevEmailSender> _logger;

    public DevEmailSender(ILogger<DevEmailSender> logger)
        => _logger = logger;

    public Task SendEmailAsync(string toEmail, string subject, string htmlBody)
    {
        _logger.LogWarning(
            """
            ╔══════════════════════════════════════════╗
            ║           [DEV] EMAIL NOT SENT           ║
            ╠══════════════════════════════════════════╣
            ║  To      : {To}
            ║  Subject : {Subject}
            ╠══════════════════════════════════════════╣
            {Body}
            ╚══════════════════════════════════════════╝
            """,
            toEmail, subject, htmlBody);

        return Task.CompletedTask;
    }
}
