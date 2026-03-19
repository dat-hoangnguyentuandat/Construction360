namespace App.Shared.Constants;

/// <summary>
/// Hằng số toàn ứng dụng.
/// </summary>
public static class AppConstants
{
    public static class Auth
    {
        /// <summary>TTL của one-time login ticket (giây).</summary>
        public const int LoginTicketTtlSeconds = 30;

        /// <summary>TTL của OTP quên mật khẩu (phút).</summary>
        public const int OtpTtlMinutes = 5;

        /// <summary>Cooldown gửi lại OTP (giây).</summary>
        public const int OtpResendCooldownSeconds = 60;

        /// <summary>Độ dài OTP.</summary>
        public const int OtpLength = 6;
    }

    public static class Routes
    {
        public const string Login         = "/account/login";
        public const string Register      = "/account/register";
        public const string ForgotPassword = "/account/forgot-password";
        public const string LoginCallback = "/account/login-callback";
        public const string Logout        = "/account/logout";
    }

    public static class OpenIddict
    {
        public const string ClientId = "construction360-client";
        public const string ClientDisplayName = "Construction 360 Web Client";
    }
}
