using System.Collections.Concurrent;

namespace Construction360.Services;

/// <summary>
/// Lưu one-time ticket (GUID) → (userId, rememberMe) với TTL 30 giây.
/// Blazor component tạo ticket sau khi xác thực credentials thành công,
/// rồi NavigateTo LoginCallback?ticket=... để Razor Page đổi ticket lấy
/// userId và gọi SignInManager — set cookie đúng cách qua HTTP context.
/// </summary>
public sealed class LoginTicketService
{
    private record TicketEntry(string UserId, bool RememberMe, DateTime ExpiresAt);

    private readonly ConcurrentDictionary<string, TicketEntry> _tickets = new();

    /// <summary>Tạo ticket mới, hợp lệ trong 30 giây.</summary>
    public string CreateTicket(string userId, bool rememberMe)
    {
        PurgeExpired();
        var ticket = Guid.NewGuid().ToString("N");
        _tickets[ticket] = new TicketEntry(userId, rememberMe, DateTime.UtcNow.AddSeconds(30));
        return ticket;
    }

    /// <summary>
    /// Đổi ticket lấy thông tin đăng nhập (one-time use).
    /// Trả về null nếu ticket không tồn tại hoặc đã hết hạn.
    /// </summary>
    public (string UserId, bool RememberMe)? RedeemTicket(string ticket)
    {
        if (_tickets.TryRemove(ticket, out var entry))
        {
            if (DateTime.UtcNow <= entry.ExpiresAt)
                return (entry.UserId, entry.RememberMe);
        }
        return null;
    }

    private void PurgeExpired()
    {
        var now = DateTime.UtcNow;
        foreach (var kv in _tickets)
        {
            if (kv.Value.ExpiresAt < now)
                _tickets.TryRemove(kv.Key, out _);
        }
    }
}
