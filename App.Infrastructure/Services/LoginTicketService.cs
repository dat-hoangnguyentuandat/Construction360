using System.Collections.Concurrent;
using App.Domain.Interfaces;
using App.Shared.Constants;

namespace App.Infrastructure.Services;

/// <summary>
/// Implement ILoginTicketService — lưu one-time ticket (GUID) → (userId, rememberMe) với TTL 30 giây.
/// Blazor component tạo ticket sau khi xác thực credentials thành công,
/// rồi NavigateTo LoginCallback?ticket=... để Razor Page đổi ticket lấy
/// userId và gọi SignInManager — set cookie đúng cách qua HTTP context.
/// </summary>
public sealed class LoginTicketService : ILoginTicketService
{
    private record TicketEntry(string UserId, bool RememberMe, DateTime ExpiresAt);

    private readonly ConcurrentDictionary<string, TicketEntry> _tickets = new();

    /// <inheritdoc/>
    public string CreateTicket(string userId, bool rememberMe)
    {
        PurgeExpired();
        var ticket = Guid.NewGuid().ToString("N");
        _tickets[ticket] = new TicketEntry(
            userId,
            rememberMe,
            DateTime.UtcNow.AddSeconds(AppConstants.Auth.LoginTicketTtlSeconds));
        return ticket;
    }

    /// <inheritdoc/>
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
