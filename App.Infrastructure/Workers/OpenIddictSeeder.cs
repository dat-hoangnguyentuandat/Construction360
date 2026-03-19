using App.Shared.Constants;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace App.Infrastructure.Workers;

/// <summary>
/// IHostedService — chạy khi app start, seed OpenIddict client application nếu chưa tồn tại.
/// </summary>
public sealed class OpenIddictSeeder : IHostedService
{
    private readonly IServiceProvider _serviceProvider;

    public OpenIddictSeeder(IServiceProvider serviceProvider)
        => _serviceProvider = serviceProvider;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await using var scope = _serviceProvider.CreateAsyncScope();
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        if (await manager.FindByClientIdAsync(AppConstants.OpenIddict.ClientId, cancellationToken) is null)
        {
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId    = AppConstants.OpenIddict.ClientId,
                ClientType  = ClientTypes.Public,
                DisplayName = AppConstants.OpenIddict.ClientDisplayName,
                RedirectUris =
                {
                    new Uri("https://localhost:7011/signin-oidc"),
                    new Uri("http://localhost:5205/signin-oidc"),
                },
                PostLogoutRedirectUris =
                {
                    new Uri("https://localhost:7011/signout-callback-oidc"),
                    new Uri("http://localhost:5205/signout-callback-oidc"),
                },
                Permissions =
                {
                    Permissions.Endpoints.Authorization,
                    Permissions.Endpoints.Logout,
                    Permissions.Endpoints.Token,
                    Permissions.GrantTypes.AuthorizationCode,
                    Permissions.GrantTypes.RefreshToken,
                    Permissions.ResponseTypes.Code,
                    Permissions.Scopes.Email,
                    Permissions.Scopes.Profile,
                    Permissions.Scopes.Roles,
                    $"{Permissions.Prefixes.Scope}offline_access",
                },
                Requirements =
                {
                    Requirements.Features.ProofKeyForCodeExchange,
                },
            }, cancellationToken);
        }
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
