using OpenIddict.Abstractions;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Construction360.Workers;

public sealed class OpenIddictSeeder : IHostedService
{
    private readonly IServiceProvider _serviceProvider;
    public OpenIddictSeeder(IServiceProvider serviceProvider) => _serviceProvider = serviceProvider;

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await using var scope = _serviceProvider.CreateAsyncScope();
        var manager = scope.ServiceProvider.GetRequiredService<IOpenIddictApplicationManager>();

        const string clientId = "construction360-client";
        if (await manager.FindByClientIdAsync(clientId, cancellationToken) is null)
        {
            await manager.CreateAsync(new OpenIddictApplicationDescriptor
            {
                ClientId = clientId,
                Type     = ClientTypes.Public,
                DisplayName = "Construction 360 Web Client",
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
