using System.Security.Claims;
using App.Application.Interfaces;
using App.Domain.Entities;
using App.Domain.Constants;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using System.Collections.Immutable;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace App.API.Controllers;

public class AuthorizationController : ControllerBase
{
    private readonly UserManager<User> _userManager;
    private readonly SignInManager<User> _signInManager;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictScopeManager _scopeManager;
    private readonly IOpenIddictTokenManager _tokenManager;
    private readonly ILogger<AuthorizationController> _logger;

    public AuthorizationController(
        UserManager<User> userManager,
        SignInManager<User> signInManager,
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictScopeManager scopeManager,
        IOpenIddictTokenManager tokenManager,
        ILogger<AuthorizationController> logger)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _applicationManager = applicationManager;
        _authorizationManager = authorizationManager;
        _scopeManager = scopeManager;
        _tokenManager = tokenManager;
        _logger = logger;
    }

    private async Task<ClaimsIdentity> BuildIdentityAsync(User user)
    {
        var identity = new ClaimsIdentity(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);

        // Subject
        var subClaim = new Claim(OpenIddictConstants.Claims.Subject, user.Id.ToString());
        subClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken,
                                 OpenIddictConstants.Destinations.IdentityToken);
        identity.AddClaim(subClaim);

        // Email
        var emailClaim = new Claim(OpenIddictConstants.Claims.Email, user.Email!);
        emailClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken,
                                   OpenIddictConstants.Destinations.IdentityToken);
        identity.AddClaim(emailClaim);

        // Name
        var nameClaim = new Claim(OpenIddictConstants.Claims.Name, user.FullName ?? user.Email!);
        nameClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken,
                                  OpenIddictConstants.Destinations.IdentityToken);
        identity.AddClaim(nameClaim);

        // Lấy roles từ DB và thêm vào claims
        var roles = await _userManager.GetRolesAsync(user);
        foreach (var role in roles)
        {
            var roleClaim = new Claim(OpenIddictConstants.Claims.Role, role);
            roleClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken,
                                       OpenIddictConstants.Destinations.IdentityToken);
            identity.AddClaim(roleClaim);
        }

        // Permission claims dựa trên roles
        var permissions = new HashSet<string>();
        foreach (var role in roles)
        {
            if (RolePermissions.Mapping.TryGetValue(role, out var rolePermissions))
            {
                foreach (var permission in rolePermissions)
                {
                    permissions.Add(permission);
                }
            }
        }

        foreach (var permission in permissions)
        {
            var permissionClaim = new Claim("permission", permission);
            permissionClaim.SetDestinations(OpenIddictConstants.Destinations.AccessToken,
                                            OpenIddictConstants.Destinations.IdentityToken);
            identity.AddClaim(permissionClaim);
        }

        return identity;
    }

    // Được gọi sau khi Login.cshtml.cs xác thực thành công và redirect về đây.
    // Tạo authorization_code (mã ủy quyền tạm thời, sống 5 phút, dùng 1 lần)
    // rồi redirect về App.Web kèm code trong URL:
    //   https://localhost:7066/signin-oidc?code=<authorization_code>
    // App.Web sẽ nhận code này và gọi Exchange() bên dưới để đổi lấy token thật.
    [HttpGet("~/connect/authorize")]
    [HttpPost("~/connect/authorize")]
    [IgnoreAntiforgeryToken]
    public async Task<IActionResult> Authorize()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        var result = await HttpContext.AuthenticateAsync();
        if (result is not { Succeeded: true })
        {
            return Challenge(new AuthenticationProperties
            {
                RedirectUri = Request.PathBase + Request.Path + QueryString.Create(
                    Request.HasFormContentType ? Request.Form : Request.Query)
            });
        }

        var user = await _userManager.GetUserAsync(result.Principal)
            ?? throw new InvalidOperationException("The user details cannot be retrieved.");

        var application = await _applicationManager.FindByClientIdAsync(request.ClientId!)
            ?? throw new InvalidOperationException("The application cannot be found.");

        var authorizationList = new List<object>();
        await foreach (var item in _authorizationManager.FindAsync(
            subject: await _userManager.GetUserIdAsync(user),
            client: await _applicationManager.GetIdAsync(application),
            status: Statuses.Valid,
            type: AuthorizationTypes.Permanent,
            scopes: request.GetScopes()))
        {
            authorizationList.Add(item);
        }

        var identity = await BuildIdentityAsync(user);

        identity.SetClaim(Claims.Subject, await _userManager.GetUserIdAsync(user))
                .SetClaim(Claims.Email, await _userManager.GetEmailAsync(user))
                .SetClaim(Claims.Name, await _userManager.GetUserNameAsync(user));

        identity.SetScopes(request.GetScopes());
        var resources = new List<string>();
        await foreach (var resource in _scopeManager.ListResourcesAsync(identity.GetScopes()))
            resources.Add(resource);
        identity.SetResources(resources);

        var authorization = authorizationList.LastOrDefault();
        authorization ??= await _authorizationManager.CreateAsync(
            identity: identity,
            subject: await _userManager.GetUserIdAsync(user),
            client: (await _applicationManager.GetIdAsync(application))!,
            type: AuthorizationTypes.Permanent,
            scopes: identity.GetScopes());

        identity.SetAuthorizationId(await _authorizationManager.GetIdAsync(authorization));
        identity.SetDestinations(GetDestinations);

        return SignIn(new ClaimsPrincipal(identity), OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpPost("~/connect/token")]
    public async Task<IActionResult> Exchange()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("OpenIddict request không hợp lệ");

        if (request.IsAuthorizationCodeGrantType())
        {
            var authResult = await HttpContext.AuthenticateAsync(
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            var principal = authResult.Principal!;

            principal.SetDestinations(GetDestinations);

            var userId = principal.GetClaim(OpenIddictConstants.Claims.Subject);
            var user = userId is not null ? await _userManager.FindByIdAsync(userId) : null;
            if (user is not null)
            {
                user.LastLoginAt = DateTime.UtcNow;
                await _userManager.UpdateAsync(user);
            }

            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        // Test Postman
        if (request.IsPasswordGrantType())
        {
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var user = await _userManager.FindByEmailAsync(request.Username!);

            if (user == null || !user.IsActive)
            {
                _logger.LogWarning(
                    "[AUDIT] LOGIN_FAILED | UserId={UserId} | Username={Username} | IP={IpAddress}",
                    request.Username, request.Username, ip);
                return Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            var checkResult = await _signInManager.CheckPasswordSignInAsync(user, request.Password!, lockoutOnFailure: true);

            if (!checkResult.Succeeded)
            {
                _logger.LogWarning(
                    "[AUDIT] LOGIN_FAILED | UserId={UserId} | Username={Username} | IP={IpAddress}",
                    user.Id.ToString(), user.Email, ip);
                return Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
            }

            _logger.LogInformation(
                "[AUDIT] LOGIN_SUCCESS | UserId={UserId} | Username={Username} | IP={IpAddress}",
                user.Id.ToString(), user.Email, ip);

            var identity = await BuildIdentityAsync(user);
            var principal = new ClaimsPrincipal(identity);
            principal.SetScopes(request.GetScopes());

            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        if (request.IsRefreshTokenGrantType())
        {
            var principal = (await HttpContext.AuthenticateAsync(
                OpenIddictServerAspNetCoreDefaults.AuthenticationScheme)).Principal!;
            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }

        return Forbid(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpGet("~/connect/logout")]
    [HttpPost("~/connect/logout")]
    public async Task<IActionResult> Logout()
    {
        var request = HttpContext.GetOpenIddictServerRequest()
            ?? throw new InvalidOperationException("OpenIddict request không hợp lệ");

        var userId = _userManager.GetUserId(User);
        var username = _userManager.GetUserName(User) ?? userId ?? "unknown";

        if (!string.IsNullOrEmpty(userId))
        {
            await foreach (var token in _tokenManager.FindBySubjectAsync(userId))
                await _tokenManager.TryRevokeAsync(token);
        }

        await HttpContext.SignOutAsync(IdentityConstants.ApplicationScheme);

        _logger.LogInformation(
            "[AUDIT] LOGOUT | UserId={UserId} | Username={Username}",
            userId ?? "unknown", username);

        return SignOut(
            authenticationSchemes: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
            properties: new AuthenticationProperties
            {
                RedirectUri = request.PostLogoutRedirectUri ?? "/"
            });
    }

    private static IEnumerable<string> GetDestinations(Claim claim)
    {
        return claim.Type switch
        {
            Claims.Name when claim.Subject!.HasScope(Scopes.Profile)
                => [Destinations.AccessToken, Destinations.IdentityToken],

            Claims.Email when claim.Subject!.HasScope(Scopes.Email)
                => [Destinations.AccessToken, Destinations.IdentityToken],

            Claims.Role when claim.Subject!.HasScope(Scopes.Roles)
                => [Destinations.AccessToken, Destinations.IdentityToken],

            "permission" when claim.Subject!.HasScope(Scopes.Roles)
                => [Destinations.AccessToken, Destinations.IdentityToken],

            _ => [Destinations.AccessToken]
        };
    }
}
