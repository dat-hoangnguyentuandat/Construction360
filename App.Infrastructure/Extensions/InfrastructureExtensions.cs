using App.Domain.Entities;
using App.Domain.Interfaces;
using App.Infrastructure.Data;
using App.Infrastructure.Services;
using App.Infrastructure.Workers;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using OpenIddict.Abstractions;

namespace App.Infrastructure.Extensions;

/// <summary>
/// Extension methods để đăng ký tất cả Infrastructure services vào DI container.
/// Gọi từ App.Web/Program.cs để giữ Program.cs gọn gàng.
/// </summary>
public static class InfrastructureExtensions
{
    public static IServiceCollection AddInfrastructure(
        this IServiceCollection services,
        IConfiguration configuration)
    {
        // ── EF Core + PostgreSQL + OpenIddict ──────────────────
        services.AddDbContext<ApplicationDbContext>(options =>
        {
            options.UseNpgsql(
                configuration.GetConnectionString("DefaultConnection"),
                npgsql => npgsql.MigrationsAssembly("App.Infrastructure")
            );
            options.UseOpenIddict();
        });

        // ── ASP.NET Core Identity ──────────────────────────────
        services
            .AddIdentity<ApplicationUser, IdentityRole>(options =>
            {
                var pwd = configuration.GetSection("Identity:Password");
                options.Password.RequireDigit           = pwd.GetValue<bool>("RequireDigit", true);
                options.Password.RequireLowercase       = pwd.GetValue<bool>("RequireLowercase", true);
                options.Password.RequireUppercase       = pwd.GetValue<bool>("RequireUppercase", true);
                options.Password.RequireNonAlphanumeric = pwd.GetValue<bool>("RequireNonAlphanumeric", false);
                options.Password.RequiredLength         = pwd.GetValue<int>("RequiredLength", 8);

                var lockout = configuration.GetSection("Identity:Lockout");
                options.Lockout.DefaultLockoutTimeSpan  = lockout.GetValue<TimeSpan>("DefaultLockoutTimeSpan", TimeSpan.FromMinutes(15));
                options.Lockout.MaxFailedAccessAttempts = lockout.GetValue<int>("MaxFailedAccessAttempts", 5);

                options.User.RequireUniqueEmail = true;
            })
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddDefaultTokenProviders();

        // ── OpenIddict ─────────────────────────────────────────
        services
            .AddOpenIddict()
            .AddCore(options =>
            {
                options.UseEntityFrameworkCore()
                       .UseDbContext<ApplicationDbContext>();
            })
            .AddServer(options =>
            {
                options.SetAuthorizationEndpointUris("/connect/authorize")
                       .SetTokenEndpointUris("/connect/token")
                       .SetLogoutEndpointUris("/connect/logout")
                       .SetUserinfoEndpointUris("/connect/userinfo")
                       .SetIntrospectionEndpointUris("/connect/introspect");

                options.AllowAuthorizationCodeFlow()
                       .AllowRefreshTokenFlow();

                options.RequireProofKeyForCodeExchange();

                options.RegisterScopes(
                    OpenIddictConstants.Scopes.Email,
                    OpenIddictConstants.Scopes.Profile,
                    OpenIddictConstants.Scopes.Roles,
                    "offline_access"
                );

                options.SetAccessTokenLifetime(TimeSpan.FromMinutes(60));
                options.SetRefreshTokenLifetime(TimeSpan.FromDays(14));
                options.SetAuthorizationCodeLifetime(TimeSpan.FromMinutes(5));

                options.AddDevelopmentEncryptionCertificate()
                       .AddDevelopmentSigningCertificate();

                options.UseAspNetCore()
                       .EnableAuthorizationEndpointPassthrough()
                       .EnableTokenEndpointPassthrough()
                       .EnableLogoutEndpointPassthrough()
                       .EnableUserinfoEndpointPassthrough();
            })
            .AddValidation(options =>
            {
                options.UseLocalServer();
                options.UseAspNetCore();
            });

        // ── Infrastructure Services (implement Domain interfaces) ──
        services.AddSingleton<ILoginTicketService, LoginTicketService>();
        services.AddSingleton<IForgotPasswordOtpService, ForgotPasswordOtpService>();
        services.AddTransient<IAppEmailSender, DevEmailSender>();

        // ── Background Services ────────────────────────────────
        services.AddHostedService<OpenIddictSeeder>();

        return services;
    }
}
