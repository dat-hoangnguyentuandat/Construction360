using App.Application.Interfaces;
using App.Domain.Entities;
using App.Domain.Constants;
using App.Infrastructure.Configuration;
using App.Infrastructure.Data;
using App.Infrastructure.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Server.AspNetCore;
using Serilog;
using Serilog.Events;
using static OpenIddict.Abstractions.OpenIddictConstants;

// Bootstrap logger: captures startup errors before full Serilog is configured
Log.Logger = new LoggerConfiguration()
    .MinimumLevel.Override("Microsoft", LogEventLevel.Information)
    .Enrich.FromLogContext()
    .WriteTo.Console()
    .CreateBootstrapLogger();

try
{
    Log.Information("Starting Construction360 API");

    var builder = WebApplication.CreateBuilder(args);

    // Serilog — read full config from appsettings
    builder.Host.UseSerilog((context, services, config) =>
        config.ReadFrom.Configuration(context.Configuration)
              .ReadFrom.Services(services)
              .Enrich.FromLogContext());

    // Database
    builder.Services.AddDbContext<AppDbContext>(options =>
    {
        options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection"));
        options.UseOpenIddict();
    });

    // Identity
    builder.Services.AddIdentity<User, IdentityRole<Guid>>(options =>
    {
        options.Password.RequireDigit = true;
        options.Password.RequiredLength = 8;
        options.User.RequireUniqueEmail = true;
    })
    .AddEntityFrameworkStores<AppDbContext>()
    .AddDefaultTokenProviders();

    // OpenIddict
    builder.Services.AddOpenIddict()
        .AddCore(options =>
        {
            options.UseEntityFrameworkCore()
                   .UseDbContext<AppDbContext>();
        })
        .AddServer(options =>
        {
            options.SetTokenEndpointUris("/connect/token")
                   .SetAuthorizationEndpointUris("/connect/authorize")
                   .SetEndSessionEndpointUris("/connect/logout");

            options.RegisterScopes(Scopes.Email, Scopes.Profile, Scopes.Roles, Scopes.OfflineAccess);

            options.AllowPasswordFlow()
                   .AllowRefreshTokenFlow()
                   .AllowAuthorizationCodeFlow();

            options.AddDevelopmentEncryptionCertificate()
                   .AddDevelopmentSigningCertificate();

            options.UseAspNetCore()
                   .EnableTokenEndpointPassthrough()
                   .EnableAuthorizationEndpointPassthrough()
                   .EnableEndSessionEndpointPassthrough();

            var tokenLifetimes = builder.Configuration
                .GetSection("OpenIddict:TokenLifetimes")
                .Get<TokenLifetimesSettings>() ?? new();
            options.SetAccessTokenLifetime(TimeSpan.FromSeconds(tokenLifetimes.AccessTokenSeconds));
            options.SetRefreshTokenLifetime(TimeSpan.FromDays(tokenLifetimes.RefreshTokenDays));
            options.SetAuthorizationCodeLifetime(TimeSpan.FromMinutes(tokenLifetimes.AuthorizationCodeMinutes));
        })
        .AddValidation(options =>
        {
            options.UseLocalServer();
            options.UseAspNetCore();
        });

    builder.Services.AddSession();
    builder.Services.AddRazorPages();
    builder.Services.AddControllers();
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();

    builder.Services.AddScoped<IAuthService, AuthService>();
    builder.Services.AddScoped<IProductService, ProductService>();

    // Authorization Policies
    builder.Services.AddAuthorization(options =>
    {
        // Product permissions
        options.AddPolicy("ProductCreate", policy =>
            policy.RequireClaim("permission", App.Domain.Constants.Permissions.ProductCreate, App.Domain.Constants.Permissions.AdminAll));

        options.AddPolicy("ProductRead", policy =>
            policy.RequireClaim("permission", App.Domain.Constants.Permissions.ProductRead, App.Domain.Constants.Permissions.AdminAll));

        options.AddPolicy("ProductUpdate", policy =>
            policy.RequireClaim("permission", App.Domain.Constants.Permissions.ProductUpdate, App.Domain.Constants.Permissions.AdminAll));

        options.AddPolicy("ProductDelete", policy =>
            policy.RequireClaim("permission", App.Domain.Constants.Permissions.ProductDelete, App.Domain.Constants.Permissions.AdminAll));

        // User permissions
        options.AddPolicy("UserRead", policy =>
            policy.RequireClaim("permission", App.Domain.Constants.Permissions.UserRead, App.Domain.Constants.Permissions.AdminAll));

        options.AddPolicy("UserManage", policy =>
            policy.RequireClaim("permission", App.Domain.Constants.Permissions.UserManage, App.Domain.Constants.Permissions.AdminAll));
    });

    var app = builder.Build();

    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI();
    }

    app.UseHttpsRedirection();
    app.UseStaticFiles();

    // Request logging: logs every HTTP request with method, path, status, elapsed + UserId
    app.UseSerilogRequestLogging(opts =>
    {
        opts.EnrichDiagnosticContext = (diagnosticContext, httpContext) =>
        {
            diagnosticContext.Set("RequestHost", httpContext.Request.Host.Value ?? string.Empty);
            diagnosticContext.Set("RequestScheme", httpContext.Request.Scheme);
            var userId = httpContext.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            if (!string.IsNullOrEmpty(userId))
                diagnosticContext.Set("UserId", userId);
        };
    });

    app.UseSession();
    app.UseAuthentication();
    app.UseAuthorization();
    app.MapRazorPages();
    app.MapControllers();

    // Seed OpenIddict clients
    using (var scope = app.Services.CreateScope())
    {
        await OpenIddictSeeder.SeedAsync(scope.ServiceProvider);
        await RoleSeeder.SeedRolesAsync(scope.ServiceProvider);
    }

    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Application terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}
