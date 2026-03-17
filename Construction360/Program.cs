using Construction360.Data;
using Construction360.Models;
using Construction360.Workers;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OpenIddict.Abstractions;

var builder = WebApplication.CreateBuilder(args);

// EF Core + PostgreSQL + OpenIddict tables
builder.Services.AddDbContext<ApplicationDbContext>(options =>
{
    options.UseNpgsql(
        builder.Configuration.GetConnectionString("DefaultConnection"),
        npgsql => npgsql.MigrationsAssembly("Construction360")
    );
    // Cho phép OpenIddict dùng EF Core store
    options.UseOpenIddict();
});

// ASP.NET Core Identity
builder.Services
    .AddIdentity<ApplicationUser, IdentityRole>(options =>
    {
        // Password policy — đọc từ config
        var pwd = builder.Configuration.GetSection("Identity:Password");
        options.Password.RequireDigit           = pwd.GetValue<bool>("RequireDigit", true);
        options.Password.RequireLowercase       = pwd.GetValue<bool>("RequireLowercase", true);
        options.Password.RequireUppercase       = pwd.GetValue<bool>("RequireUppercase", true);
        options.Password.RequireNonAlphanumeric = pwd.GetValue<bool>("RequireNonAlphanumeric", false);
        options.Password.RequiredLength         = pwd.GetValue<int>("RequiredLength", 8);

        // Lockout policy
        var lockout = builder.Configuration.GetSection("Identity:Lockout");
        options.Lockout.DefaultLockoutTimeSpan  = lockout.GetValue<TimeSpan>("DefaultLockoutTimeSpan", TimeSpan.FromMinutes(15));
        options.Lockout.MaxFailedAccessAttempts = lockout.GetValue<int>("MaxFailedAccessAttempts", 5);

        // User settings
        options.User.RequireUniqueEmail = true;
    })
    .AddEntityFrameworkStores<ApplicationDbContext>()
    .AddDefaultTokenProviders();

// Cookie configuration
builder.Services.ConfigureApplicationCookie(options =>
{
    options.LoginPath        = "/Account/Login";
    options.LogoutPath       = "/Account/Logout";
    options.AccessDeniedPath = "/Account/AccessDenied";
    options.SlidingExpiration = true;
    options.ExpireTimeSpan   = TimeSpan.FromHours(8);
});

// OpenIddict — Server (Authorization Code + PKCE + Refresh Token)
builder.Services
    .AddOpenIddict()

    // Core — dùng EF Core store
    .AddCore(options =>
    {
        options.UseEntityFrameworkCore()
               .UseDbContext<ApplicationDbContext>();
    })

    // Server
    .AddServer(options =>
    {
        // Endpoints
        options.SetAuthorizationEndpointUris("/connect/authorize")
               .SetTokenEndpointUris("/connect/token")
               .SetLogoutEndpointUris("/connect/logout")
               .SetUserinfoEndpointUris("/connect/userinfo")
               .SetIntrospectionEndpointUris("/connect/introspect");

        // Flows
        options.AllowAuthorizationCodeFlow()
               .AllowRefreshTokenFlow();

        // Require PKCE cho Authorization Code
        options.RequireProofKeyForCodeExchange();

        // Scopes
        options.RegisterScopes(
            OpenIddictConstants.Scopes.Email,
            OpenIddictConstants.Scopes.Profile,
            OpenIddictConstants.Scopes.Roles,
            "offline_access"
        );

        // Token lifetimes
        options.SetAccessTokenLifetime(TimeSpan.FromMinutes(60));
        options.SetRefreshTokenLifetime(TimeSpan.FromDays(14));
        options.SetAuthorizationCodeLifetime(TimeSpan.FromMinutes(5));

        // Development certificates
        options.AddDevelopmentEncryptionCertificate()
               .AddDevelopmentSigningCertificate();

        // Passthrough — OpenIddict uỷ quyền xử lý cho Razor Pages / Controllers
        options.UseAspNetCore()
               .EnableAuthorizationEndpointPassthrough()
               .EnableTokenEndpointPassthrough()
               .EnableLogoutEndpointPassthrough()
               .EnableUserinfoEndpointPassthrough();
    })

    // Validation — dùng local server
    .AddValidation(options =>
    {
        options.UseLocalServer();
        options.UseAspNetCore();
    });

// OpenIddict seeder (IHostedService)
builder.Services.AddHostedService<OpenIddictSeeder>();


// Blazor services
builder.Services.AddRazorPages();
builder.Services.AddServerSideBlazor();


var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

// Authentication + Authorization
app.UseAuthentication();
app.UseAuthorization();

// Endpoints
app.MapRazorPages();
app.MapBlazorHub();
app.MapFallbackToPage("/_Host");

app.Run();
