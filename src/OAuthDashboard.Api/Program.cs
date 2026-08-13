using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;
using OAuthDashboard.Infrastructure.Accounts;
using OAuthDashboard.Infrastructure.Auth;
using OAuthDashboard.Infrastructure.Persistence;
using OAuthDashboard.Infrastructure.Security;
using OAuthDashboard.Infrastructure.Users;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

// The SPA runs on its own origin, so every call it makes here is cross-origin. Because those
// calls carry the BFF session cookie, the CORS policy below has to name the origin explicitly —
// AllowCredentials is illegal in combination with a wildcard origin, by design: it would let
// any site on the internet make authenticated calls with the user's cookie.
var spaOrigin = (builder.Configuration["Spa:Origin"]
                 ?? throw new InvalidOperationException(
                     "Spa:Origin is not configured. Set it in appsettings.Development.json."))
    .TrimEnd('/');

// --- Persistence -----------------------------------------------------------------------------
var connectionString = builder.Configuration.GetConnectionString("Dashboard")
                       ?? throw new InvalidOperationException(
                           "ConnectionStrings:Dashboard is not configured. Set it in appsettings.Development.json.");

builder.Services.AddDbContext<DashboardDbContext>(options => options.UseSqlite(connectionString));

// --- Token encryption at rest ----------------------------------------------------------------
// SetApplicationName pins the key-derivation discriminator. Without it the application name is
// derived from the content-root path, so moving or renaming the folder would silently produce a
// different key and every token already in SQLite would fail to decrypt. The same keyring also
// protects the auth cookie below, which is why the session survives a restart too.
builder.Services.AddDataProtection().SetApplicationName("OAuthDashboard");
builder.Services.AddSingleton<TokenProtector>();

// --- Local login -----------------------------------------------------------------------------
builder.Services.AddScoped<LocalUserService>();
builder.Services.AddScoped<LinkedAccountService>();

builder.Services
    .AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.Cookie.Name = "oauthdash.session";

        // The three cookie flags that make this the SPA's *only* credential, and the reason the SPA
        // never needs to hold a token itself:
        //   HttpOnly — script on the page cannot read it, so an XSS bug can't exfiltrate the session
        //   Secure   — never sent over plain http
        //   None     — required because the SPA (http://localhost:5173) and this API
        //              (https://localhost:7236) differ in scheme and are therefore cross-*site*;
        //              a default Lax cookie would simply never be sent. SameSite=None is only
        //              accepted alongside Secure. See the M0 note in the README.
        options.Cookie.HttpOnly = true;
        options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        options.Cookie.SameSite = SameSiteMode.None;

        options.ExpireTimeSpan = TimeSpan.FromDays(7);
        options.SlidingExpiration = true;

        // Cookie auth defaults to 302-redirecting an unauthenticated request to an MVC login page
        // that doesn't exist here. There are two kinds of caller to serve instead: the SPA's fetch
        // calls, which want a 401 they can branch on, and real top-level browser navigations
        // (/api/auth/github/authorize, and the provider's callback), where a bare 401 page would be
        // a dead end. Accept: text/html is what separates the two.
        options.Events.OnRedirectToLogin = context =>
        {
            var wantsHtml = context.Request.Headers.Accept.Any(
                value => value?.Contains("text/html", StringComparison.OrdinalIgnoreCase) == true);

            if (wantsHtml)
            {
                context.Response.Redirect($"{spaOrigin}/login?reason=session_expired");
            }
            else
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
            }

            return Task.CompletedTask;
        };

        options.Events.OnRedirectToAccessDenied = context =>
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            return Task.CompletedTask;
        };
    });

builder.Services.AddAuthorization();

// --- Provider OAuth clients -------------------------------------------------------------------
builder.Services.AddMemoryCache();
builder.Services.AddSingleton<OAuthStateStore>();
builder.Services.AddOptions<GitHubOAuthOptions>()
    .Bind(builder.Configuration.GetSection("OAuth:GitHub"))
    .ValidateOnStart();
builder.Services.AddHttpClient<GitHubOAuthClient>();

builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy => policy
        .WithOrigins(spaOrigin)
        .AllowCredentials()
        .AllowAnyHeader()
        .AllowAnyMethod());
});

var app = builder.Build();

// Schema is applied on startup rather than by a separate `dotnet ef database update` step: this is
// a single-user local SQLite file, and having the app own its schema keeps the M2 verification
// ("restart the process, are the tokens still readable?") a one-command exercise.
using (var scope = app.Services.CreateScope())
{
    await scope.ServiceProvider.GetRequiredService<DashboardDbContext>().Database.MigrateAsync();
}

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.UseCors();

// Order matters and is not interchangeable: authentication turns the cookie into a ClaimsPrincipal,
// authorization then decides whether that principal may proceed. Reversed, every [Authorize]
// endpoint would evaluate against an anonymous user and reject valid sessions.
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
