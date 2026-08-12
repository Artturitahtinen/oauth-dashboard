using OAuthDashboard.Infrastructure.Auth;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

builder.Services.AddMemoryCache();
builder.Services.AddSingleton<OAuthStateStore>();
builder.Services.AddOptions<GitHubOAuthOptions>()
    .Bind(builder.Configuration.GetSection("OAuth:GitHub"))
    .ValidateOnStart();
builder.Services.AddHttpClient<GitHubOAuthClient>();

// The SPA runs on its own origin, so every call it makes here is cross-origin. Because those
// calls carry the BFF session cookie, the policy has to name the origin explicitly —
// AllowCredentials is illegal in combination with a wildcard origin, by design: it would let
// any site on the internet make authenticated calls with the user's cookie.
var spaOrigin = builder.Configuration["Spa:Origin"]
                ?? throw new InvalidOperationException(
                    "Spa:Origin is not configured. Set it in appsettings.Development.json.");

builder.Services.AddCors(options =>
{
    options.AddDefaultPolicy(policy => policy
        .WithOrigins(spaOrigin)
        .AllowCredentials()
        .AllowAnyHeader()
        .AllowAnyMethod());
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.UseCors();

app.UseAuthorization();

app.MapControllers();

app.Run();
