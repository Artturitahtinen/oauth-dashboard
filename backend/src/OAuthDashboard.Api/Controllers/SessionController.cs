using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Mvc;
using OAuthDashboard.Core.Users;
using OAuthDashboard.Infrastructure.Users;

namespace OAuthDashboard.Api.Controllers;

/// <summary>
/// The local login the SPA authenticates against — deliberately separate from provider OAuth.
/// </summary>
/// <remarks>
/// This is the identity that provider tokens hang off. Before M2 there was no "who", so a linked
/// GitHub account really belonged to "whoever holds the cookie"; now every
/// <c>LinkedAccount</c> row is scoped to a real user id.
/// <para>
/// Nothing here is OAuth. It's worth keeping the two straight: this endpoint proves who the local
/// user is, while <see cref="GitHubAuthController"/> proves what that user has authorized this app
/// to do on their behalf at GitHub. Conflating "log in with GitHub" and "link GitHub" is the usual
/// source of confusion, and the BFF split makes the distinction concrete.
/// </para>
/// </remarks>
[ApiController]
[Route("api/auth")]
public class SessionController(
    LocalUserService users,
    ILogger<SessionController> logger) : ControllerBase
{
    /// <summary>
    /// One call that drives the whole login screen: whether this browser is already authenticated,
    /// and whether the single local account still needs to be claimed.
    /// </summary>
    [HttpGet("session")]
    public async Task<ActionResult<SessionResponse>> GetSession(CancellationToken ct)
    {
        var authenticated = User.Identity?.IsAuthenticated == true;

        return new SessionResponse(
            Authenticated: authenticated,
            Username: authenticated ? User.FindFirstValue(ClaimTypes.Name) : null,
            // Only meaningful to an anonymous caller, and cheap to answer: an authenticated request
            // already proves an account exists.
            NeedsSetup: !authenticated && await users.NeedsSetupAsync(ct));
    }

    /// <summary>
    /// First-run claim of the single local account. Refused once an account exists, so this is not
    /// an open sign-up endpoint.
    /// </summary>
    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] CredentialsRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.Username) || request.Username.Length > 64)
        {
            return BadRequest(new { error = "invalid_username" });
        }

        // A length floor is the one password rule worth enforcing here. Composition rules
        // ("one digit, one symbol") mostly push people toward predictable substitutions.
        if (string.IsNullOrEmpty(request.Password) || request.Password.Length < 12)
        {
            return BadRequest(new { error = "password_too_short", minimumLength = 12 });
        }

        var user = await users.TryRegisterFirstUserAsync(request.Username.Trim(), request.Password, ct);
        if (user is null)
        {
            return Conflict(new { error = "already_registered" });
        }

        logger.LogInformation("Local account claimed for {Username} (id {UserId}).", user.Username, user.Id);

        await SignInAsync(user);
        return Ok(new SessionResponse(true, user.Username, NeedsSetup: false));
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] CredentialsRequest request, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(request.Username) || string.IsNullOrEmpty(request.Password))
        {
            return BadRequest(new { error = "missing_credentials" });
        }

        var user = await users.VerifyCredentialsAsync(request.Username.Trim(), request.Password, ct);
        if (user is null)
        {
            // One undifferentiated failure for both "no such user" and "wrong password" — telling
            // them apart would turn this into a username oracle. The log is equally vague; a failed
            // attempt is not a reason to write an attacker-supplied guess into the log file.
            logger.LogWarning("Failed local login attempt.");
            return Unauthorized(new { error = "invalid_credentials" });
        }

        await SignInAsync(user);
        return Ok(new SessionResponse(true, user.Username, NeedsSetup: false));
    }

    [HttpPost("logout")]
    public async Task<IActionResult> Logout()
    {
        // Clears the cookie's server-side validity by expiring it. Note this deliberately does NOT
        // touch stored provider tokens — logging out of the dashboard is not the same act as
        // revoking GitHub's grant. That's what unlink (M5) is for.
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return NoContent();
    }

    private Task SignInAsync(User user)
    {
        // The user id is the claim everything else keys off — GitHubAuthController reads it to
        // decide whose LinkedAccount row to write. NameIdentifier holds the immutable id rather than
        // the username, so a future rename can't silently repoint a session at nothing.
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id.ToString()),
            new(ClaimTypes.Name, user.Username),
        };

        var identity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);

        return HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity),
            new AuthenticationProperties { IsPersistent = true });
    }
}

public record CredentialsRequest(string Username, string Password);

public record SessionResponse(bool Authenticated, string? Username, bool NeedsSetup);
