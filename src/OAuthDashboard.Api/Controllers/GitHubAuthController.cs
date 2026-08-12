using Microsoft.AspNetCore.Mvc;
using OAuthDashboard.Infrastructure.Auth;

namespace OAuthDashboard.Api.Controllers;

/// <summary>
/// M1: hand-rolled authorization code flow for GitHub, no PKCE and no persistence yet
/// (see M2). The point of this milestone is to see the redirect dance and the `state`
/// parameter with nothing hidden behind a framework handler.
/// </summary>
[ApiController]
[Route("api/auth/github")]
public class GitHubAuthController(
    GitHubOAuthClient client,
    OAuthStateStore stateStore,
    ILogger<GitHubAuthController> logger) : ControllerBase
{
    [HttpGet("authorize")]
    public IActionResult Authorize()
    {
        var state = stateStore.Issue();
        return Redirect(client.BuildAuthorizationUrl(state));
    }

    [HttpGet("callback")]
    public async Task<IActionResult> Callback(
        [FromQuery] string? code,
        [FromQuery] string? state,
        [FromQuery] string? error,
        CancellationToken ct)
    {
        if (error is not null)
        {
            logger.LogWarning("GitHub authorization was not granted: {Error}", error);
            return BadRequest(new { error });
        }

        // Checked before the code is even looked at: a missing or unknown state means this
        // callback wasn't initiated by our own /authorize redirect (or is a replay of one),
        // so nothing past this point should be trusted.
        if (string.IsNullOrEmpty(state) || !stateStore.TryConsume(state))
        {
            logger.LogWarning("GitHub callback rejected: missing or unrecognized state parameter.");
            return BadRequest(new { error = "invalid_state" });
        }

        if (string.IsNullOrEmpty(code))
        {
            return BadRequest(new { error = "missing_code" });
        }

        var accessToken = await client.ExchangeCodeForAccessTokenAsync(code, ct);
        var user = await client.GetAuthenticatedUserAsync(accessToken, ct);

        return Ok(user);
    }
}
