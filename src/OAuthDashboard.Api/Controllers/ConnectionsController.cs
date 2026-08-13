using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OAuthDashboard.Core.Accounts;
using OAuthDashboard.Infrastructure.Accounts;
using OAuthDashboard.Infrastructure.Auth;

namespace OAuthDashboard.Api.Controllers;

/// <summary>
/// What the SPA is allowed to know about the current user's provider links.
/// </summary>
/// <remarks>
/// The response is intentionally metadata only — provider, account name, granted scopes, timestamps.
/// No token, and not even the ciphertext: handing the SPA an encrypted token would still put it in
/// the browser's memory and network log for no benefit. This is the BFF boundary at its narrowest
/// point, and it's the endpoint to check first if that boundary is ever suspected of leaking.
/// </remarks>
[ApiController]
[Route("api/connections")]
[Authorize]
public class ConnectionsController(
    LinkedAccountService linkedAccounts,
    GitHubOAuthClient gitHub,
    ILogger<ConnectionsController> logger) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<List<LinkedAccountSummary>>> Get(CancellationToken ct) =>
        await linkedAccounts.GetSummariesAsync(User.GetUserId(), ct);

    /// <summary>
    /// Decrypts the stored token and spends it on a real provider call, reporting only whether it
    /// still works.
    /// </summary>
    /// <remarks>
    /// This exists because M2's central claim — tokens survive a restart because the encryption round
    /// trip works — is otherwise unverifiable from outside. Every other field on
    /// <see cref="LinkedAccountSummary"/> comes from an unencrypted column, so a completely broken
    /// protector would still render a healthy-looking "Linked" card. This is the one path that proves
    /// the ciphertext in SQLite can still be turned back into a working credential.
    /// <para>
    /// It's also the seed of M3: "use the stored token, notice it was rejected" is exactly the
    /// signal the refresh flow will hang off. For now a 401 from the provider is only reported, not
    /// acted on.
    /// </para>
    /// </remarks>
    [HttpGet("{provider}/check")]
    public async Task<ActionResult<ConnectionCheckResponse>> Check(OAuthProvider provider, CancellationToken ct)
    {
        if (provider != OAuthProvider.GitHub)
        {
            // Google's client arrives in M4. Saying so beats a confusing generic failure.
            return StatusCode(StatusCodes.Status501NotImplemented, new { error = "provider_not_implemented" });
        }

        var userId = User.GetUserId();
        var accessToken = await linkedAccounts.GetAccessTokenAsync(userId, provider, ct);
        if (accessToken is null)
        {
            return NotFound(new { error = "not_linked" });
        }

        try
        {
            var account = await gitHub.GetAuthenticatedUserAsync(accessToken, ct);

            logger.LogInformation(
                "Verified stored {Provider} token for user {UserId} against the provider.", provider, userId);

            // Returns the provider's answer, never the token that produced it.
            return new ConnectionCheckResponse(provider.ToString(), true, account.DisplayName, null);
        }
        catch (HttpRequestException ex)
        {
            logger.LogWarning(ex, "Stored {Provider} token failed verification.", provider);

            var reason = ex.StatusCode == System.Net.HttpStatusCode.Unauthorized
                ? "token_rejected"
                : "provider_unreachable";

            return new ConnectionCheckResponse(provider.ToString(), false, null, reason);
        }
    }

    /// <summary>
    /// Drops the local link. Route-bound to the <see cref="OAuthProvider"/> enum, so an unknown
    /// provider name fails model binding with a 400 and never reaches the database as a string.
    /// </summary>
    /// <remarks>
    /// This is a local delete, not a revocation: GitHub still considers the grant live and the token
    /// this app just discarded would keep working if a copy existed elsewhere. M5 replaces this with
    /// a real unlink that calls the provider's revoke endpoint first, then deletes.
    /// </remarks>
    [HttpDelete("{provider}")]
    public async Task<IActionResult> Delete(OAuthProvider provider, CancellationToken ct)
    {
        var userId = User.GetUserId();
        var deleted = await linkedAccounts.DeleteAsync(userId, provider, ct);

        if (!deleted)
        {
            return NotFound(new { error = "not_linked" });
        }

        logger.LogInformation(
            "Deleted local {Provider} link for user {UserId} (token discarded locally; not yet revoked upstream).",
            provider, userId);

        return NoContent();
    }
}

/// <param name="Ok">Whether the stored token still authenticates against the provider.</param>
/// <param name="AccountName">The provider's own answer for who the token belongs to, on success.</param>
/// <param name="Reason">A machine-readable failure code, on failure.</param>
public record ConnectionCheckResponse(string Provider, bool Ok, string? AccountName, string? Reason);
