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
    ProviderTokenService providerTokens,
    GitHubOAuthClient gitHub,
    GoogleOAuthClient google,
    ILogger<ConnectionsController> logger) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<List<LinkedAccountSummary>>> Get(CancellationToken ct) =>
        await linkedAccounts.GetSummariesAsync(User.GetUserId(), ct);

    /// <summary>
    /// Spends the stored token on a real provider call — refreshing it first if it has expired —
    /// and reports whether it worked and whether a refresh was needed.
    /// </summary>
    /// <remarks>
    /// This began as M2's falsifiability check: every other field on
    /// <see cref="LinkedAccountSummary"/> comes from an unencrypted column, so a completely broken
    /// protector would still render a healthy-looking "Linked" card, and this is the one path that
    /// proves the ciphertext in SQLite can still be turned back into a working credential.
    /// <para>
    /// M3 gives it a second job for the same reason. A refresh that works is invisible by
    /// construction — "the call succeeded" is equally consistent with "the token was refreshed" and
    /// "it never needed to be". <see cref="ConnectionCheckResponse.Refreshed"/> is what separates
    /// the two, so the milestone's claim can be checked rather than assumed.
    /// </para>
    /// </remarks>
    [HttpGet("{provider}/check")]
    public async Task<ActionResult<ConnectionCheckResponse>> Check(OAuthProvider provider, CancellationToken ct)
    {
        // Each provider's "who am I" call. Not a switch over behaviour — the refresh decision, the
        // retry and the failure taxonomy are identical for both and live in ProviderTokenService —
        // just over which endpoint the stored token gets spent on.
        Func<string, CancellationToken, Task<ProviderAccountInfo>>? identityCall = provider switch
        {
            OAuthProvider.GitHub => gitHub.GetAuthenticatedUserAsync,
            OAuthProvider.Google => google.GetAuthenticatedUserAsync,
            _ => null,
        };

        if (identityCall is null)
        {
            return StatusCode(StatusCodes.Status501NotImplemented, new { error = "provider_not_implemented" });
        }

        var userId = User.GetUserId();

        try
        {
            // The token never appears in this method. It is handed to the callback, spent, and
            // forgotten; what comes back is the provider's answer.
            var result = await providerTokens.CallAsync(userId, provider, identityCall, ct);

            logger.LogInformation(
                "Verified stored {Provider} token for user {UserId} against the provider (refreshed: {Refreshed}).",
                provider, userId, result.Refreshed);

            return new ConnectionCheckResponse(
                provider.ToString(), Ok: true, result.Value.DisplayName, result.Refreshed, Reason: null);
        }
        catch (ProviderNotLinkedException)
        {
            return NotFound(new { error = "not_linked" });
        }
        catch (ReauthorizationRequiredException ex)
        {
            // 409, not 401: the local session is fine, and answering 401 would send the SPA to the
            // wrong login screen. This says "the GitHub link is broken", not "you are logged out".
            logger.LogWarning(
                "The {Provider} link for user {UserId} needs re-authorization ({Reason}).",
                provider, userId, ex.Reason);

            return Conflict(new ConnectionCheckResponse(
                provider.ToString(), Ok: false, AccountName: null, Refreshed: false, Reason: ex.Reason));
        }
        catch (HttpRequestException ex)
        {
            // Anything left here is transport-level — the provider being unreachable is not a reason
            // to tell the user their link is broken.
            logger.LogWarning(ex, "Stored {Provider} token could not be verified.", provider);

            return new ConnectionCheckResponse(
                provider.ToString(), Ok: false, AccountName: null, Refreshed: false, Reason: "provider_unreachable");
        }
        catch (OpenIdConnectDiscoveryException ex)
        {
            // Google's endpoints are discovered rather than configured, so its metadata being
            // unavailable is a new way for this call to fail — and it says nothing about the stored
            // token. Same category as unreachable, reported under its own code so "we couldn't ask"
            // stays distinguishable from "we asked and were refused".
            logger.LogWarning(ex, "The {Provider} OIDC metadata could not be obtained.", provider);

            return new ConnectionCheckResponse(
                provider.ToString(), Ok: false, AccountName: null, Refreshed: false,
                Reason: "provider_metadata_unavailable");
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
/// <param name="Refreshed">
/// Whether serving this call required the refresh grant. This is M3's observable: a successful
/// transparent refresh leaves no other trace.
/// </param>
/// <param name="Reason">A machine-readable failure code, on failure.</param>
public record ConnectionCheckResponse(
    string Provider, bool Ok, string? AccountName, bool Refreshed, string? Reason);
