using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OAuthDashboard.Core.Accounts;
using OAuthDashboard.Infrastructure.Accounts;
using OAuthDashboard.Infrastructure.Auth;

namespace OAuthDashboard.Api.Controllers;

/// <summary>
/// Hand-rolled authorization code flow for GitHub, now with PKCE and encrypted persistence (M2).
/// </summary>
/// <remarks>
/// What changed from M1, and why each piece matters:
/// <list type="bullet">
/// <item><c>[Authorize]</c> — linking is an action taken *by a known local user*. Without it there
/// would be no answer to "whose GitHub account is this", and the tokens would have nowhere to go.</item>
/// <item>PKCE — the authorize redirect carries only <c>SHA256(verifier)</c>; the verifier itself
/// stays in <see cref="OAuthStateStore"/> until the server-to-server token POST.</item>
/// <item>Persistence — the token is encrypted and written to SQLite instead of being used once and
/// dropped, so a restart no longer means re-authorizing.</item>
/// <item>The callback redirects into the SPA rather than returning JSON. A provider callback lands
/// in a top-level browser navigation, so its response is a *page* the user sees — and it must not be
/// a page containing token material.</item>
/// </list>
/// </remarks>
[ApiController]
[Route("api/auth/github")]
[Authorize]
public class GitHubAuthController(
    GitHubOAuthClient client,
    OAuthStateStore stateStore,
    LinkedAccountService linkedAccounts,
    IConfiguration configuration,
    ILogger<GitHubAuthController> logger) : ControllerBase
{
    private const OAuthProvider Provider = OAuthProvider.GitHub;

    private string SpaOrigin => configuration["Spa:Origin"]!.TrimEnd('/');

    /// <summary>
    /// Starts an authorization. With no <paramref name="grant"/> this is a plain link, requesting the
    /// base scope and nothing else; with one, it is an incremental authorization adding that single
    /// widget's permission (M5).
    /// </summary>
    /// <param name="grant">
    /// A key from <see cref="ProviderScopes.Optional"/> — <em>not</em> a scope string. The distinction
    /// is the security property: this is an authenticated endpoint that redirects the user's browser
    /// to a consent screen, so a <c>?scope=</c> parameter honoured verbatim would let anyone who can
    /// get this user to follow a link choose which permissions the consent screen asks for. A key can
    /// only ever resolve to a scope this code already decided it wanted.
    /// </param>
    [HttpGet("authorize")]
    public IActionResult Authorize([FromQuery] string? grant)
    {
        OptionalScope? additionalScope = null;

        if (!string.IsNullOrEmpty(grant) && !ProviderScopes.TryResolve(Provider, grant, out additionalScope))
        {
            // Refused rather than ignored. Quietly falling back to a base-scope authorization would
            // send the user through a consent screen, come back looking successful, and leave the
            // widget that asked for the scope reporting that it still needs one — a loop with nothing
            // in it that says why. A caller asking for a grant that doesn't exist has a bug, and a
            // 400 is where that gets found.
            logger.LogWarning("Refused a GitHub authorization for an unrecognized grant key.");
            return BadRequest(new { error = "unknown_grant" });
        }

        // state + code_verifier are minted together and stored server-side against the current
        // user. Only the state and the derived challenge travel to GitHub.
        var pending = stateStore.Issue(Provider, User.GetUserId());
        var challenge = Pkce.CodeChallengeFor(pending.CodeVerifier);

        if (additionalScope is not null)
        {
            logger.LogInformation(
                "Starting an incremental GitHub authorization for user {UserId}, adding {Scope}.",
                pending.UserId, additionalScope.Scope);
        }

        return Redirect(client.BuildAuthorizationUrl(pending.State, challenge, additionalScope));
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
            return RedirectToSpa($"error={Uri.EscapeDataString(error)}");
        }

        // Checked before the code is even looked at: a missing or unknown state means this callback
        // wasn't initiated by our own /authorize redirect (or is a replay of one), so nothing past
        // this point should be trusted.
        if (string.IsNullOrEmpty(state) || !stateStore.TryConsume(state, out var pending))
        {
            logger.LogWarning("GitHub callback rejected: missing or unrecognized state parameter.");
            return RedirectToSpa("error=invalid_state");
        }

        // The state was valid, but valid for *someone*. This confirms the session finishing the flow
        // is the one that started it — otherwise a link begun in one session could be completed in
        // another, attaching an attacker's GitHub account to this user (or vice versa).
        if (pending!.UserId != User.GetUserId() || pending.Provider != Provider)
        {
            logger.LogWarning("GitHub callback rejected: state did not belong to the current session.");
            return RedirectToSpa("error=state_session_mismatch");
        }

        if (string.IsNullOrEmpty(code))
        {
            return RedirectToSpa("error=missing_code");
        }

        try
        {
            var tokens = await client.ExchangeCodeForTokenAsync(code, pending.CodeVerifier, ct);
            var account = await client.GetAuthenticatedUserAsync(tokens.AccessToken, ct);

            await linkedAccounts.UpsertAsync(pending.UserId, Provider, tokens, account, ct);

            logger.LogInformation(
                "Linked GitHub account {AccountName} to user {UserId} (granted scopes: {Scopes}).",
                account.DisplayName, pending.UserId, tokens.Scopes);

            return RedirectToSpa("linked=github");
        }
        catch (HttpRequestException ex)
        {
            // The provider being unreachable is not the user's mistake, and the exception text can
            // carry request detail, so it goes to the log and the browser gets a bare error code.
            logger.LogError(ex, "GitHub token exchange failed at the transport level.");
            return RedirectToSpa("error=provider_unreachable");
        }
        catch (InvalidOperationException ex)
        {
            logger.LogError(ex, "GitHub token exchange was rejected.");
            return RedirectToSpa("error=exchange_failed");
        }
    }

    /// <summary>
    /// Sends the browser back into the SPA's connections screen. The target is built from
    /// configuration, never from a query parameter — an <c>?next=</c>-style caller-supplied redirect
    /// here would be an open redirect hanging off an authenticated endpoint.
    /// </summary>
    private RedirectResult RedirectToSpa(string query) => Redirect($"{SpaOrigin}/connections?{query}");
}
