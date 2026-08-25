using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OAuthDashboard.Core.Accounts;
using OAuthDashboard.Infrastructure.Accounts;
using OAuthDashboard.Infrastructure.Auth;

namespace OAuthDashboard.Api.Controllers;

/// <summary>
/// The hand-rolled flow again, this time for an OpenID Connect provider (M4).
/// </summary>
/// <remarks>
/// Kept as its own controller rather than folded into a shared base with
/// <see cref="GitHubAuthController"/>. The state handling either side of the exchange is genuinely
/// the same, but the middle is not — this flow carries a nonce out, gets a signed identity back, and
/// has to validate it before anything is written — and a base class would hide exactly the stage
/// this milestone exists to show. Two visible flows beat one abstracted one when the difference
/// between them is the lesson.
/// <para>
/// Note what is <em>not</em> different: this is still "link Google to the local account you are
/// already logged into", not "log in with Google". Google now hands this app a verified identity, so
/// building a login on it would be a small step — and a separate decision, with its own account
/// linking and account takeover questions. The BFF split from M2 stands.
/// </para>
/// </remarks>
[ApiController]
[Route("api/auth/google")]
[Authorize]
public class GoogleAuthController(
    GoogleOAuthClient client,
    OAuthStateStore stateStore,
    LinkedAccountService linkedAccounts,
    IConfiguration configuration,
    ILogger<GoogleAuthController> logger) : ControllerBase
{
    private const OAuthProvider Provider = OAuthProvider.Google;

    private string SpaOrigin => configuration["Spa:Origin"]!.TrimEnd('/');

    [HttpGet("authorize")]
    public async Task<IActionResult> Authorize(CancellationToken ct)
    {
        // state, verifier and nonce are minted together and stored server-side against the current
        // user. Only the state, the derived challenge and the nonce travel to Google.
        var pending = stateStore.Issue(Provider, User.GetUserId());
        var challenge = Pkce.CodeChallengeFor(pending.CodeVerifier);

        var url = await client.BuildAuthorizationUrlAsync(pending.State, challenge, pending.Nonce, ct);

        return Redirect(url);
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
            logger.LogWarning("Google authorization was not granted: {Error}", error);
            return RedirectToSpa($"error={Uri.EscapeDataString(error)}");
        }

        if (string.IsNullOrEmpty(state) || !stateStore.TryConsume(state, out var pending))
        {
            logger.LogWarning("Google callback rejected: missing or unrecognized state parameter.");
            return RedirectToSpa("error=invalid_state");
        }

        if (pending!.UserId != User.GetUserId() || pending.Provider != Provider)
        {
            logger.LogWarning("Google callback rejected: state did not belong to the current session.");
            return RedirectToSpa("error=state_session_mismatch");
        }

        if (string.IsNullOrEmpty(code))
        {
            return RedirectToSpa("error=missing_code");
        }

        try
        {
            // The nonce goes back in here, and the exchange refuses to return anything unless the
            // id_token it got carries the same one. Consuming the state above already invalidated
            // it, so this pairing exists exactly once.
            var result = await client.ExchangeCodeForTokenAsync(code, pending.CodeVerifier, pending.Nonce, ct);

            // The account identity comes from the signed assertion, not from a userinfo call. `sub`
            // is the stable key; the email is display only and is never what the link is matched on.
            var account = new ProviderAccountInfo(
                result.Identity.Subject,
                result.Identity.Email ?? result.Identity.Name ?? result.Identity.Subject);

            await linkedAccounts.UpsertAsync(pending.UserId, Provider, result.Tokens, account, ct);

            logger.LogInformation(
                "Linked Google account {Subject} to user {UserId} (granted scopes: {Scopes}, refresh token: {HasRefreshToken}).",
                result.Identity.Subject, pending.UserId, result.Tokens.Scopes, result.Tokens.RefreshToken is not null);

            return RedirectToSpa("linked=google");
        }
        catch (IdTokenValidationException ex)
        {
            // The distinct failure M4 adds: the exchange itself worked and Google returned tokens,
            // but the identity attached to them did not check out. Nothing is persisted — an access
            // token whose accompanying assertion failed validation is not a link, and storing it
            // "because the token part looked fine" is how a mis-issued identity becomes a row in the
            // database.
            logger.LogError(ex, "Google returned an id_token that failed validation; the link was not established.");
            return RedirectToSpa("error=id_token_invalid");
        }
        catch (OpenIdConnectDiscoveryException ex)
        {
            logger.LogError(ex, "Google's OIDC metadata could not be obtained or did not check out.");
            return RedirectToSpa("error=provider_metadata_unavailable");
        }
        catch (HttpRequestException ex)
        {
            logger.LogError(ex, "Google token exchange failed at the transport level.");
            return RedirectToSpa("error=provider_unreachable");
        }
        catch (InvalidOperationException ex)
        {
            logger.LogError(ex, "Google token exchange was rejected.");
            return RedirectToSpa("error=exchange_failed");
        }
    }

    /// <summary>
    /// Built from configuration, never from a query parameter — see the note on
    /// <see cref="GitHubAuthController"/>.
    /// </summary>
    private RedirectResult RedirectToSpa(string query) => Redirect($"{SpaOrigin}/connections?{query}");
}
