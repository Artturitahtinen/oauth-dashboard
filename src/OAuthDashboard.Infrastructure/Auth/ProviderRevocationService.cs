using Microsoft.Extensions.Logging;
using OAuthDashboard.Core.Accounts;
using OAuthDashboard.Infrastructure.Accounts;

namespace OAuthDashboard.Infrastructure.Auth;

/// <summary>
/// What came back from asking a provider to destroy a grant.
/// </summary>
/// <remarks>
/// Four outcomes rather than a bool, because "the grant is gone" and "we could not find out" need
/// different words in front of a user. Only <see cref="Unreachable"/> leaves a live credential in
/// someone else's hands, and it is the only one worth telling them about.
/// </remarks>
public enum RevocationOutcome
{
    /// <summary>The provider confirmed it destroyed the grant.</summary>
    Revoked,

    /// <summary>
    /// The provider had nothing to destroy — the user already revoked it from their own settings
    /// page, or the credential had expired. The desired end state, arrived at without us.
    /// </summary>
    AlreadyInvalid,

    /// <summary>There was no usable credential left locally to present, so nothing was sent.</summary>
    NothingToRevoke,

    /// <summary>This provider publishes no revocation endpoint, so revocation is not on offer.</summary>
    Unsupported,

    /// <summary>
    /// The request could not be completed — the provider was down, slow, or rate limiting. The grant
    /// may well still be live, and this is the one outcome that has to be reported upward rather than
    /// smoothed over.
    /// </summary>
    Unreachable,
}

/// <param name="Outcome">What happened.</param>
/// <param name="Detail">A short machine-readable note for the SPA, or null when there is nothing to add.</param>
public record RevocationReport(RevocationOutcome Outcome, string? Detail = null)
{
    /// <summary>
    /// Whether the provider's side is known to be clean. False for <see cref="RevocationOutcome.Unreachable"/>
    /// and <see cref="RevocationOutcome.Unsupported"/> — the two cases where a token may still work.
    /// </summary>
    public bool GrantIsGone => Outcome is RevocationOutcome.Revoked
        or RevocationOutcome.AlreadyInvalid
        or RevocationOutcome.NothingToRevoke;
}

/// <summary>
/// M5's other half: unlinking that the provider is told about, rather than a row this app quietly
/// forgets.
/// </summary>
/// <remarks>
/// Deleting the local row was always the easy half. A token this app discards keeps working —
/// GitHub still lists the authorization in the user's settings, Google still counts the grant, and
/// any copy of the token that leaked (a log file, a backup, a database file taken in M2's threat
/// model) stays live for its full lifetime. "Unlink" has to mean the credential stops working, and
/// only the provider can make that true.
/// <para>
/// <b>This path deliberately does not go through <c>ProviderTokenService</c>,</b> which is otherwise
/// the rule for anything that spends a token. Two reasons, and both matter. Refreshing a token in
/// order to revoke it mints a brand-new credential for the sole purpose of destroying it — and with
/// GitHub's rotation, spends the stored refresh token to do it, so a revocation that then failed at
/// the transport level would leave the local row holding a rotated-away credential that can never be
/// revoked. And a link already latched as needing re-authorization would raise
/// <c>ReauthorizationRequiredException</c> from the token service — turning "this link is broken" into
/// "you may not unlink it", which is exactly backwards. Revocation reads what is stored, sends it,
/// and reports.
/// </para>
/// <para>
/// <b>Revocation is best-effort; the local delete is not.</b> The order is revoke-then-delete,
/// because once the row is gone there is no credential left to present and the grant could never be
/// revoked afterwards. But a provider outage must not be able to trap a user in a link they have
/// asked to remove: the row goes either way, and the response says plainly whether the upstream grant
/// went with it. The alternative — refusing to unlink until Google answers — keeps a token this app
/// was told to stop holding, which is the worse of the two failures. The honest remedy for the
/// remainder is the provider's own settings page, and it is worth naming in the response rather than
/// leaving the user to assume revocation always succeeds.
/// </para>
/// </remarks>
public class ProviderRevocationService(
    LinkedAccountService accounts,
    GitHubOAuthClient gitHub,
    GoogleOAuthClient google,
    ILogger<ProviderRevocationService> logger)
{
    /// <summary>
    /// Asks the provider to destroy the grant behind one link. Never throws for a provider-side
    /// problem — every failure it can distinguish comes back as an outcome, because the caller's next
    /// step (delete the row) is the same regardless.
    /// </summary>
    public async Task<RevocationReport> RevokeAsync(int userId, OAuthProvider provider, CancellationToken ct)
    {
        StoredProviderTokens? stored;
        try
        {
            stored = await accounts.GetTokenStateAsync(userId, provider, ct);
        }
        catch (Exception ex)
        {
            // Unprotect failing means the keyring moved or the column was tampered with. The
            // credential is unusable to us and therefore unpresentable, which is not a reason to
            // block the unlink — the row still has to go.
            logger.LogWarning(ex, "The stored {Provider} credentials could not be decrypted, so nothing can be revoked.", provider);
            return new RevocationReport(RevocationOutcome.NothingToRevoke, "credentials_unreadable");
        }

        if (stored is null)
        {
            return new RevocationReport(RevocationOutcome.NothingToRevoke, "not_linked");
        }

        try
        {
            var outcome = await RevokeWithProviderAsync(provider, stored, ct);

            logger.LogInformation(
                "Revocation of the {Provider} grant for user {UserId} returned {Outcome}.",
                provider, userId, outcome);

            return new RevocationReport(outcome);
        }
        catch (HttpRequestException ex)
        {
            // The link is still being deleted below this call. Saying so is the point: the user needs
            // to know that finishing the job means visiting the provider's settings page.
            //
            // The detail distinguishes two things the same exception type carries. A null StatusCode
            // means the request never got an answer — DNS, a socket, TLS. A status code means the
            // provider answered and refused, which is a different thing to tell a user and a
            // different thing to go looking for: a 400 here is most likely this app's own client
            // credentials, and "the provider was unreachable" would send the reader hunting for an
            // outage that never happened.
            logger.LogWarning(
                ex, "The {Provider} grant for user {UserId} could not be revoked ({Status}); the local link is being removed anyway.",
                provider, userId, ex.StatusCode);

            return new RevocationReport(
                RevocationOutcome.Unreachable,
                ex.StatusCode is null ? "provider_unreachable" : "provider_refused");
        }
        catch (OpenIdConnectDiscoveryException ex)
        {
            // Google's revocation endpoint comes out of the discovery document, so its metadata being
            // unavailable is its own way for this to fail — and it says nothing about the token.
            logger.LogWarning(
                ex, "The {Provider} revocation endpoint could not be discovered; the local link is being removed anyway.",
                provider);

            return new RevocationReport(RevocationOutcome.Unreachable, "provider_metadata_unavailable");
        }
        catch (TaskCanceledException) when (!ct.IsCancellationRequested)
        {
            // A timeout rather than the caller giving up. Same category as unreachable: we do not
            // know whether the provider acted.
            logger.LogWarning("Revoking the {Provider} grant for user {UserId} timed out.", provider, userId);
            return new RevocationReport(RevocationOutcome.Unreachable, "provider_timeout");
        }
    }

    /// <summary>
    /// The one provider-specific hop. Both providers are asked to drop the whole grant, but they
    /// disagree about how that is expressed, and neither difference is cosmetic.
    /// </summary>
    /// <remarks>
    /// GitHub revokes by <em>application</em>: the call is authenticated with the client secret and
    /// names the user's token as its subject, which is why it can drop the authorization itself and
    /// not merely a token. Google revokes by <em>token</em> (RFC 7009) and infers the grant from it,
    /// which is why the refresh token is the right one to send — it is the credential the whole grant
    /// hangs from, and revoking it takes the derived access tokens with it. Sending Google the access
    /// token instead would produce a cheerful <c>200</c> and leave the grant alive.
    /// </remarks>
    private Task<RevocationOutcome> RevokeWithProviderAsync(
        OAuthProvider provider, StoredProviderTokens stored, CancellationToken ct) => provider switch
    {
        OAuthProvider.GitHub => gitHub.RevokeGrantAsync(stored.AccessToken, ct),

        // Refresh token first, and the access token only as a fallback for a link that never got one
        // — a Google link authorized without access_type=offline, or one whose refresh token was
        // already revoked. Revoking just the access token there is worth doing and worth not
        // overstating: it retires that one string.
        OAuthProvider.Google => google.RevokeTokenAsync(stored.RefreshToken ?? stored.AccessToken, ct),

        _ => throw new NotSupportedException($"No revocation path is implemented for {provider}."),
    };
}
