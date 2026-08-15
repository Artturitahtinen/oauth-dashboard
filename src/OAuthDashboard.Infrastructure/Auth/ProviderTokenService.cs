using System.Net;
using Microsoft.Extensions.Logging;
using OAuthDashboard.Core.Accounts;
using OAuthDashboard.Infrastructure.Accounts;

namespace OAuthDashboard.Infrastructure.Auth;

/// <summary>
/// M3: the single place that hands out a provider access token that is actually usable, refreshing
/// it first if it isn't.
/// </summary>
/// <remarks>
/// The milestone's whole idea is that the rest of the application stops thinking about token
/// lifetime. A widget asks to call GitHub; whether that involves a refresh POST, a retry, or
/// nothing at all is decided here.
/// <para>
/// <b>Two triggers, because one is not enough.</b> The proactive trigger — "expires within
/// <see cref="ExpiryLeeway"/>" — catches the common case cheaply, before a request is wasted. But it
/// only works for a token whose expiry the provider actually advertised, and it cannot know about a
/// token revoked from the user's GitHub settings page five seconds ago. So there is also a reactive
/// trigger: a <c>401</c> from the provider means the token is dead regardless of what the stored
/// expiry claimed. A refresh implementation with only the proactive half looks correct right up
/// until a clock skews or a user revokes something.
/// </para>
/// <para>
/// <b>Exactly one retry.</b> After a reactive refresh the call is retried once. If that fails too,
/// the grant is latched as needing re-authorization instead of being retried again — a token minted
/// seconds ago and immediately refused is not going to start working on the third attempt, and a
/// refresh loop against a provider's rate limiter is its own outage.
/// </para>
/// </remarks>
public class ProviderTokenService(
    LinkedAccountService accounts,
    GitHubOAuthClient gitHub,
    RefreshLockRegistry locks,
    ILogger<ProviderTokenService> logger)
{
    /// <summary>
    /// How far before the stated expiry a token is treated as already expired.
    /// </summary>
    /// <remarks>
    /// Not paranoia about clock drift so much as arithmetic: a token with eight seconds left passes
    /// a naive <c>ExpiresAtUtc > UtcNow</c> check and then expires in flight, turning a refresh that
    /// could have happened quietly into a user-visible failure. The leeway also absorbs the fact
    /// that <c>expires_in</c> was measured at the provider, and the network time between there and
    /// here is real.
    /// </remarks>
    public static readonly TimeSpan ExpiryLeeway = TimeSpan.FromMinutes(2);

    /// <summary>
    /// Returns a token believed good, refreshing first if the stored one is expired or nearly so.
    /// </summary>
    /// <exception cref="ProviderNotLinkedException">The user has no link to this provider.</exception>
    /// <exception cref="ReauthorizationRequiredException">The link is broken and cannot self-heal.</exception>
    public async Task<ProviderAccessToken> GetAccessTokenAsync(
        int userId, OAuthProvider provider, CancellationToken ct)
    {
        var stored = await accounts.GetTokenStateAsync(userId, provider, ct)
                     ?? throw new ProviderNotLinkedException(provider);

        // The latch is checked before anything else. Once a grant is known dead, re-attempting it on
        // every request only burns provider rate limit to rediscover the same answer.
        if (stored.ReauthorizationRequiredAtUtc is not null)
        {
            throw new ReauthorizationRequiredException(provider, "refresh_token_rejected");
        }

        if (!IsExpiringSoon(stored.ExpiresAtUtc))
        {
            return new ProviderAccessToken(stored.AccessToken, Refreshed: false);
        }

        logger.LogInformation(
            "Stored {Provider} token for user {UserId} expires at {ExpiresAt}; refreshing before use.",
            provider, userId, stored.ExpiresAtUtc);

        return new ProviderAccessToken(
            await RefreshAsync(userId, provider, stored.AccessToken, ct), Refreshed: true);
    }

    /// <summary>
    /// Runs a provider call with a usable token, and — if the provider answers <c>401</c> anyway —
    /// refreshes once and runs it again.
    /// </summary>
    /// <remarks>
    /// The callback shape is what keeps the reactive half honest: the retry has to re-run the actual
    /// request with the new token, and handing this service a delegate is what makes that possible
    /// without every call site growing its own copy of the retry logic.
    /// </remarks>
    public async Task<ProviderCallResult<T>> CallAsync<T>(
        int userId,
        OAuthProvider provider,
        Func<string, CancellationToken, Task<T>> call,
        CancellationToken ct)
    {
        var token = await GetAccessTokenAsync(userId, provider, ct);

        try
        {
            return new ProviderCallResult<T>(await call(token.Value, ct), token.Refreshed);
        }
        catch (HttpRequestException ex) when (ex.StatusCode == HttpStatusCode.Unauthorized)
        {
            if (token.Refreshed)
            {
                // This token was minted moments ago by the proactive path and the provider refused it
                // anyway, so the grant behind it is dead — refreshing again would spend another
                // rotation to obtain another token from the same dead grant.
                await accounts.MarkReauthorizationRequiredAsync(userId, provider, ct);

                logger.LogWarning(
                    "{Provider} rejected a freshly refreshed token for user {UserId}; the link now needs re-authorization.",
                    provider, userId);

                throw new ReauthorizationRequiredException(provider, "token_rejected_after_refresh", ex);
            }

            // The stored expiry said this token was fine and the provider disagreed. That happens
            // when the user revoked the grant, when the provider never advertised an expiry it
            // nonetheless enforces, or when a clock is wrong. All three are recoverable by asking
            // for a new token, so this is a refresh trigger rather than an error.
            logger.LogInformation(
                "{Provider} rejected the stored token for user {UserId} despite its recorded expiry; refreshing and retrying once.",
                provider, userId);

            var refreshed = await RefreshAsync(userId, provider, token.Value, ct);

            try
            {
                return new ProviderCallResult<T>(await call(refreshed, ct), Refreshed: true);
            }
            catch (HttpRequestException retryEx) when (retryEx.StatusCode == HttpStatusCode.Unauthorized)
            {
                // A token minted moments ago, refused immediately. Retrying a third time would just
                // be a slower way to reach the same conclusion.
                await accounts.MarkReauthorizationRequiredAsync(userId, provider, ct);

                logger.LogWarning(
                    "{Provider} rejected a freshly refreshed token for user {UserId}; the link now needs re-authorization.",
                    provider, userId);

                throw new ReauthorizationRequiredException(provider, "token_rejected_after_refresh", retryEx);
            }
        }
    }

    private static bool IsExpiringSoon(DateTimeOffset? expiresAtUtc) =>
        // Null is "no expiry advertised", which is a GitHub OAuth App's normal state — not a reason
        // to refresh. Treating null as expired here would send every request into a refresh path
        // that has no refresh token to use, and turn a working link into a demand to re-consent.
        expiresAtUtc is { } expiry && expiry - DateTimeOffset.UtcNow <= ExpiryLeeway;

    /// <summary>
    /// Performs the refresh under the per-link gate and persists the result. Returns the new access
    /// token, or the one another request just obtained.
    /// </summary>
    /// <param name="staleAccessToken">
    /// The token whose inadequacy triggered this. It doubles as the check for whether a concurrent
    /// request already refreshed: if what's stored is no longer this value, someone else won the
    /// race and their token is the one to use.
    /// </param>
    private async Task<string> RefreshAsync(
        int userId, OAuthProvider provider, string staleAccessToken, CancellationToken ct)
    {
        var gate = locks.For(userId, provider);
        await gate.WaitAsync(ct);

        try
        {
            // Re-read inside the lock. Whoever held it before may have already done this work, and
            // spending a rotated-away refresh token would look like a replay to the provider.
            var current = await accounts.GetTokenStateAsync(userId, provider, ct)
                          ?? throw new ProviderNotLinkedException(provider);

            if (!string.Equals(current.AccessToken, staleAccessToken, StringComparison.Ordinal))
            {
                logger.LogDebug(
                    "A concurrent request already refreshed the {Provider} token for user {UserId}; reusing it.",
                    provider, userId);

                return current.AccessToken;
            }

            if (current.ReauthorizationRequiredAtUtc is not null)
            {
                throw new ReauthorizationRequiredException(provider, "refresh_token_rejected");
            }

            if (current.RefreshToken is null)
            {
                // Nothing to refresh with. For a GitHub OAuth App this is the expected end state:
                // it issues a non-expiring access token and no refresh token, so a token that has
                // stopped working means the user revoked it and only a new consent will help.
                await accounts.MarkReauthorizationRequiredAsync(userId, provider, ct);

                logger.LogWarning(
                    "The {Provider} link for user {UserId} has no refresh token, so the dead access token cannot be replaced.",
                    provider, userId);

                throw new ReauthorizationRequiredException(provider, "no_refresh_token");
            }

            try
            {
                var refreshed = await RefreshWithProviderAsync(provider, current.RefreshToken, ct);

                // Persisted before the token is handed out. GitHub has already retired the old
                // refresh token by this point, so a crash between the POST and the write would leave
                // the database holding a credential the provider no longer honours.
                await accounts.UpdateAfterRefreshAsync(userId, provider, refreshed, ct);

                logger.LogInformation(
                    "Refreshed the {Provider} access token for user {UserId} without user interaction (new expiry: {ExpiresAt}).",
                    provider, userId, refreshed.ExpiresAtUtc);

                return refreshed.AccessToken;
            }
            catch (RefreshTokenRejectedException ex)
            {
                // The dead-refresh-token path: the grant is over. Latched so the SPA can ask for a
                // re-link rather than the dashboard rediscovering this on every request.
                await accounts.MarkReauthorizationRequiredAsync(userId, provider, ct);

                logger.LogWarning(
                    "The {Provider} refresh token for user {UserId} was rejected ({Error}); the link now needs re-authorization.",
                    provider, userId, ex.Error);

                throw new ReauthorizationRequiredException(provider, "refresh_token_rejected", ex);
            }
        }
        finally
        {
            gate.Release();
        }
    }

    /// <summary>
    /// The one provider-specific hop. M4 adds Google's client here; the surrounding decision —
    /// when to refresh, what to do when it fails, how to avoid racing — is provider-agnostic and
    /// stays where it is.
    /// </summary>
    private Task<OAuthTokenResult> RefreshWithProviderAsync(
        OAuthProvider provider, string refreshToken, CancellationToken ct) => provider switch
    {
        OAuthProvider.GitHub => gitHub.RefreshAccessTokenAsync(refreshToken, ct),
        _ => throw new NotSupportedException($"No OAuth client is registered for {provider} yet."),
    };
}

/// <param name="Value">The token to send to the provider. Server side only.</param>
/// <param name="Refreshed">Whether obtaining it required a refresh grant just now.</param>
public record ProviderAccessToken(string Value, bool Refreshed);

/// <param name="Value">Whatever the provider call returned.</param>
/// <param name="Refreshed">
/// Whether a refresh happened on the way. Surfaced so the milestone is demonstrable from outside:
/// without it, a transparent refresh is by definition invisible, and "it still works" is equally
/// consistent with "the refresh ran" and "the token never expired in the first place".
/// </param>
public record ProviderCallResult<T>(T Value, bool Refreshed);
