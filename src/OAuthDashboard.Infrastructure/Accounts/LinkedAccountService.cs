using Microsoft.EntityFrameworkCore;
using OAuthDashboard.Core.Accounts;
using OAuthDashboard.Infrastructure.Auth;
using OAuthDashboard.Infrastructure.Persistence;
using OAuthDashboard.Infrastructure.Security;

namespace OAuthDashboard.Infrastructure.Accounts;

/// <summary>
/// The only route provider tokens take in and out of the database.
/// </summary>
/// <remarks>
/// Funnelling every read and write through here is what keeps encryption from being optional:
/// there's no call site that can persist a <see cref="LinkedAccount"/> without going past
/// <see cref="TokenProtector"/>, so "forgot to encrypt this one" isn't an available mistake.
/// It's also why the plaintext token never appears on a return type that a controller could
/// accidentally serialize — <see cref="GetAccessTokenAsync"/> hands back a bare string that has to
/// be asked for deliberately.
/// </remarks>
public class LinkedAccountService(DashboardDbContext db, TokenProtector protector)
{
    /// <summary>
    /// Stores the result of a successful token exchange, replacing any existing link for the same
    /// user and provider. Re-linking updates in place rather than inserting a second row, so there's
    /// never a stale token copy left behind that revocation would miss.
    /// </summary>
    public async Task UpsertAsync(
        int userId,
        OAuthProvider provider,
        OAuthTokenResult tokens,
        ProviderAccountInfo account,
        CancellationToken ct)
    {
        var existing = await db.LinkedAccounts
            .SingleOrDefaultAsync(a => a.UserId == userId && a.Provider == provider, ct);

        if (existing is null)
        {
            db.LinkedAccounts.Add(new LinkedAccount
            {
                UserId = userId,
                Provider = provider,
                ProviderUserId = account.Id,
                ProviderAccountName = account.DisplayName,
                EncryptedAccessToken = protector.Protect(tokens.AccessToken),
                EncryptedRefreshToken = protector.ProtectOptional(tokens.RefreshToken),
                Scopes = tokens.Scopes,
                ExpiresAtUtc = tokens.ExpiresAtUtc,
                RefreshTokenExpiresAtUtc = tokens.RefreshTokenExpiresAtUtc,
                ObtainedAtUtc = DateTimeOffset.UtcNow,
            });
        }
        else
        {
            existing.ProviderUserId = account.Id;
            existing.ProviderAccountName = account.DisplayName;
            existing.EncryptedAccessToken = protector.Protect(tokens.AccessToken);

            // Only overwrite the stored refresh token when the provider actually sent a new one.
            // Google omits refresh_token on repeat consents, and clobbering the good stored value
            // with null there would silently break M3's refresh path.
            if (tokens.RefreshToken is not null)
            {
                existing.EncryptedRefreshToken = protector.Protect(tokens.RefreshToken);
                existing.RefreshTokenExpiresAtUtc = tokens.RefreshTokenExpiresAtUtc;
            }

            existing.Scopes = tokens.Scopes;
            existing.ExpiresAtUtc = tokens.ExpiresAtUtc;
            existing.ObtainedAtUtc = DateTimeOffset.UtcNow;

            // A completed consent is the one thing that can clear the latch. Anything less — a retry,
            // a restart, a lucky API call — would just re-discover that the grant is still dead.
            existing.RefreshedAtUtc = null;
            existing.ReauthorizationRequiredAtUtc = null;
        }

        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Everything the refresh logic needs about a link, with both tokens decrypted. Server side
    /// only, and named to make that obvious at the call site — nothing here may reach a response.
    /// </summary>
    public async Task<StoredProviderTokens?> GetTokenStateAsync(int userId, OAuthProvider provider, CancellationToken ct)
    {
        var account = await db.LinkedAccounts.AsNoTracking()
            .SingleOrDefaultAsync(a => a.UserId == userId && a.Provider == provider, ct);

        if (account is null)
        {
            return null;
        }

        return new StoredProviderTokens(
            AccessToken: protector.Unprotect(account.EncryptedAccessToken),
            RefreshToken: protector.UnprotectOptional(account.EncryptedRefreshToken),
            ExpiresAtUtc: account.ExpiresAtUtc,
            RefreshTokenExpiresAtUtc: account.RefreshTokenExpiresAtUtc,
            ReauthorizationRequiredAtUtc: account.ReauthorizationRequiredAtUtc);
    }

    /// <summary>
    /// Persists the result of a successful refresh grant, keeping the link row itself intact.
    /// </summary>
    /// <remarks>
    /// Separate from <see cref="UpsertAsync"/> because a refresh is not a re-link: no consent
    /// happened, the provider account is unchanged, and <c>ObtainedAtUtc</c> must keep pointing at
    /// the original authorization. The two also differ on the refresh token itself — GitHub
    /// <em>rotates</em> it and the new value must be written before it's needed, while Google
    /// returns none and the stored one has to survive untouched. Both are handled by the same rule:
    /// write what the provider sent, keep what it didn't.
    /// </remarks>
    public async Task UpdateAfterRefreshAsync(
        int userId,
        OAuthProvider provider,
        OAuthTokenResult tokens,
        CancellationToken ct)
    {
        var account = await db.LinkedAccounts
            .SingleOrDefaultAsync(a => a.UserId == userId && a.Provider == provider, ct)
            ?? throw new ProviderNotLinkedException(provider);

        account.EncryptedAccessToken = protector.Protect(tokens.AccessToken);
        account.ExpiresAtUtc = tokens.ExpiresAtUtc;

        if (tokens.RefreshToken is not null)
        {
            account.EncryptedRefreshToken = protector.Protect(tokens.RefreshToken);
            account.RefreshTokenExpiresAtUtc = tokens.RefreshTokenExpiresAtUtc;
        }

        // A refresh response may restate the granted scopes; it never widens them. Ignoring a null
        // here keeps a terse provider response from erasing what we know.
        if (tokens.Scopes is not null)
        {
            account.Scopes = tokens.Scopes;
        }

        account.RefreshedAtUtc = DateTimeOffset.UtcNow;

        // A working refresh is proof the grant is alive, so any earlier latch was wrong or stale.
        account.ReauthorizationRequiredAtUtc = null;

        await db.SaveChangesAsync(ct);
    }

    /// <summary>
    /// Latches the link as unrecoverable, so the SPA can offer "Reconnect" instead of the dashboard
    /// re-attempting a grant that is known dead on every page load.
    /// </summary>
    /// <remarks>
    /// The dead tokens are left in place rather than nulled out. They're useless, but they're also
    /// encrypted, and keeping the row whole means the failure is diagnosable afterwards instead of
    /// looking identical to "never linked" — which has a different remedy.
    /// </remarks>
    public async Task MarkReauthorizationRequiredAsync(int userId, OAuthProvider provider, CancellationToken ct) =>
        await db.LinkedAccounts
            .Where(a => a.UserId == userId && a.Provider == provider && a.ReauthorizationRequiredAtUtc == null)
            .ExecuteUpdateAsync(
                set => set.SetProperty(a => a.ReauthorizationRequiredAtUtc, DateTimeOffset.UtcNow), ct);

    /// <summary>What the SPA is allowed to know: which providers are linked, and as whom.</summary>
    public async Task<List<LinkedAccountSummary>> GetSummariesAsync(int userId, CancellationToken ct) =>
        await db.LinkedAccounts
            .Where(a => a.UserId == userId)
            .OrderBy(a => a.Provider)
            .Select(a => new LinkedAccountSummary(
                a.Provider.ToString(),
                a.ProviderAccountName,
                a.Scopes,
                a.ExpiresAtUtc,
                a.ObtainedAtUtc,
                a.RefreshedAtUtc,
                a.RefreshTokenExpiresAtUtc,
                // Whether the link is broken is a fact about the connection, not token material, and
                // the SPA needs it to draw "Reconnect" instead of a healthy card.
                a.ReauthorizationRequiredAtUtc != null,
                // "Can this link heal itself?" — true when a refresh token is stored. Reported as a
                // boolean derived from the ciphertext column, never the ciphertext itself.
                a.EncryptedRefreshToken != null))
            .ToListAsync(ct);

    /// <summary>
    /// Decrypts and returns the stored access token exactly as persisted, or null if this provider
    /// isn't linked. Server side only — this value must never reach a response body.
    /// </summary>
    /// <remarks>
    /// This does <em>not</em> refresh. It answers "what is in the database", which is what the
    /// encryption round-trip tests need and nothing else should want: callers that are about to
    /// spend the token on a provider API must go through <c>ProviderTokenService</c>, which knows
    /// how to notice an expired one.
    /// </remarks>
    public async Task<string?> GetAccessTokenAsync(int userId, OAuthProvider provider, CancellationToken ct)
    {
        var account = await db.LinkedAccounts.AsNoTracking()
            .SingleOrDefaultAsync(a => a.UserId == userId && a.Provider == provider, ct);

        return account is null ? null : protector.Unprotect(account.EncryptedAccessToken);
    }

    /// <summary>
    /// Deletes the local link. M5 replaces this with a real unlink that calls the provider's revoke
    /// endpoint first — deleting the row alone leaves a live token in the provider's hands.
    /// </summary>
    public async Task<bool> DeleteAsync(int userId, OAuthProvider provider, CancellationToken ct)
    {
        var deleted = await db.LinkedAccounts
            .Where(a => a.UserId == userId && a.Provider == provider)
            .ExecuteDeleteAsync(ct);

        return deleted > 0;
    }
}

/// <summary>
/// The SPA-facing view of a link. Contains no token material of any kind, encrypted or otherwise —
/// this is the BFF boundary expressed as a type.
/// </summary>
/// <param name="RefreshedAtUtc">Null until the refresh grant has replaced the original token at least once.</param>
/// <param name="ReauthorizationRequired">The link is broken beyond what a refresh can fix; the user must re-consent.</param>
/// <param name="CanRefresh">A refresh token is stored, so an expiring access token can heal itself.</param>
public record LinkedAccountSummary(
    string Provider,
    string? AccountName,
    string? Scopes,
    DateTimeOffset? ExpiresAtUtc,
    DateTimeOffset ObtainedAtUtc,
    DateTimeOffset? RefreshedAtUtc,
    DateTimeOffset? RefreshTokenExpiresAtUtc,
    bool ReauthorizationRequired,
    bool CanRefresh);

/// <summary>
/// The decrypted token state behind one link — the input the refresh decision is made from.
/// </summary>
/// <remarks>
/// This type holds live credentials in plaintext, which is precisely why it is a distinct type from
/// <see cref="LinkedAccountSummary"/> rather than a few extra fields on it. There is no serializer
/// path from here to an HTTP response: a controller that wanted to leak a token would have to ask
/// for this type by name and then write it out deliberately.
/// </remarks>
public record StoredProviderTokens(
    string AccessToken,
    string? RefreshToken,
    DateTimeOffset? ExpiresAtUtc,
    DateTimeOffset? RefreshTokenExpiresAtUtc,
    DateTimeOffset? ReauthorizationRequiredAtUtc);
