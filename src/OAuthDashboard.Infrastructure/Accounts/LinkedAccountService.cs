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
            }

            existing.Scopes = tokens.Scopes;
            existing.ExpiresAtUtc = tokens.ExpiresAtUtc;
            existing.ObtainedAtUtc = DateTimeOffset.UtcNow;
        }

        await db.SaveChangesAsync(ct);
    }

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
                a.ObtainedAtUtc))
            .ToListAsync(ct);

    /// <summary>
    /// Decrypts and returns the stored access token, or null if this provider isn't linked. Server
    /// side only — this value must never reach a response body.
    /// </summary>
    public async Task<string?> GetAccessTokenAsync(int userId, OAuthProvider provider, CancellationToken ct)
    {
        var account = await db.LinkedAccounts
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
public record LinkedAccountSummary(
    string Provider,
    string? AccountName,
    string? Scopes,
    DateTimeOffset? ExpiresAtUtc,
    DateTimeOffset ObtainedAtUtc);
