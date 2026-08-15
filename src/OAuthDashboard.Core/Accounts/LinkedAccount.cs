using OAuthDashboard.Core.Users;

namespace OAuthDashboard.Core.Accounts;

/// <summary>
/// One provider connection belonging to one local <see cref="User"/> — the row that makes the BFF
/// boundary real. Every token the dashboard uses lives here, encrypted, on the server; the SPA is
/// never told any of these values, only whether the link exists.
/// </summary>
public class LinkedAccount
{
    public int Id { get; init; }

    public int UserId { get; init; }

    public User? User { get; init; }

    public required OAuthProvider Provider { get; init; }

    /// <summary>The provider's own account id, kept so a re-link can be spotted as the same account.</summary>
    public string? ProviderUserId { get; set; }

    /// <summary>Human-readable provider handle (GitHub login, Google email) for display only.</summary>
    public string? ProviderAccountName { get; set; }

    /// <summary>
    /// Data Protection ciphertext, never the raw token. Reading this column straight out of the
    /// SQLite file yields an opaque blob — see <c>TokenProtector</c>.
    /// </summary>
    public required string EncryptedAccessToken { get; set; }

    /// <summary>
    /// Also ciphertext, and null for providers that didn't issue one. GitHub OAuth Apps hand out
    /// non-expiring access tokens with no refresh token at all, which is why this is nullable
    /// rather than required.
    /// </summary>
    public string? EncryptedRefreshToken { get; set; }

    /// <summary>Scopes the provider actually granted, which can be narrower than what was asked for.</summary>
    public string? Scopes { get; set; }

    /// <summary>Null means "no expiry advertised" — not "already expired". M3 depends on that distinction.</summary>
    public DateTimeOffset? ExpiresAtUtc { get; set; }

    /// <summary>
    /// When the <em>refresh</em> token itself stops working (GitHub Apps: ~6 months; Google in
    /// Testing mode: 7 days). Once this passes there is no automated way back — the user has to walk
    /// the consent screen again — so it's worth surfacing rather than hitting as a surprise.
    /// </summary>
    public DateTimeOffset? RefreshTokenExpiresAtUtc { get; set; }

    /// <summary>When the link was first established, or last re-established through a full consent.</summary>
    public DateTimeOffset ObtainedAtUtc { get; set; }

    /// <summary>
    /// When the access token was last replaced by the refresh grant, or null if it never has been.
    /// Deliberately separate from <see cref="ObtainedAtUtc"/>: "this grant is three months old but
    /// the token in it is four minutes old" is precisely what M3 is supposed to make true, and
    /// collapsing the two timestamps would hide it.
    /// </summary>
    public DateTimeOffset? RefreshedAtUtc { get; set; }

    /// <summary>
    /// Set when the refresh path has proven it cannot recover this link — the refresh token was
    /// rejected, or there was never one to begin with and the access token stopped working. It is a
    /// latch, not a guess: once set, nothing but a fresh authorization clears it, so the dashboard
    /// can show "Reconnect" instead of retrying a grant that is known dead.
    /// </summary>
    public DateTimeOffset? ReauthorizationRequiredAtUtc { get; set; }
}
