namespace OAuthDashboard.Core.Accounts;

/// <summary>
/// The upstream providers this dashboard can link. Persisted as its string name rather than its
/// numeric value, so the SQLite rows stay readable and reordering the enum can't silently
/// repoint every stored token at the wrong provider.
/// </summary>
public enum OAuthProvider
{
    GitHub = 1,
    Google = 2,
}
