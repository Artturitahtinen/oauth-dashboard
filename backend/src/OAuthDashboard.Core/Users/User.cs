namespace OAuthDashboard.Core.Users;

/// <summary>
/// The local account the SPA logs into. Deliberately not ASP.NET Core Identity: this project needs
/// exactly one credential check and one cookie, and Identity would hide the password hashing and
/// sign-in mechanics that are the point of the exercise.
/// </summary>
/// <remarks>
/// This local identity is what provider tokens hang off. Without it, "the user's GitHub token"
/// would really mean "whoever holds the session cookie", and there'd be nothing to scope a
/// <see cref="Accounts.LinkedAccount"/> to.
/// </remarks>
public class User
{
    public int Id { get; init; }

    public required string Username { get; init; }

    /// <summary>
    /// Self-describing PBKDF2 hash, never a reversible encryption of the password. Format is
    /// documented on <c>PasswordHasher</c>; the iteration count travels inside the string so
    /// raising it later doesn't invalidate existing hashes.
    /// </summary>
    public required string PasswordHash { get; set; }

    public DateTimeOffset CreatedAtUtc { get; init; }

    public List<Accounts.LinkedAccount> LinkedAccounts { get; init; } = [];
}
