using Microsoft.EntityFrameworkCore;
using OAuthDashboard.Core.Users;
using OAuthDashboard.Infrastructure.Persistence;
using OAuthDashboard.Infrastructure.Security;

namespace OAuthDashboard.Infrastructure.Users;

/// <summary>
/// Minimal local account handling: claim the single account on first run, then verify credentials.
/// </summary>
/// <remarks>
/// Registration is open only while the users table is empty — a "first-run claim". That keeps a
/// personal dashboard from exposing an open sign-up endpoint, without needing an invite system or a
/// bootstrap password sitting in plaintext in configuration.
/// </remarks>
public class LocalUserService(DashboardDbContext db)
{
    /// <summary>True while nobody has claimed the account yet, which is what unlocks registration.</summary>
    public async Task<bool> NeedsSetupAsync(CancellationToken ct) => !await db.Users.AnyAsync(ct);

    /// <summary>
    /// Creates the one local account. Fails closed if an account already exists, so this can't be
    /// used to add a second user or overwrite the first one's password.
    /// </summary>
    public async Task<User?> TryRegisterFirstUserAsync(string username, string password, CancellationToken ct)
    {
        if (await db.Users.AnyAsync(ct))
        {
            return null;
        }

        var user = new User
        {
            Username = username,
            PasswordHash = PasswordHasher.Hash(password),
            CreatedAtUtc = DateTimeOffset.UtcNow,
        };

        db.Users.Add(user);

        try
        {
            await db.SaveChangesAsync(ct);
        }
        catch (DbUpdateException)
        {
            // Two simultaneous first-run registrations: the unique index decides the winner and the
            // loser is treated as "already taken" rather than surfacing as a 500.
            return null;
        }

        return user;
    }

    /// <summary>
    /// Verifies a login attempt, returning the user on success and null on any failure.
    /// </summary>
    /// <remarks>
    /// Callers get one undifferentiated null for "no such user" and "wrong password" on purpose: a
    /// distinguishable response turns this endpoint into a username oracle. The unknown-user path
    /// still runs a full PBKDF2 verification against a dummy hash so it takes comparable time —
    /// returning early there would leak the same information through latency instead.
    /// </remarks>
    public async Task<User?> VerifyCredentialsAsync(string username, string password, CancellationToken ct)
    {
        var user = await db.Users
            .SingleOrDefaultAsync(u => u.Username.ToLower() == username.ToLower(), ct);

        if (user is null)
        {
            _ = PasswordHasher.Verify(password, DummyHash.Value);
            return null;
        }

        return PasswordHasher.Verify(password, user.PasswordHash) ? user : null;
    }

    public Task<User?> FindByIdAsync(int id, CancellationToken ct) =>
        db.Users.SingleOrDefaultAsync(u => u.Id == id, ct);

    /// <summary>
    /// A valid hash of a throwaway password, computed once, purely to give the unknown-user path the
    /// same cost as the known-user path.
    /// </summary>
    private static class DummyHash
    {
        internal static readonly string Value = PasswordHasher.Hash("timing-equalizer");
    }
}
