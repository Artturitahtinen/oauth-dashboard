using System.Collections.Concurrent;
using OAuthDashboard.Core.Accounts;

namespace OAuthDashboard.Infrastructure.Auth;

/// <summary>
/// One mutex per (user, provider) link, so two requests can never refresh the same grant at once.
/// </summary>
/// <remarks>
/// This exists because refresh tokens <em>rotate</em>. If two requests both notice the token is
/// expiring and both POST the same refresh token, the provider issues two new grants from one — and
/// treats the second presentation of an already-used refresh token as a replay, which is exactly the
/// signal OAuth implementations use to revoke the entire grant as stolen. So concurrent refresh is
/// not merely wasteful: it can log the user out of a provider they never touched. Serializing per
/// link, plus a re-read after the wait, turns the race into "one refreshes, the rest use the
/// result."
/// <para>
/// The scope of this lock is one process. It is the right size for a single-user local dashboard,
/// where the concurrency being defended against is the SPA firing several widget requests at once
/// on page load. It would <em>not</em> be enough behind more than one instance — that needs the
/// database row itself to be the lock (a conditional update on the token value, or a transaction
/// with <c>UPDATE ... WHERE EncryptedAccessToken = @seen</c>), which is a bigger hammer than this
/// project needs.
/// </para>
/// <para>
/// Entries are never evicted. Bounded by users times providers — two rows here — so a cache eviction
/// policy would be more code than the thing it manages.
/// </para>
/// </remarks>
public sealed class RefreshLockRegistry
{
    private readonly ConcurrentDictionary<(int UserId, OAuthProvider Provider), SemaphoreSlim> _gates = new();

    public SemaphoreSlim For(int userId, OAuthProvider provider) =>
        _gates.GetOrAdd((userId, provider), _ => new SemaphoreSlim(1, 1));
}
