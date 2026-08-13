using System.Security.Cryptography;
using Microsoft.Extensions.Caching.Memory;
using OAuthDashboard.Core.Accounts;

namespace OAuthDashboard.Infrastructure.Auth;

/// <summary>
/// One authorization attempt in flight, held server-side between the <c>/authorize</c> redirect and
/// the provider's callback. None of this is ever sent to the browser except <see cref="State"/>.
/// </summary>
public record PendingAuthorization(
    string State,
    string CodeVerifier,
    OAuthProvider Provider,
    int UserId);

/// <summary>
/// Tracks in-flight OAuth authorizations, keyed by the <c>state</c> value handed to the provider.
/// </summary>
/// <remarks>
/// Single-use by design: <see cref="TryConsume"/> removes the entry, so a state value replayed on a
/// second callback (an attacker resubmitting a captured redirect) is rejected because there's
/// nothing left to consume.
/// <para>
/// M2 widened each entry from a bare marker to a record, because two more things now have to
/// survive the round trip and neither can safely live in the browser:
/// the PKCE <c>code_verifier</c> (the whole point is that only the server ever sees it), and the id
/// of the user who started the flow. Binding the user id here means the callback can't attach a
/// provider account to a <em>different</em> session than the one that asked for it — the flow is
/// completed by the same logged-in user or not at all.
/// </para>
/// <para>
/// <see cref="IMemoryCache"/> is the right size for this: these entries are meant to be short-lived
/// and disposable, and losing them on restart just means an in-flight link has to be retried. It
/// does mean a backend restart mid-flow surfaces as <c>invalid_state</c> rather than as a hang.
/// </para>
/// </remarks>
public class OAuthStateStore(IMemoryCache cache)
{
    // Long enough for a real consent screen (reading scopes, a 2FA prompt), short enough that a
    // leaked authorize URL goes stale quickly.
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Mints a fresh state + PKCE verifier pair for <paramref name="userId"/> and remembers it.
    /// </summary>
    public PendingAuthorization Issue(OAuthProvider provider, int userId)
    {
        var pending = new PendingAuthorization(
            State: GenerateState(),
            CodeVerifier: Pkce.NewCodeVerifier(),
            Provider: provider,
            UserId: userId);

        cache.Set(CacheKey(pending.State), pending, Ttl);
        return pending;
    }

    /// <summary>
    /// Looks up and immediately invalidates the entry for <paramref name="state"/>. A false return
    /// means the callback wasn't initiated by this backend, has already been used, or has expired —
    /// all of which are handled the same way, by refusing to go any further.
    /// </summary>
    public bool TryConsume(string state, out PendingAuthorization? pending)
    {
        var key = CacheKey(state);
        if (!cache.TryGetValue(key, out pending) || pending is null)
        {
            return false;
        }

        cache.Remove(key);
        return true;
    }

    private static string GenerateState() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');

    private static string CacheKey(string state) => $"oauth-state:{state}";
}
