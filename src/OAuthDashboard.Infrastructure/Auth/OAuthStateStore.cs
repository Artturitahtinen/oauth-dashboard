using System.Security.Cryptography;
using Microsoft.Extensions.Caching.Memory;

namespace OAuthDashboard.Infrastructure.Auth;

/// <summary>
/// Tracks in-flight OAuth `state` values between the authorize redirect and the callback.
/// Single-use by design: <see cref="TryConsume"/> removes the entry, so a state value replayed
/// on a second callback (e.g. an attacker resubmitting a captured redirect) is rejected.
/// </summary>
public class OAuthStateStore(IMemoryCache cache)
{
    private static readonly TimeSpan Ttl = TimeSpan.FromMinutes(5);

    public string Issue()
    {
        var state = GenerateState();
        cache.Set(CacheKey(state), true, Ttl);
        return state;
    }

    public bool TryConsume(string state)
    {
        var key = CacheKey(state);
        if (!cache.TryGetValue(key, out _))
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
