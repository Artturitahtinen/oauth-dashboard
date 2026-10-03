using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace OAuthDashboard.Infrastructure.Auth;

/// <summary>
/// The subset of an OIDC provider's discovery document this app actually uses.
/// </summary>
/// <remarks>
/// Only the fields that get used are modelled. A discovery document has around thirty, and pulling
/// in the ones nothing reads would invite trusting a value that was never checked.
/// </remarks>
public record OpenIdConnectDiscoveryDocument(
    string Issuer,
    string AuthorizationEndpoint,
    string TokenEndpoint,
    string UserInfoEndpoint,
    string JwksUri,
    string? RevocationEndpoint);

/// <summary>
/// Fetches and caches an OIDC provider's discovery document and its JSON Web Key Set.
/// </summary>
/// <remarks>
/// This is the piece of M4 that makes OIDC more than "OAuth2 with an extra token": the provider
/// publishes where its endpoints are and which public keys it currently signs with, so a key
/// rotation on Google's side needs no change here.
/// <para>
/// <b>Both documents are cached, for different reasons and different lengths.</b> The discovery
/// document changes on the order of never, so it is held for a day. The key set changes whenever the
/// provider rotates a signing key — Google does this roughly daily and overlaps old and new keys —
/// so it is held for an hour, and additionally refetched on demand when a token arrives bearing a
/// <c>kid</c> the cached set doesn't contain.
/// </para>
/// <para>
/// <b>That on-demand refetch is rate limited, and has to be.</b> "Unknown kid, so go ask Google
/// again" is a fetch this app performs on the say-so of an unauthenticated token — an attacker can
/// mint junk headers all day. Without <see cref="OpenIdConnectCacheIntervals.MinimumRefetch"/> a
/// stream of them turns into a stream of outbound requests, which is a denial of service against
/// Google's endpoint with this app's own IP address on it, and against this app when Google starts
/// refusing.
/// </para>
/// <para>
/// The floor has a cost worth stating plainly: a genuine rotation occurring within five minutes of a
/// cache fill is <em>not</em> picked up until the floor passes, and tokens signed with the new key
/// fail validation until then. That is the accepted trade — it is the same one
/// <c>Microsoft.IdentityModel</c>'s <c>ConfigurationManager</c> makes with the same default — and it
/// is safe in practice because providers publish a new key well before they start signing with it.
/// The alternative, an unbounded refetch, hands an attacker a request amplifier.
/// </para>
/// <para>
/// Registered as a singleton so the caches are actually shared, and single-flighted per authority so
/// a cold start with several concurrent requests results in one fetch rather than several.
/// </para>
/// </remarks>
public class OpenIdConnectDiscoveryCache(
    IHttpClientFactory httpClientFactory,
    ILogger<OpenIdConnectDiscoveryCache> logger,
    OpenIdConnectCacheIntervals? intervals = null)
{
    public const string HttpClientName = "oidc-discovery";

    private readonly OpenIdConnectCacheIntervals _intervals = intervals ?? OpenIdConnectCacheIntervals.Default;

    private readonly ConcurrentDictionary<string, AuthorityCache> _authorities = new();

    private TimeSpan DocumentTtl => _intervals.Document;
    private TimeSpan KeysTtl => _intervals.Keys;
    private TimeSpan MinimumRefetchInterval => _intervals.MinimumRefetch;

    /// <summary>
    /// Returns the provider's discovery document, fetching it on first use.
    /// </summary>
    /// <exception cref="OpenIdConnectDiscoveryException">
    /// The document could not be fetched, was missing a required endpoint, or claimed an issuer
    /// other than the authority it was served from.
    /// </exception>
    public async Task<OpenIdConnectDiscoveryDocument> GetDocumentAsync(string authority, CancellationToken ct)
    {
        var cache = _authorities.GetOrAdd(authority, _ => new AuthorityCache());

        if (IsFresh(cache.Document, cache.DocumentFetchedAt, DocumentTtl))
        {
            return cache.Document!;
        }

        await cache.Gate.WaitAsync(ct);
        try
        {
            // Re-checked inside the gate: whoever held it may have just done this work.
            if (IsFresh(cache.Document, cache.DocumentFetchedAt, DocumentTtl))
            {
                return cache.Document!;
            }

            var url = $"{authority.TrimEnd('/')}/.well-known/openid-configuration";
            var payload = await FetchAsync<DiscoveryPayload>(url, ct);

            var document = Convert(payload, authority);

            cache.Document = document;
            cache.DocumentFetchedAt = DateTimeOffset.UtcNow;

            logger.LogInformation(
                "Loaded the OIDC discovery document for {Authority} (token endpoint: {TokenEndpoint}, jwks: {JwksUri}).",
                authority, document.TokenEndpoint, document.JwksUri);

            return document;
        }
        finally
        {
            cache.Gate.Release();
        }
    }

    /// <summary>
    /// Returns the provider's current signing keys.
    /// </summary>
    /// <param name="forceRefresh">
    /// Set when a token carried a <c>kid</c> the cached set didn't have, which is what a key rotation
    /// looks like from here. Honoured no more often than <see cref="MinimumRefetchInterval"/> — see
    /// the note on the class about why an attacker-triggerable fetch needs a floor.
    /// </param>
    public async Task<JsonWebKeySet> GetSigningKeysAsync(string authority, bool forceRefresh, CancellationToken ct)
    {
        var cache = _authorities.GetOrAdd(authority, _ => new AuthorityCache());

        if (CanUseCachedKeys(cache, forceRefresh))
        {
            return cache.Keys!;
        }

        // The JWKS URI comes from the discovery document rather than from configuration — the
        // provider is the only thing entitled to say where its keys live. Resolved *before* the gate
        // below is taken, because GetDocumentAsync has a gate of its own and nesting them is a
        // deadlock waiting to be introduced.
        var document = await GetDocumentAsync(authority, ct);

        await cache.Gate.WaitAsync(ct);
        try
        {
            // Re-checked inside the gate. On a forced refresh this is what stops a burst of tokens
            // with unknown kids from becoming a burst of outbound requests: the first one through
            // stamps KeysFetchedAt, and everyone queued behind it falls inside the floor.
            if (CanUseCachedKeys(cache, forceRefresh))
            {
                return cache.Keys!;
            }

            var json = await FetchStringAsync(document.JwksUri, ct);

            JsonWebKeySet keys;
            try
            {
                keys = new JsonWebKeySet(json);
            }
            catch (Exception ex)
            {
                throw new OpenIdConnectDiscoveryException($"The key set at {document.JwksUri} could not be parsed.", ex);
            }

            if (keys.Keys.Count == 0)
            {
                throw new OpenIdConnectDiscoveryException($"The key set at {document.JwksUri} contained no keys.");
            }

            cache.Keys = keys;
            cache.KeysFetchedAt = DateTimeOffset.UtcNow;

            logger.LogInformation(
                "Loaded {KeyCount} signing key(s) for {Authority} (kids: {Kids}).",
                keys.Keys.Count, authority, string.Join(", ", keys.Keys.Select(k => k.Kid)));

            return keys;
        }
        finally
        {
            cache.Gate.Release();
        }
    }

    private static bool IsFresh(object? value, DateTimeOffset fetchedAt, TimeSpan ttl) =>
        value is not null && DateTimeOffset.UtcNow - fetchedAt < ttl;

    /// <summary>
    /// Whether the cached key set may be served. A forced refresh doesn't ignore the cache outright —
    /// it swaps the ordinary TTL for a much shorter floor, so "the provider rotated a key" is
    /// answered promptly while "an attacker is inventing kids" is answered from memory.
    /// </summary>
    private bool CanUseCachedKeys(AuthorityCache cache, bool forceRefresh)
    {
        if (cache.Keys is null)
        {
            return false;
        }

        var age = DateTimeOffset.UtcNow - cache.KeysFetchedAt;
        return age < (forceRefresh ? MinimumRefetchInterval : KeysTtl);
    }

    private static OpenIdConnectDiscoveryDocument Convert(DiscoveryPayload payload, string authority)
    {
        // OpenID Connect Discovery §4.3 requires the issuer in the document to equal the authority it
        // was fetched from. Skipping this check is how a redirected or cached-poisoned discovery
        // response gets to nominate a different identity provider, whose id_tokens would then pass
        // issuer validation because the expected issuer came from the same untrusted document.
        if (!string.Equals(payload.Issuer?.TrimEnd('/'), authority.TrimEnd('/'), StringComparison.Ordinal))
        {
            throw new OpenIdConnectDiscoveryException(
                $"The discovery document served from {authority} declares issuer '{payload.Issuer}'.");
        }

        return new OpenIdConnectDiscoveryDocument(
            Issuer: payload.Issuer!,
            AuthorizationEndpoint: Required(payload.AuthorizationEndpoint, "authorization_endpoint", authority),
            TokenEndpoint: Required(payload.TokenEndpoint, "token_endpoint", authority),
            UserInfoEndpoint: Required(payload.UserInfoEndpoint, "userinfo_endpoint", authority),
            JwksUri: Required(payload.JwksUri, "jwks_uri", authority),
            // Optional in the spec, and the seam M5's real revocation hangs off.
            RevocationEndpoint: payload.RevocationEndpoint);
    }

    private static string Required(string? value, string field, string authority) =>
        string.IsNullOrWhiteSpace(value)
            ? throw new OpenIdConnectDiscoveryException($"The discovery document for {authority} has no {field}.")
            : value;

    private async Task<T> FetchAsync<T>(string url, CancellationToken ct)
    {
        using var client = httpClientFactory.CreateClient(HttpClientName);
        using var response = await client.GetAsync(url, ct);
        response.EnsureSuccessStatusCode();

        return await response.Content.ReadFromJsonAsync<T>(cancellationToken: ct)
               ?? throw new OpenIdConnectDiscoveryException($"{url} returned an empty body.");
    }

    private async Task<string> FetchStringAsync(string url, CancellationToken ct)
    {
        using var client = httpClientFactory.CreateClient(HttpClientName);
        using var response = await client.GetAsync(url, ct);
        response.EnsureSuccessStatusCode();

        return await response.Content.ReadAsStringAsync(ct);
    }

    /// <summary>Everything cached for one authority, plus the gate that single-flights fetching it.</summary>
    private sealed class AuthorityCache
    {
        public SemaphoreSlim Gate { get; } = new(1, 1);

        public OpenIdConnectDiscoveryDocument? Document { get; set; }

        public DateTimeOffset DocumentFetchedAt { get; set; }

        public JsonWebKeySet? Keys { get; set; }

        public DateTimeOffset KeysFetchedAt { get; set; }
    }

    private record DiscoveryPayload(
        [property: JsonPropertyName("issuer")] string? Issuer,
        [property: JsonPropertyName("authorization_endpoint")] string? AuthorizationEndpoint,
        [property: JsonPropertyName("token_endpoint")] string? TokenEndpoint,
        [property: JsonPropertyName("userinfo_endpoint")] string? UserInfoEndpoint,
        [property: JsonPropertyName("jwks_uri")] string? JwksUri,
        [property: JsonPropertyName("revocation_endpoint")] string? RevocationEndpoint);
}

/// <summary>
/// How long <see cref="OpenIdConnectDiscoveryCache"/> holds each piece of provider metadata.
/// </summary>
/// <remarks>
/// The defaults mirror what <c>Microsoft.IdentityModel</c>'s own <c>ConfigurationManager</c> uses —
/// a long automatic refresh interval plus a short floor on <em>requested</em> refreshes — because the
/// tradeoff is the same one: a key rotation should be picked up promptly, and picking it up must not
/// be something an unauthenticated caller can trigger at will.
/// <para>
/// Overridable so the floor can be tested from both sides. Production never passes it.
/// </para>
/// </remarks>
public record OpenIdConnectCacheIntervals(TimeSpan Document, TimeSpan Keys, TimeSpan MinimumRefetch)
{
    public static readonly OpenIdConnectCacheIntervals Default = new(
        Document: TimeSpan.FromHours(24),
        Keys: TimeSpan.FromHours(1),
        MinimumRefetch: TimeSpan.FromMinutes(5));
}

/// <summary>
/// The provider's own metadata could not be obtained or did not describe the provider it was asked
/// about. Distinct from a token being invalid: nothing has been proven wrong about the user yet.
/// </summary>
public class OpenIdConnectDiscoveryException(string message, Exception? inner = null)
    : Exception(message, inner);
