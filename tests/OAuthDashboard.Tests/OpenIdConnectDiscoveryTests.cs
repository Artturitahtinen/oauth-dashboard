using OAuthDashboard.Infrastructure.Auth;

namespace OAuthDashboard.Tests;

/// <summary>
/// The metadata layer OIDC adds under the flow: where the provider's endpoints are and which keys it
/// signs with, both fetched from the provider rather than compiled in.
/// </summary>
/// <remarks>
/// Worth testing separately from the tokens because this is the layer that decides <em>what counts
/// as the provider</em>. Everything downstream — issuer validation, signature validation — is only
/// as trustworthy as the document these checks are performed against.
/// </remarks>
public class OpenIdConnectDiscoveryTests : IDisposable
{
    private readonly FakeGoogle _google = new();

    public void Dispose() => _google.Dispose();

    [Fact]
    public async Task GetDocumentAsync_ReadsTheEndpointsTheProviderPublishes()
    {
        var document = await _google.CreateDiscoveryCache()
            .GetDocumentAsync(FakeGoogle.Authority, CancellationToken.None);

        Assert.Equal(FakeGoogle.Authority, document.Issuer);
        Assert.Equal(FakeGoogle.AuthorizationEndpoint, document.AuthorizationEndpoint);
        Assert.Equal(FakeGoogle.TokenEndpoint, document.TokenEndpoint);
        Assert.Equal(FakeGoogle.UserInfoEndpoint, document.UserInfoEndpoint);
        Assert.Equal(FakeGoogle.JwksUri, document.JwksUri);

        // Unused until M5's real revocation, and read now so the seam is visibly there rather than
        // rediscovered later.
        Assert.Equal(FakeGoogle.RevocationEndpoint, document.RevocationEndpoint);
    }

    /// <summary>
    /// OpenID Connect Discovery §4.3: the issuer inside the document must equal the authority it was
    /// served from.
    /// </summary>
    /// <remarks>
    /// Skipping this check is subtler than it looks, because the same document supplies the expected
    /// issuer that id_token validation later compares against. A document that names a different
    /// issuer would therefore <em>validate its own tokens perfectly</em> — issuer checking would pass
    /// while checking the wrong thing. The comparison has to be against the authority this app
    /// configured, which is the one value in the chain an attacker cannot supply.
    /// </remarks>
    [Fact]
    public async Task GetDocumentAsync_RejectsADocumentThatNamesADifferentIssuer()
    {
        _google.IssuerToPublish = "https://accounts.evil.example";

        await Assert.ThrowsAsync<OpenIdConnectDiscoveryException>(
            () => _google.CreateDiscoveryCache().GetDocumentAsync(FakeGoogle.Authority, CancellationToken.None));
    }

    /// <summary>
    /// A document missing an endpoint this app needs fails here rather than producing a request to
    /// an empty URL three layers down.
    /// </summary>
    [Fact]
    public async Task GetDocumentAsync_RejectsADocumentMissingAnEndpointThisAppNeeds()
    {
        _google.OmitTokenEndpoint = true;

        await Assert.ThrowsAsync<OpenIdConnectDiscoveryException>(
            () => _google.CreateDiscoveryCache().GetDocumentAsync(FakeGoogle.Authority, CancellationToken.None));
    }

    /// <summary>
    /// An empty key set means nothing can ever be verified. Treated as a metadata failure rather than
    /// silently becoming "no key matched, so every token is invalid" — the two have different causes
    /// and only one of them is the user's problem.
    /// </summary>
    [Fact]
    public async Task GetSigningKeysAsync_RejectsAnEmptyKeySet()
    {
        _google.PublishNoKeys = true;

        await Assert.ThrowsAsync<OpenIdConnectDiscoveryException>(
            () => _google.CreateDiscoveryCache()
                .GetSigningKeysAsync(FakeGoogle.Authority, forceRefresh: false, CancellationToken.None));
    }

    /// <summary>
    /// The metadata is fetched once and shared. Registered scoped instead of singleton, this cache
    /// would refetch on every request — slow, and a good way to be rate limited by the identity
    /// provider for no reason.
    /// </summary>
    [Fact]
    public async Task GetDocumentAsync_FetchesOncePerAuthorityAcrossManyCalls()
    {
        var cache = _google.CreateDiscoveryCache();

        for (var call = 0; call < 5; call++)
        {
            await cache.GetDocumentAsync(FakeGoogle.Authority, CancellationToken.None);
        }

        Assert.Equal(1, _google.DiscoveryFetches);
    }

    /// <summary>
    /// A cold start under load. Several requests arriving before the first fetch completes must
    /// produce one fetch, not one each — the same single-flight reasoning as M3's refresh gate,
    /// applied to a much cheaper resource for a much less severe reason.
    /// </summary>
    [Fact]
    public async Task GetDocumentAsync_SingleFlightsAColdStart()
    {
        var cache = _google.CreateDiscoveryCache();

        await Task.WhenAll(Enumerable.Range(0, 8).Select(_ =>
            Task.Run(() => cache.GetDocumentAsync(FakeGoogle.Authority, CancellationToken.None))));

        Assert.Equal(1, _google.DiscoveryFetches);
    }
}
