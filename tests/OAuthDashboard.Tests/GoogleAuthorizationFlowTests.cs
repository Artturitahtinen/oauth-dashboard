using System.Net;
using OAuthDashboard.Infrastructure.Auth;

namespace OAuthDashboard.Tests;

/// <summary>
/// Google's half of M4 as it goes over the wire: what the authorize URL has to carry, what the token
/// exchange sends and gets back, and the places Google's conventions differ from GitHub's.
/// </summary>
public class GoogleAuthorizationFlowTests : IDisposable
{
    private const string State = "state-value";
    private const string Challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    private const string Nonce = "nonce-value";

    private readonly FakeGoogle _google = new();

    public void Dispose() => _google.Dispose();

    /// <summary>
    /// The two parameters without which Google's refresh flow simply does not exist. Their absence
    /// costs nothing at link time and everything an hour later, when the access token expires and
    /// there is no refresh token to replace it with.
    /// </summary>
    [Fact]
    public async Task BuildAuthorizationUrlAsync_AsksForOfflineAccessAndForcesTheConsentScreen()
    {
        var url = await BuildAuthorizationUrlAsync();

        Assert.Contains("access_type=offline", url, StringComparison.Ordinal);
        Assert.Contains("prompt=consent", url, StringComparison.Ordinal);
    }

    /// <summary>
    /// The nonce has to reach Google, or there is nothing for the id_token to echo back and the bind
    /// check degrades into "the token had no nonce, so skip it".
    /// </summary>
    [Fact]
    public async Task BuildAuthorizationUrlAsync_CarriesTheNonceAlongsideStateAndThePkceChallenge()
    {
        var url = await BuildAuthorizationUrlAsync();

        Assert.Contains($"nonce={Nonce}", url, StringComparison.Ordinal);
        Assert.Contains($"state={State}", url, StringComparison.Ordinal);
        Assert.Contains("code_challenge_method=S256", url, StringComparison.Ordinal);
        Assert.Contains($"code_challenge={Challenge}", url, StringComparison.Ordinal);
        Assert.Contains("response_type=code", url, StringComparison.Ordinal);
        Assert.Contains("scope=openid%20email%20profile", url, StringComparison.Ordinal);
    }

    /// <summary>
    /// The endpoint is the one the provider published, not one compiled in. That is the difference
    /// between OIDC discovery and a hardcoded URL that quietly rots.
    /// </summary>
    [Fact]
    public async Task BuildAuthorizationUrlAsync_TargetsTheEndpointFromTheDiscoveryDocument()
    {
        var url = await BuildAuthorizationUrlAsync();

        Assert.StartsWith(FakeGoogle.AuthorizationEndpoint + "?", url, StringComparison.Ordinal);
        Assert.Equal(1, _google.DiscoveryFetches);
    }

    [Fact]
    public async Task ExchangeCodeForTokenAsync_SendsTheAuthorizationCodeGrantWithThePkceVerifier()
    {
        _google.NonceToEcho = Nonce;
        _google.RefreshTokenToIssue = "1//granted";

        await _google.CreateClient().ExchangeCodeForTokenAsync("the-code", "the-verifier", Nonce, CancellationToken.None);

        var request = _google.LastTokenRequest;
        Assert.Equal("authorization_code", request.Form("grant_type"));
        Assert.Equal("the-code", request.Form("code"));
        Assert.Equal("the-verifier", request.Form("code_verifier"));
        Assert.Equal(FakeGoogle.ClientId, request.Form("client_id"));
        Assert.Equal(FakeGoogle.ClientSecret, request.Form("client_secret"));
        Assert.Equal(FakeGoogle.RedirectUri, request.Form("redirect_uri"));
    }

    /// <summary>
    /// The exchange returns a validated identity, not a raw JWT — there is no overload that hands
    /// back an unchecked one, which is what stops a caller from reading claims out of an assertion
    /// nobody verified.
    /// </summary>
    [Fact]
    public async Task ExchangeCodeForTokenAsync_ReturnsTheValidatedIdentityAlongsideTheTokens()
    {
        _google.NonceToEcho = Nonce;
        _google.RefreshTokenToIssue = "1//granted";
        _google.AccessTokenToIssue = "ya29.granted";

        var result = await _google.CreateClient()
            .ExchangeCodeForTokenAsync("the-code", "the-verifier", Nonce, CancellationToken.None);

        Assert.Equal("ya29.granted", result.Tokens.AccessToken);
        Assert.Equal("1//granted", result.Tokens.RefreshToken);
        Assert.Equal("openid email profile", result.Tokens.Scopes);
        Assert.Equal(FakeGoogle.Subject, result.Identity.Subject);
        Assert.Equal(FakeGoogle.Email, result.Identity.Email);
    }

    /// <summary>
    /// A token exchange that succeeds while returning an id_token bound to some other request must
    /// not produce a link. The tokens are real and would work — and using them anyway would mean
    /// storing a credential under an identity that was never proven to belong to this flow.
    /// </summary>
    [Fact]
    public async Task ExchangeCodeForTokenAsync_FailsWhenTheIdTokenAnswersADifferentRequest()
    {
        _google.NonceToEcho = "a-nonce-from-some-other-flow";

        await Assert.ThrowsAsync<IdTokenValidationException>(
            () => _google.CreateClient().ExchangeCodeForTokenAsync(
                "the-code", "the-verifier", Nonce, CancellationToken.None));
    }

    /// <summary>
    /// No id_token at all means the openid scope went missing. There is no identity to link, so this
    /// fails rather than falling back to a userinfo call — the point of OIDC is the signed assertion.
    /// </summary>
    [Fact]
    public async Task ExchangeCodeForTokenAsync_FailsWhenNoIdTokenComesBack()
    {
        _google.IncludeIdToken = false;

        await Assert.ThrowsAsync<IdTokenValidationException>(
            () => _google.CreateClient().ExchangeCodeForTokenAsync(
                "the-code", "the-verifier", Nonce, CancellationToken.None));
    }

    /// <summary>
    /// <c>expires_in</c> is relative to when the answer arrived, the same as GitHub's — the value has
    /// to become an absolute instant here, once, and not at every later comparison.
    /// </summary>
    [Fact]
    public async Task ExchangeCodeForTokenAsync_ConvertsTheRelativeLifetimeToAnAbsoluteInstant()
    {
        _google.NonceToEcho = Nonce;
        _google.ExpiresInToIssue = 3599;

        var before = DateTimeOffset.UtcNow;
        var result = await _google.CreateClient()
            .ExchangeCodeForTokenAsync("the-code", "the-verifier", Nonce, CancellationToken.None);

        Assert.NotNull(result.Tokens.ExpiresAtUtc);
        Assert.InRange(
            result.Tokens.ExpiresAtUtc.Value,
            before.AddSeconds(3599),
            DateTimeOffset.UtcNow.AddSeconds(3599));

        // Google never advertises a refresh-token lifetime. Inventing one would put a date on the
        // connections card that Google never promised.
        Assert.Null(result.Tokens.RefreshTokenExpiresAtUtc);
    }

    [Fact]
    public async Task RefreshAccessTokenAsync_SendsTheRefreshGrantWithoutCodeOrPkce()
    {
        await _google.CreateClient().RefreshAccessTokenAsync("1//stored", CancellationToken.None);

        var request = _google.LastTokenRequest;
        Assert.Equal("refresh_token", request.Form("grant_type"));
        Assert.Equal("1//stored", request.Form("refresh_token"));
        Assert.Null(request.Form("code"));
        Assert.Null(request.Form("code_verifier"));
        Assert.Null(request.Form("redirect_uri"));
    }

    /// <summary>
    /// Google does not rotate. The absence of <c>refresh_token</c> in the response is the normal case
    /// and must surface as null — "keep the one you have" — rather than as an error.
    /// </summary>
    [Fact]
    public async Task RefreshAccessTokenAsync_ReportsNoRotatedRefreshToken()
    {
        var result = await _google.CreateClient().RefreshAccessTokenAsync("1//stored", CancellationToken.None);

        Assert.Equal("ya29.refreshed", result.AccessToken);
        Assert.Null(result.RefreshToken);
    }

    /// <summary>
    /// The convention difference that would silently break a client copied from the GitHub one:
    /// Google reports a dead grant as HTTP <c>400</c>. Read status-first, and this is an
    /// <c>HttpRequestException</c> — a transport blip, retried forever, never latching the link.
    /// </summary>
    [Theory]
    [InlineData("invalid_grant")]
    [InlineData("unauthorized_client")]
    public async Task RefreshAccessTokenAsync_TreatsAFourHundredWithADeadGrantErrorAsRejection(string error)
    {
        _google.TokenError = error;

        var ex = await Assert.ThrowsAsync<RefreshTokenRejectedException>(
            () => _google.CreateClient().RefreshAccessTokenAsync("1//stored", CancellationToken.None));

        Assert.Equal(error, ex.Error);
    }

    /// <summary>
    /// And the other half: <c>invalid_client</c> means <em>this app's</em> credentials are wrong, which
    /// no amount of user re-consent fixes. Latching the link on it would tell the user to reconnect,
    /// over and over, to fix a configuration mistake they cannot see.
    /// </summary>
    [Fact]
    public async Task RefreshAccessTokenAsync_DoesNotTreatABadClientSecretAsADeadGrant()
    {
        _google.TokenError = "invalid_client";
        _google.TokenErrorStatus = HttpStatusCode.Unauthorized;

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => _google.CreateClient().RefreshAccessTokenAsync("1//stored", CancellationToken.None));
    }

    /// <summary>
    /// An outage answers with an HTML error page, not an OAuth error. It has to arrive as a transport
    /// failure so <c>ProviderTokenService</c> leaves the link alone — "Google was down for a minute"
    /// is not "your grant is dead", and only one of the two is fixed by re-consenting.
    /// </summary>
    [Fact]
    public async Task RefreshAccessTokenAsync_SurfacesAnUnexplainedServerErrorAsATransportFailure()
    {
        _google.TokenEndpointTransportFailure = HttpStatusCode.ServiceUnavailable;

        var ex = await Assert.ThrowsAsync<HttpRequestException>(
            () => _google.CreateClient().RefreshAccessTokenAsync("1//stored", CancellationToken.None));

        Assert.Equal(HttpStatusCode.ServiceUnavailable, ex.StatusCode);
    }

    /// <summary>
    /// The connection check's endpoint. The 401 has to escape as an <c>HttpRequestException</c>
    /// carrying its status code, because that is precisely what the reactive refresh trigger reads.
    /// </summary>
    [Fact]
    public async Task GetAuthenticatedUserAsync_SurfacesARejectedTokenAsAFourOhOne()
    {
        _google.AcceptedAccessToken = "ya29.the-good-one";

        var ex = await Assert.ThrowsAsync<HttpRequestException>(
            () => _google.CreateClient().GetAuthenticatedUserAsync("ya29.a-revoked-one", CancellationToken.None));

        Assert.Equal(HttpStatusCode.Unauthorized, ex.StatusCode);
    }

    [Fact]
    public async Task GetAuthenticatedUserAsync_KeysTheAccountOnSubRatherThanEmail()
    {
        _google.AcceptedAccessToken = "ya29.the-good-one";

        var account = await _google.CreateClient()
            .GetAuthenticatedUserAsync("ya29.the-good-one", CancellationToken.None);

        Assert.Equal(FakeGoogle.Subject, account.Id);
        Assert.Equal(FakeGoogle.Email, account.DisplayName);
    }

    /// <summary>
    /// A plain link: base scopes only, no widget's permission added. M5's incremental case is covered
    /// in <c>ProviderScopeTests</c>.
    /// </summary>
    private Task<string> BuildAuthorizationUrlAsync(OptionalScope? additionalScope = null) =>
        _google.CreateClient()
            .BuildAuthorizationUrlAsync(State, Challenge, Nonce, additionalScope, CancellationToken.None);
}
