using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using OAuthDashboard.Infrastructure.Auth;

namespace OAuthDashboard.Tests;

/// <summary>
/// Stands in for Google at the transport layer: the discovery document, the JWKS, the token endpoint
/// and userinfo, all served by one <see cref="HttpMessageHandler"/> over a real RSA key pair.
/// </summary>
/// <remarks>
/// Substituting the handler rather than faking <c>GoogleOAuthClient</c> is the same choice M3 made
/// and for the same reason, with more to gain: the details most likely to be wrong here are the wire
/// details — that Google reports a dead grant as HTTP <c>400</c> and not <c>200</c>, that it omits
/// <c>refresh_token</c> on a refresh, that the endpoints come out of the discovery document — and a
/// hand-written fake of the client would assume every one of them correct.
/// <para>
/// The key pair is real, so a token this fake signs is genuinely verifiable and a token it tampers
/// with genuinely isn't. Tests that assert "a forged signature is rejected" are worthless against a
/// stub that only pretends to sign.
/// </para>
/// </remarks>
internal sealed class FakeGoogle : IDisposable
{
    public const string Authority = "https://accounts.google.com";
    public const string ClientId = "123456789.apps.googleusercontent.com";
    public const string ClientSecret = "test-google-client-secret";
    public const string RedirectUri = "https://localhost:7236/api/auth/google/callback";

    public const string AuthorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
    public const string TokenEndpoint = "https://oauth2.googleapis.com/token";
    public const string UserInfoEndpoint = "https://openidconnect.googleapis.com/v1/userinfo";
    public const string JwksUri = "https://www.googleapis.com/oauth2/v3/certs";
    public const string RevocationEndpoint = "https://oauth2.googleapis.com/revoke";

    public const string Subject = "104729384756102938475";
    public const string Email = "tester@example.com";

    private RSA _signingKey = RSA.Create(2048);

    /// <summary>A second key the provider never publishes — used to forge a well-formed signature.</summary>
    private readonly RSA _foreignKey = RSA.Create(2048);

    private readonly ConcurrentQueue<StubGoogleRequest> _requests = new();

    private int _discoveryFetches;
    private int _jwksFetches;
    private int _tokenCalls;
    private int _userInfoCalls;

    /// <summary>The kid the fake currently publishes and signs with. Change it to simulate a rotation.</summary>
    public string PublishedKeyId { get; set; } = "test-key-1";

    /// <summary>The issuer the discovery document declares. Change it to break OIDC Discovery §4.3.</summary>
    public string IssuerToPublish { get; set; } = Authority;

    /// <summary>Set to publish a discovery document with no token_endpoint.</summary>
    public bool OmitTokenEndpoint { get; set; }

    /// <summary>Set to publish an empty key set — a provider that signs with keys it never announced.</summary>
    public bool PublishNoKeys { get; set; }

    /// <summary>What userinfo will accept as a bearer token. Anything else gets a 401.</summary>
    public string AcceptedAccessToken { get; set; } = "ya29.initial";

    public string AccessTokenToIssue { get; set; } = "ya29.refreshed";

    /// <summary>
    /// Null models Google's behaviour on the refresh grant, where no <c>refresh_token</c> comes back
    /// at all because Google does not rotate it.
    /// </summary>
    public string? RefreshTokenToIssue { get; set; }

    public int? ExpiresInToIssue { get; set; } = 3599;

    /// <summary>Set to make the token endpoint answer with an OAuth error — as HTTP 400, like Google.</summary>
    public string? TokenError { get; set; }

    public HttpStatusCode TokenErrorStatus { get; set; } = HttpStatusCode.BadRequest;

    /// <summary>
    /// Set to answer the token endpoint with a failure that carries no OAuth error at all — a load
    /// balancer's HTML 5xx page, which is what an outage actually looks like from a client.
    /// </summary>
    public HttpStatusCode? TokenEndpointTransportFailure { get; set; }

    /// <summary>Overrides the id_token the token endpoint returns. Null means "mint a valid one".</summary>
    public string? IdTokenToIssue { get; set; }

    /// <summary>When false the token response carries no id_token at all.</summary>
    public bool IncludeIdToken { get; set; } = true;

    /// <summary>The nonce the minted id_token will echo. Set by the test to match — or not to.</summary>
    public string? NonceToEcho { get; set; }

    public int DiscoveryFetches => Volatile.Read(ref _discoveryFetches);

    public int JwksFetches => Volatile.Read(ref _jwksFetches);

    public int TokenCalls => Volatile.Read(ref _tokenCalls);

    public int UserInfoCalls => Volatile.Read(ref _userInfoCalls);

    public IReadOnlyCollection<StubGoogleRequest> Requests => _requests;

    public StubGoogleRequest LastTokenRequest => _requests.Last(r => r.Url.StartsWith(TokenEndpoint, StringComparison.Ordinal));

    // --- the fake provider -------------------------------------------------------------------------

    public HttpResponseMessage Respond(StubGoogleRequest request)
    {
        _requests.Enqueue(request);

        if (request.Url.Contains("/.well-known/openid-configuration", StringComparison.Ordinal))
        {
            Interlocked.Increment(ref _discoveryFetches);
            return Json(HttpStatusCode.OK, DiscoveryJson());
        }

        if (request.Url.StartsWith(JwksUri, StringComparison.Ordinal))
        {
            Interlocked.Increment(ref _jwksFetches);
            return Json(HttpStatusCode.OK, JwksJson());
        }

        if (request.Url.StartsWith(TokenEndpoint, StringComparison.Ordinal))
        {
            Interlocked.Increment(ref _tokenCalls);
            return TokenResponse();
        }

        if (request.Url.StartsWith(UserInfoEndpoint, StringComparison.Ordinal))
        {
            Interlocked.Increment(ref _userInfoCalls);

            return request.AccessToken == AcceptedAccessToken
                ? Json(HttpStatusCode.OK,
                    $$"""{"sub":"{{Subject}}","email":"{{Email}}","email_verified":true,"name":"Test Person"}""")
                : Json(HttpStatusCode.Unauthorized, """{"error":"invalid_token"}""");
        }

        return Json(HttpStatusCode.NotFound, """{"error":"not_found"}""");
    }

    private HttpResponseMessage TokenResponse()
    {
        if (TokenEndpointTransportFailure is { } transportStatus)
        {
            return new HttpResponseMessage(transportStatus)
            {
                Content = new StringContent(
                    "<html><head><title>Error</title></head><body>Service Unavailable</body></html>",
                    Encoding.UTF8,
                    "text/html"),
            };
        }

        if (TokenError is not null)
        {
            // The detail that separates Google from GitHub: a rejected grant is a 4xx, not a 200.
            return Json(
                TokenErrorStatus,
                $$"""{"error":"{{TokenError}}","error_description":"simulated {{TokenError}}"}""");
        }

        AcceptedAccessToken = AccessTokenToIssue;

        var fields = new List<string>
        {
            $"\"access_token\":\"{AccessTokenToIssue}\"",
            "\"scope\":\"openid email profile\"",
            "\"token_type\":\"Bearer\"",
        };

        if (ExpiresInToIssue is not null) fields.Add($"\"expires_in\":{ExpiresInToIssue}");
        if (RefreshTokenToIssue is not null) fields.Add($"\"refresh_token\":\"{RefreshTokenToIssue}\"");
        if (IncludeIdToken) fields.Add($"\"id_token\":\"{IdTokenToIssue ?? CreateIdToken(nonce: NonceToEcho)}\"");

        return Json(HttpStatusCode.OK, "{" + string.Join(',', fields) + "}");
    }

    private string DiscoveryJson()
    {
        var tokenEndpoint = OmitTokenEndpoint ? "" : $"\"token_endpoint\": \"{TokenEndpoint}\",";

        return $$"""
            {
              "issuer": "{{IssuerToPublish}}",
              "authorization_endpoint": "{{AuthorizationEndpoint}}",
              {{tokenEndpoint}}
              "userinfo_endpoint": "{{UserInfoEndpoint}}",
              "jwks_uri": "{{JwksUri}}",
              "revocation_endpoint": "{{RevocationEndpoint}}",
              "response_types_supported": ["code", "token", "id_token"],
              "id_token_signing_alg_values_supported": ["RS256"]
            }
            """;
    }

    private string JwksJson()
    {
        if (PublishNoKeys)
        {
            return """{"keys":[]}""";
        }

        var parameters = _signingKey.ExportParameters(includePrivateParameters: false);

        return $$"""
            {"keys":[{
              "kty":"RSA","use":"sig","alg":"RS256",
              "kid":"{{PublishedKeyId}}",
              "n":"{{Base64UrlEncoder.Encode(parameters.Modulus)}}",
              "e":"{{Base64UrlEncoder.Encode(parameters.Exponent)}}"
            }]}
            """;
    }

    /// <summary>
    /// A real key rotation: new key material <em>and</em> a new kid. Relabelling the same key would
    /// leave a stale cache still able to verify, which is exactly the failure the refetch exists to
    /// prevent — so the test would pass without it.
    /// </summary>
    public void RotateSigningKey(string newKeyId)
    {
        _signingKey.Dispose();
        _signingKey = RSA.Create(2048);
        PublishedKeyId = newKeyId;
    }

    // --- id_token construction ---------------------------------------------------------------------

    /// <summary>
    /// Mints an id_token. Every parameter defaults to the value that <em>passes</em>, so a test names
    /// only the thing it is breaking.
    /// </summary>
    public string CreateIdToken(
        string? nonce = null,
        string? issuer = null,
        string? audience = null,
        string? subject = null,
        DateTime? expires = null,
        DateTime? issuedAt = null,
        string? keyId = null,
        bool signWithUnpublishedKey = false)
    {
        var now = DateTime.UtcNow;

        var claims = new Dictionary<string, object>
        {
            ["sub"] = subject ?? Subject,
            ["email"] = Email,
            ["email_verified"] = true,
            ["name"] = "Test Person",
            ["azp"] = ClientId,
        };

        if (nonce is not null)
        {
            claims["nonce"] = nonce;
        }

        var key = new RsaSecurityKey(signWithUnpublishedKey ? _foreignKey : _signingKey)
        {
            KeyId = keyId ?? PublishedKeyId,
        };

        return new JsonWebTokenHandler().CreateToken(new SecurityTokenDescriptor
        {
            Issuer = issuer ?? Authority,
            Audience = audience ?? ClientId,
            IssuedAt = issuedAt ?? now.AddSeconds(-5),
            NotBefore = issuedAt ?? now.AddSeconds(-5),
            Expires = expires ?? now.AddHours(1),
            Claims = claims,
            SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.RsaSha256),
        });
    }

    /// <summary>
    /// The <c>alg: none</c> token: a real header, a real payload, and an empty signature. A verifier
    /// that reads the algorithm out of the header it is verifying accepts this.
    /// </summary>
    public string CreateUnsignedIdToken(string? nonce = null)
    {
        var header = Base64UrlEncoder.Encode("""{"alg":"none","typ":"JWT","kid":"test-key-1"}""");
        var payload = Base64UrlEncoder.Encode(PayloadJson(nonce));

        return $"{header}.{payload}.";
    }

    /// <summary>
    /// The algorithm-confusion token: signed with HMAC-SHA256 using the provider's <em>public</em>
    /// key as the shared secret. Everything an attacker needs is published in the JWKS, so this is a
    /// valid HS256 token — and it is only rejected by refusing to let the header pick the algorithm.
    /// </summary>
    public string CreateHmacSignedIdToken(string? nonce = null)
    {
        var header = Base64UrlEncoder.Encode($$"""{"alg":"HS256","typ":"JWT","kid":"{{PublishedKeyId}}"}""");
        var payload = Base64UrlEncoder.Encode(PayloadJson(nonce));
        var signingInput = $"{header}.{payload}";

        var secret = _signingKey.ExportSubjectPublicKeyInfo();
        var signature = HMACSHA256.HashData(secret, Encoding.ASCII.GetBytes(signingInput));

        return $"{signingInput}.{Base64UrlEncoder.Encode(signature)}";
    }

    private static string PayloadJson(string? nonce)
    {
        var now = DateTimeOffset.UtcNow;
        var nonceField = nonce is null ? "" : $"\"nonce\":\"{nonce}\",";

        return $$"""
            {"iss":"{{Authority}}","aud":"{{ClientId}}","sub":"{{Subject}}",{{nonceField}}
             "email":"{{Email}}","email_verified":true,
             "iat":{{now.ToUnixTimeSeconds() - 5}},"exp":{{now.AddHours(1).ToUnixTimeSeconds()}}}
            """;
    }

    // --- wiring --------------------------------------------------------------------------------------

    private StubGoogleHandler? _handler;

    public StubGoogleHandler Handler => _handler ??= new StubGoogleHandler(Respond);

    public OpenIdConnectDiscoveryCache CreateDiscoveryCache(OpenIdConnectCacheIntervals? intervals = null) =>
        new(new StubHttpClientFactory(Handler), NullLogger<OpenIdConnectDiscoveryCache>.Instance, intervals);

    public IdTokenValidator CreateIdTokenValidator(OpenIdConnectCacheIntervals? intervals = null) =>
        new(CreateDiscoveryCache(intervals), NullLogger<IdTokenValidator>.Instance);

    public GoogleOAuthClient CreateClient(OpenIdConnectDiscoveryCache? discovery = null)
    {
        discovery ??= CreateDiscoveryCache();

        return new GoogleOAuthClient(
            new HttpClient(Handler, disposeHandler: false),
            Options.Create(new GoogleOAuthOptions
            {
                ClientId = ClientId,
                ClientSecret = ClientSecret,
                RedirectUri = RedirectUri,
                Authority = Authority,
            }),
            discovery,
            new IdTokenValidator(discovery, NullLogger<IdTokenValidator>.Instance),
            NullLogger<GoogleOAuthClient>.Instance);
    }

    private static HttpResponseMessage Json(HttpStatusCode status, string body) => new(status)
    {
        Content = new StringContent(body, Encoding.UTF8, "application/json"),
    };

    public void Dispose()
    {
        _signingKey.Dispose();
        _foreignKey.Dispose();
        _handler?.Dispose();
    }
}

/// <summary>Serves every Google endpoint from one handler, recording what was asked for.</summary>
internal sealed class StubGoogleHandler(Func<StubGoogleRequest, HttpResponseMessage> respond) : HttpMessageHandler
{
    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null
            ? string.Empty
            : await request.Content.ReadAsStringAsync(cancellationToken);

        return respond(new StubGoogleRequest(
            request.RequestUri!.ToString(), body, request.Headers.Authorization?.Parameter));
    }
}

internal record StubGoogleRequest(string Url, string Body, string? AccessToken)
{
    /// <summary>Reads one field back out of the form-urlencoded request body.</summary>
    public string? Form(string name) => Body
        .Split('&')
        .Select(pair => pair.Split('=', 2))
        .Where(parts => parts.Length == 2 && Uri.UnescapeDataString(parts[0]) == name)
        .Select(parts => Uri.UnescapeDataString(parts[1].Replace('+', ' ')))
        .FirstOrDefault();
}

/// <summary>
/// The discovery cache asks <see cref="IHttpClientFactory"/> for a client per fetch, exactly as it
/// does in the running app. <c>disposeHandler: false</c> matters: the cache wraps each client in a
/// <c>using</c>, and disposing the shared stub handler would break every later request.
/// </summary>
internal sealed class StubHttpClientFactory(HttpMessageHandler handler) : IHttpClientFactory
{
    public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
}
