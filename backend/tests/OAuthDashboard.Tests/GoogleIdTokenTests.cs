using OAuthDashboard.Infrastructure.Auth;

namespace OAuthDashboard.Tests;

/// <summary>
/// M4's central claim: an <c>id_token</c> is believed only after every check passes, and each check
/// is load-bearing on its own.
/// </summary>
/// <remarks>
/// These are written as "break exactly one thing and watch it fail closed", because that is the only
/// way to know a check is running. A validator with the signature verification quietly disabled
/// passes every happy-path test ever written against it — the token still parses, the claims are
/// still there, the flow still completes. Only the negative cases can tell the difference.
/// <para>
/// The fake provider signs with a real 2048-bit RSA key it publishes in a real JWKS, so "the
/// signature doesn't verify" means the arithmetic actually failed rather than a stub deciding to
/// return false.
/// </para>
/// </remarks>
public class GoogleIdTokenTests : IDisposable
{
    private const string Nonce = "the-nonce-from-the-authorize-request";

    private readonly FakeGoogle _google = new();

    public void Dispose() => _google.Dispose();

    /// <summary>The baseline every negative case below is one mutation away from.</summary>
    [Fact]
    public async Task ValidateAsync_AcceptsAWellFormedTokenAndReturnsItsClaims()
    {
        var identity = await ValidateAsync(_google.CreateIdToken(nonce: Nonce), Nonce);

        Assert.Equal(FakeGoogle.Subject, identity.Subject);
        Assert.Equal(FakeGoogle.Email, identity.Email);
        Assert.True(identity.EmailVerified);
        Assert.Equal("Test Person", identity.Name);
        Assert.True(identity.ExpiresAtUtc > DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// The check the whole exercise rests on. This token's payload is byte-for-byte the payload of a
    /// valid one — it just wasn't signed by the key Google publishes, which is exactly the position
    /// an attacker is in.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_RejectsATokenSignedByAKeyTheProviderDoesNotPublish()
    {
        var forged = _google.CreateIdToken(nonce: Nonce, signWithUnpublishedKey: true);

        await Assert.ThrowsAsync<IdTokenValidationException>(() => ValidateAsync(forged, Nonce));
    }

    /// <summary>
    /// Tampering after signing. Flipping a character in the payload leaves a syntactically perfect
    /// JWT whose claims read fine to anything that doesn't verify.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_RejectsATokenWhosePayloadWasEditedAfterSigning()
    {
        var parts = _google.CreateIdToken(nonce: Nonce).Split('.');
        var tampered = string.Join('.', parts[0], MutateOneCharacter(parts[1]), parts[2]);

        await Assert.ThrowsAsync<IdTokenValidationException>(() => ValidateAsync(tampered, Nonce));
    }

    /// <summary>
    /// <c>alg: none</c>. A JWT that declares it needs no signature, and carries none. A verifier that
    /// takes the algorithm from the header it is verifying accepts this without a key at all.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_RejectsAnUnsignedToken()
    {
        await Assert.ThrowsAsync<IdTokenValidationException>(
            () => ValidateAsync(_google.CreateUnsignedIdToken(Nonce), Nonce));
    }

    /// <summary>
    /// RS256→HS256 confusion: the attacker signs with HMAC using the provider's <em>public</em> key —
    /// which is published, by design — as the shared secret. A verifier that trusts the header looks
    /// up "the key for kid X", finds the RSA public key, and happily uses it as an HMAC secret. This
    /// is a valid HS256 token; the only thing that rejects it is refusing to let the header choose.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_RejectsATokenThatSwapsTheAlgorithmForHmac()
    {
        await Assert.ThrowsAsync<IdTokenValidationException>(
            () => ValidateAsync(_google.CreateHmacSignedIdToken(Nonce), Nonce));
    }

    /// <summary>
    /// Correctly signed, by the right key, for the right audience — by the wrong issuer. Without this
    /// check, <c>sub</c> values from different providers land in the same namespace, and any
    /// identity provider becomes able to assert any user.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_RejectsATokenFromADifferentIssuer()
    {
        var wrongIssuer = _google.CreateIdToken(nonce: Nonce, issuer: "https://accounts.evil.example");

        await Assert.ThrowsAsync<IdTokenValidationException>(() => ValidateAsync(wrongIssuer, Nonce));
    }

    /// <summary>
    /// The subtle one. This token is genuinely Google's, genuinely signed, genuinely about this user —
    /// it was just issued to a <em>different application</em>. Any developer with a Google client id
    /// can obtain one. Skipping the audience check turns "a user logged into some other Google app"
    /// into "a user linked here".
    /// </summary>
    [Fact]
    public async Task ValidateAsync_RejectsATokenMintedForADifferentApplication()
    {
        var wrongAudience = _google.CreateIdToken(nonce: Nonce, audience: "999999.apps.googleusercontent.com");

        await Assert.ThrowsAsync<IdTokenValidationException>(() => ValidateAsync(wrongAudience, Nonce));
    }

    /// <summary>
    /// A short-lived assertion honoured after it expires is not short-lived. Well outside the 30
    /// second skew, so this is testing the check rather than the tolerance.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_RejectsAnExpiredToken()
    {
        var expired = _google.CreateIdToken(
            nonce: Nonce,
            issuedAt: DateTime.UtcNow.AddHours(-2),
            expires: DateTime.UtcNow.AddHours(-1));

        await Assert.ThrowsAsync<IdTokenValidationException>(() => ValidateAsync(expired, Nonce));
    }

    /// <summary>
    /// A perfectly valid Google token for this application and this user, replayed into a
    /// <em>different</em> authorization attempt. Everything except the nonce checks out, which is
    /// precisely the situation the nonce exists for.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_RejectsATokenMintedForADifferentAuthorizationRequest()
    {
        var otherRequest = _google.CreateIdToken(nonce: "a-nonce-from-some-other-flow");

        var ex = await Assert.ThrowsAsync<IdTokenValidationException>(() => ValidateAsync(otherRequest, Nonce));
        Assert.Contains("nonce", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// And a token with no nonce at all, when one was requested — the degenerate version of the same
    /// attack, and the one that slips past a check written as "if a nonce is present, compare it".
    /// </summary>
    [Fact]
    public async Task ValidateAsync_RejectsATokenWithNoNonceWhenOneWasRequested()
    {
        await Assert.ThrowsAsync<IdTokenValidationException>(() => ValidateAsync(_google.CreateIdToken(), Nonce));
    }

    /// <summary>
    /// The refresh grant answers with an id_token that has no nonce, because no authorization request
    /// happened. Passing null has to mean "there is nothing to bind to here" rather than being an
    /// accidental way to skip the check — which is why the parameter has no default value.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_AcceptsATokenWithoutANonceOnTheRefreshPath()
    {
        var identity = await ValidateAsync(_google.CreateIdToken(), expectedNonce: null);

        Assert.Equal(FakeGoogle.Subject, identity.Subject);
    }

    /// <summary>
    /// A routine key rotation: Google starts signing with a kid this app's cached key set has never
    /// seen. The right response is one refetch, not a failure — otherwise every rotation is an
    /// outage until the cache happens to expire.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_RefetchesTheKeySetWhenTheProviderRotatesItsSigningKey()
    {
        // Warm the cache against the original key.
        var validator = CreateValidator(NoRefetchFloor);
        await ValidateAsync(_google.CreateIdToken(nonce: Nonce), Nonce, validator);
        var fetchesBeforeRotation = _google.JwksFetches;

        // New key material, not just a new label — otherwise the stale cache could still verify and
        // the test would pass whether the refetch happened or not.
        _google.RotateSigningKey("test-key-2-after-rotation");
        var identity = await ValidateAsync(_google.CreateIdToken(nonce: Nonce), Nonce, validator);

        Assert.Equal(FakeGoogle.Subject, identity.Subject);
        Assert.Equal(fetchesBeforeRotation + 1, _google.JwksFetches);
    }

    /// <summary>
    /// The other side of that refetch, and the reason it needs a floor. "Unknown kid" is a fetch an
    /// unauthenticated caller can ask this app to perform, so a stream of junk tokens must not become
    /// a stream of outbound requests to Google.
    /// </summary>
    /// <remarks>
    /// These tokens are signed with a key the provider never published as well as carrying an unknown
    /// kid, because the kid alone is not what rejects them: the header is a hint about which key to
    /// try, not a claim to be enforced, and the library falls back to trying every published key when
    /// the hint doesn't match. What rejects a forgery is the signature failing against all of them —
    /// which is the right behaviour, and worth knowing rather than assuming the kid is a gate.
    /// </remarks>
    [Fact]
    public async Task ValidateAsync_DoesNotRefetchTheKeySetOnceForEveryTokenWithAnUnknownKeyId()
    {
        var validator = CreateValidator();

        for (var attempt = 0; attempt < 5; attempt++)
        {
            var junk = _google.CreateIdToken(
                nonce: Nonce, keyId: $"kid-that-does-not-exist-{attempt}", signWithUnpublishedKey: true);

            await Assert.ThrowsAsync<IdTokenValidationException>(() => ValidateAsync(junk, Nonce, validator));
        }

        // One fetch, to fill the cache. Every subsequent "unknown kid, please refetch" lands inside
        // the five-minute floor and is answered from memory — five forged tokens, zero extra
        // requests to Google. The floor is the whole reason this is one and not six.
        Assert.Equal(1, _google.JwksFetches);
    }

    /// <summary>
    /// The endpoints and the expected issuer come from the discovery document, and it is fetched
    /// once rather than per token — a JWKS lookup on every validation would be a round trip to Google
    /// on every request this app serves.
    /// </summary>
    [Fact]
    public async Task ValidateAsync_ReadsProviderMetadataOnceAndReusesIt()
    {
        var validator = CreateValidator();

        for (var attempt = 0; attempt < 3; attempt++)
        {
            await ValidateAsync(_google.CreateIdToken(nonce: Nonce), Nonce, validator);
        }

        Assert.Equal(1, _google.DiscoveryFetches);
        Assert.Equal(1, _google.JwksFetches);
    }

    // --- helpers -----------------------------------------------------------------------------------

    /// <summary>
    /// The rotation test needs a forced refetch to actually happen immediately. Production keeps the
    /// five-minute floor; a rotation within five minutes of a cache fill is a case Google's
    /// publish-before-you-sign overlap already covers.
    /// </summary>
    private static readonly OpenIdConnectCacheIntervals NoRefetchFloor =
        OpenIdConnectCacheIntervals.Default with { MinimumRefetch = TimeSpan.Zero };

    private IdTokenValidator CreateValidator(OpenIdConnectCacheIntervals? intervals = null) =>
        _google.CreateIdTokenValidator(intervals);

    private Task<ValidatedIdToken> ValidateAsync(
        string idToken, string? expectedNonce, IdTokenValidator? validator = null) =>
        (validator ?? CreateValidator()).ValidateAsync(
            idToken, FakeGoogle.Authority, FakeGoogle.ClientId, expectedNonce, CancellationToken.None);

    /// <summary>Changes one base64url character, so the payload decodes to something else.</summary>
    private static string MutateOneCharacter(string segment)
    {
        var characters = segment.ToCharArray();
        var index = characters.Length / 2;
        characters[index] = characters[index] == 'A' ? 'B' : 'A';

        return new string(characters);
    }
}
