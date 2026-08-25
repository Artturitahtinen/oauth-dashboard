using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace OAuthDashboard.Infrastructure.Auth;

/// <summary>
/// The claims of an <c>id_token</c> that has passed every check — signature, issuer, audience,
/// lifetime and nonce.
/// </summary>
/// <remarks>
/// A distinct type from "the JWT that arrived", for the same reason
/// <c>StoredProviderTokens</c> is distinct from <c>LinkedAccountSummary</c>: the only way to obtain
/// one is to go through <see cref="IdTokenValidator"/>, so there is no call site that can read a
/// claim out of an unverified token by accident. A JWT is trivially readable without its signature —
/// that is precisely the mistake this type exists to make unavailable.
/// </remarks>
/// <param name="Subject">
/// The <c>sub</c> claim: the provider's stable, never-reused identifier for this account. This — not
/// the email address — is what the link is keyed on. Google is explicit that an email can be
/// reassigned and that a user can change theirs, so treating email as an identity key eventually
/// hands one person's dashboard to another.
/// </param>
/// <param name="EmailVerified">
/// Whether Google claims to have verified the address. Display-only here, but the reason to carry it
/// at all is that an <em>unverified</em> email from any provider is a self-asserted string, and
/// matching accounts on one is the classic account-takeover path.
/// </param>
public record ValidatedIdToken(
    string Subject,
    string? Email,
    bool EmailVerified,
    string? Name,
    DateTimeOffset IssuedAtUtc,
    DateTimeOffset ExpiresAtUtc);

/// <summary>
/// An <c>id_token</c> failed validation. The link must not be established on the strength of it.
/// </summary>
public class IdTokenValidationException(string message, Exception? inner = null)
    : Exception(message, inner);

/// <summary>
/// Validates an OIDC <c>id_token</c> against the issuing provider's published signing keys.
/// </summary>
/// <remarks>
/// This is what separates M4 from the previous milestones. An OAuth2 access token is opaque: it says
/// nothing, it is only spent. An <c>id_token</c> is an <em>assertion about who the user is</em>,
/// which means it is only worth as much as the checks performed on it — and a JWT's payload is
/// base64, not ciphertext, so an unchecked one is just a claim an attacker wrote down.
/// <para>
/// <b>Every check here has a specific attack behind it.</b>
/// <list type="bullet">
/// <item><b>Signature, against the provider's JWKS.</b> Without it the token is a suggestion.</item>
/// <item><b>Algorithm pinned to RS256.</b> The two classic JWT breaks are <c>alg: none</c> (a token
/// with no signature at all, accepted by a library that trusts the header) and RS256→HS256
/// confusion (the attacker signs with HMAC using the provider's <em>public</em> key as the shared
/// secret, and a library that also trusts the header verifies it happily). Both are attacks on the
/// header telling the verifier how to verify, and both are closed by deciding the algorithm here
/// instead of reading it from the token.</item>
/// <item><b>Issuer.</b> Otherwise any provider's correctly-signed token for its own user would pass,
/// and the <c>sub</c> namespace is per-issuer.</item>
/// <item><b>Audience.</b> An <c>id_token</c> Google minted for a <em>different</em> application is
/// perfectly valid and perfectly signed; it just isn't for us. Skipping this check is how a token
/// obtained by any other Google client becomes a login here.</item>
/// <item><b>Lifetime.</b> With a deliberately small skew — the whole value of a short-lived
/// assertion evaporates if it is honoured an hour late.</item>
/// <item><b>Nonce.</b> See <see cref="ValidateAsync"/>.</item>
/// </list>
/// </para>
/// <para>
/// <b>The one place this project does not hand-roll, on purpose.</b> Everything else in it is
/// written against raw <c>HttpClient</c> so the mechanics are visible. RSA-PKCS1 signature
/// verification is the exception: the failure mode of a subtly wrong implementation is "accepts
/// forged tokens", it is invisible in testing, and there is nothing left to learn from re-deriving
/// it. The discovery document and the key set are still fetched by hand (see
/// <see cref="OpenIdConnectDiscoveryCache"/>) — it's the crypto that is delegated, not the protocol.
/// </para>
/// </remarks>
public class IdTokenValidator(OpenIdConnectDiscoveryCache discovery, ILogger<IdTokenValidator> logger)
{
    /// <summary>
    /// Tolerance on <c>exp</c>/<c>nbf</c>. Deliberately far below the library default of five
    /// minutes: this app and Google are both synchronized to real clocks, and every second of skew
    /// is a second a revoked-and-expired assertion stays usable.
    /// </summary>
    private static readonly TimeSpan ClockSkew = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Validates <paramref name="idToken"/> and returns its claims.
    /// </summary>
    /// <param name="expectedNonce">
    /// The nonce minted for the authorization request this token answers, or <c>null</c> on the
    /// refresh grant — where no authorization request happened, so there is no nonce to bind to and
    /// Google does not send one.
    /// <para>
    /// There is no default value on this parameter on purpose. A nonce check that can be skipped by
    /// forgetting an argument is a nonce check that will eventually be skipped.
    /// </para>
    /// </param>
    /// <exception cref="IdTokenValidationException">Any check failed.</exception>
    public async Task<ValidatedIdToken> ValidateAsync(
        string idToken,
        string authority,
        string audience,
        string? expectedNonce,
        CancellationToken ct)
    {
        var document = await discovery.GetDocumentAsync(authority, ct);
        var handler = new JsonWebTokenHandler();

        JsonWebToken unverified;
        try
        {
            // Parsing before verifying is safe only for one purpose: choosing which public key to
            // verify *with*. Nothing read here is trusted, and nothing read here escapes this method.
            unverified = handler.ReadJsonWebToken(idToken);
        }
        catch (Exception ex)
        {
            throw new IdTokenValidationException("The id_token could not be parsed as a JWT.", ex);
        }

        var keys = await discovery.GetSigningKeysAsync(authority, forceRefresh: false, ct);

        // A kid the cached set doesn't know is what a routine key rotation looks like from here —
        // Google publishes the new key before it starts signing with it, but a cache older than the
        // overlap still misses. Refetch once; the rate limit inside the cache stops this from being
        // a lever an attacker can pull.
        if (!string.IsNullOrEmpty(unverified.Kid) && keys.Keys.All(key => key.Kid != unverified.Kid))
        {
            logger.LogInformation(
                "The id_token was signed with an unknown key id ({Kid}); refetching {Authority}'s key set.",
                unverified.Kid, authority);

            keys = await discovery.GetSigningKeysAsync(authority, forceRefresh: true, ct);
        }

        var parameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = document.Issuer,

            ValidateAudience = true,
            ValidAudience = audience,

            ValidateLifetime = true,
            RequireExpirationTime = true,
            ClockSkew = ClockSkew,

            ValidateIssuerSigningKey = true,
            RequireSignedTokens = true,
            IssuerSigningKeys = keys.GetSigningKeys(),

            // The header does not get to choose. See the class remarks: this single line is what
            // closes `alg: none` and RS256→HS256 confusion.
            ValidAlgorithms = [SecurityAlgorithms.RsaSha256],
        };

        var result = await handler.ValidateTokenAsync(idToken, parameters);

        if (!result.IsValid)
        {
            // The library's message names which check failed, which is exactly what makes a
            // deliberately-broken one worth watching fail. It goes to the log, not to the browser.
            logger.LogWarning(
                result.Exception,
                "An id_token from {Authority} failed validation.", authority);

            throw new IdTokenValidationException(
                $"The id_token from {authority} failed validation.", result.Exception);
        }

        var token = (JsonWebToken)result.SecurityToken;

        VerifyNonce(token, expectedNonce);

        var subject = token.Subject;
        if (string.IsNullOrEmpty(subject))
        {
            // sub is mandatory in OIDC Core §2. A signed token without one is well-formed and
            // useless: there is nothing to key the link on.
            throw new IdTokenValidationException("The id_token carried no sub claim.");
        }

        var email = Claim(token, "email");

        logger.LogInformation(
            "Validated an id_token from {Authority} (sub: {Subject}, email_verified: {EmailVerified}, " +
            "nonce checked: {NonceChecked}).",
            authority, subject, Flag(token, "email_verified"), expectedNonce is not null);

        return new ValidatedIdToken(
            Subject: subject,
            Email: email,
            EmailVerified: Flag(token, "email_verified"),
            Name: Claim(token, "name"),
            IssuedAtUtc: token.IssuedAt,
            ExpiresAtUtc: token.ValidTo);
    }

    /// <summary>
    /// Binds the token to the authorization request that asked for it.
    /// </summary>
    /// <remarks>
    /// The nonce travels out in the authorize URL and comes back inside the <em>signed</em> token, so
    /// it proves this assertion was minted for this request rather than replayed from another one.
    /// <para>
    /// Worth being honest about how much it adds <em>here</em>: in the authorization code flow the
    /// token arrives over a server-to-server POST, bound to a single-use code that is itself bound to
    /// a PKCE verifier only this process holds, so an injected id_token has few ways in already. The
    /// nonce is what carries that guarantee in the implicit and hybrid flows, where the token lands
    /// in the browser and none of the above applies. It is implemented for the same reason PKCE is
    /// (see <c>Pkce</c>): the argument for skipping it depends on properties of the current
    /// deployment, and those stop holding quietly.
    /// </para>
    /// </remarks>
    private static void VerifyNonce(JsonWebToken token, string? expectedNonce)
    {
        if (expectedNonce is null)
        {
            return;
        }

        if (!token.TryGetPayloadValue<string>("nonce", out var nonce) || string.IsNullOrEmpty(nonce))
        {
            throw new IdTokenValidationException("The id_token carried no nonce, but one was requested.");
        }

        if (!string.Equals(nonce, expectedNonce, StringComparison.Ordinal))
        {
            throw new IdTokenValidationException("The id_token's nonce did not match the authorization request.");
        }
    }

    private static string? Claim(JsonWebToken token, string name) =>
        token.TryGetPayloadValue<string>(name, out var value) ? value : null;

    private static bool Flag(JsonWebToken token, string name) =>
        token.TryGetPayloadValue<bool>(name, out var value) && value;
}
