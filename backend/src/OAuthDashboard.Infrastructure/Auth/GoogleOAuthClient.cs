using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OAuthDashboard.Core.Accounts;

namespace OAuthDashboard.Infrastructure.Auth;

/// <summary>
/// A successful Google authorization: the tokens to store, plus the identity Google
/// <em>asserted</em> in a signed <c>id_token</c>.
/// </summary>
/// <remarks>
/// The two halves are returned together because they are obtained together and neither is usable on
/// its own here. The <see cref="Identity"/> can only be constructed by
/// <see cref="IdTokenValidator"/>, so there is no way to reach this record with an unvalidated
/// assertion inside it.
/// </remarks>
public record GoogleAuthorizationResult(OAuthTokenResult Tokens, ValidatedIdToken Identity);

/// <summary>
/// Google's OAuth2 + OIDC endpoints, hand-rolled the same way <see cref="GitHubOAuthClient"/> is —
/// no <c>Microsoft.AspNetCore.Authentication.Google</c> handler anywhere.
/// </summary>
/// <remarks>
/// Google is the more instructive of the two providers, and the differences from GitHub are the
/// point of M4 rather than incidental:
/// <list type="bullet">
/// <item><b>Endpoints are discovered, not configured.</b> Every URL below comes out of the OIDC
/// discovery document (see <see cref="OpenIdConnectDiscoveryCache"/>), so nothing here hardcodes a
/// hostname that Google is free to move.</item>
/// <item><b>An identity comes back, not just an access token.</b> The <c>id_token</c> is a signed
/// statement about who authorized this, and it is validated before it is believed.</item>
/// <item><b>A refresh token has to be asked for.</b> <c>access_type=offline</c> is what makes Google
/// issue one at all, and <c>prompt=consent</c> is what makes it issue one <em>again</em> on a repeat
/// authorization — without it a user who has already consented gets an access token and no refresh
/// token, and the link quietly loses the ability to heal itself.</item>
/// <item><b>The refresh token does not rotate.</b> Where GitHub retires the old one on every use,
/// Google returns no <c>refresh_token</c> at all on a refresh and expects the stored one to keep
/// being used. Both are handled by the same rule in <c>LinkedAccountService</c>: write what the
/// provider sent, keep what it didn't.</item>
/// <item><b>OAuth failures arrive as HTTP 4xx.</b> GitHub answers a rejected grant with
/// <c>200 OK</c> and an error in the body; Google answers with <c>400</c> and an error in the body.
/// A client written against either convention alone misreads the other — GitHub's would treat a
/// Google failure as a transport blip, Google's would treat a GitHub failure as a token.</item>
/// </list>
/// </remarks>
public class GoogleOAuthClient(
    HttpClient httpClient,
    IOptions<GoogleOAuthOptions> options,
    OpenIdConnectDiscoveryCache discovery,
    IdTokenValidator idTokens,
    ILogger<GoogleOAuthClient> logger)
{
    private GoogleOAuthOptions Options => options.Value;

    /// <summary>
    /// Builds the URL the browser is redirected to. Async because the authorization endpoint is read
    /// from the discovery document rather than hardcoded.
    /// </summary>
    /// <param name="additionalScope">
    /// The one optional permission this authorization is adding, or null for a plain link. Resolved
    /// from <see cref="ProviderScopes"/> by key; a caller never supplies a scope string.
    /// </param>
    public async Task<string> BuildAuthorizationUrlAsync(
        string state, string codeChallenge, string nonce, OptionalScope? additionalScope, CancellationToken ct)
    {
        var document = await discovery.GetDocumentAsync(Options.Authority, ct);

        var query = string.Join('&', new[]
        {
            "response_type=code",
            $"client_id={Uri.EscapeDataString(Options.ClientId)}",
            $"redirect_uri={Uri.EscapeDataString(Options.RedirectUri)}",

            // Base scopes plus at most one widget's scope — never the union of everything the
            // dashboard might eventually want. See ProviderScopes.
            $"scope={Uri.EscapeDataString(ProviderScopes.RequestFor(OAuthProvider.Google, additionalScope))}",

            // Google's incremental-authorization switch, and the reason least privilege is workable
            // here at all. Without it, a token minted for this request carries *only* the scopes this
            // request named: adding the calendar widget would hand back a token that can read events
            // and can no longer read the profile the connection card is drawn from. The user's grant
            // keeps every scope they have ever approved either way — this is about what lands on the
            // new token, not about what they have consented to.
            "include_granted_scopes=true",

            $"state={Uri.EscapeDataString(state)}",

            // The nonce goes out in the clear here and comes back inside the signed id_token, which
            // is what binds the assertion to this request. Like the PKCE challenge beside it, the
            // value in the address bar is useless without the copy held server-side.
            $"nonce={Uri.EscapeDataString(nonce)}",

            $"code_challenge={Uri.EscapeDataString(codeChallenge)}",
            "code_challenge_method=S256",

            // Without this Google issues no refresh token and M3's entire flow is unreachable here.
            "access_type=offline",

            // And without this, it issues one only on the *first* consent. A user re-linking would
            // get an access token with no refresh token, the stored one would be kept (correctly),
            // and the failure would only show up whenever that older refresh token finally died.
            // Forcing the consent screen every time is the cost of a link that can always heal.
            "prompt=consent",
        });

        return $"{document.AuthorizationEndpoint}?{query}";
    }

    /// <summary>
    /// Exchanges the authorization code for tokens and validates the <c>id_token</c> that comes with
    /// them.
    /// </summary>
    /// <remarks>
    /// Validation happens here rather than in the caller so that there is no path by which an
    /// unverified assertion reaches a controller. The method either returns a
    /// <see cref="ValidatedIdToken"/> or throws.
    /// </remarks>
    /// <exception cref="IdTokenValidationException">The id_token was absent or did not check out.</exception>
    public async Task<GoogleAuthorizationResult> ExchangeCodeForTokenAsync(
        string code, string codeVerifier, string nonce, CancellationToken ct)
    {
        var payload = await PostToTokenEndpointAsync(new Dictionary<string, string>
        {
            ["client_id"] = Options.ClientId,
            ["client_secret"] = Options.ClientSecret,
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            // A binding check, not a redirect instruction — and it comes from configuration, never
            // from the request. Same rule as GitHub's.
            ["redirect_uri"] = Options.RedirectUri,
            ["code_verifier"] = codeVerifier,
        }, ct);

        if (payload.Error is not null)
        {
            throw new InvalidOperationException(
                $"Google token exchange failed: {payload.Error} ({payload.ErrorDescription})");
        }

        if (payload.IdToken is null)
        {
            // Only reachable if the openid scope went missing. Failing loudly beats linking an
            // account whose identity was never asserted.
            throw new IdTokenValidationException("Google's token response carried no id_token.");
        }

        var identity = await idTokens.ValidateAsync(
            payload.IdToken, Options.Authority, Options.ClientId, expectedNonce: nonce, ct);

        var tokens = LogAndConvert(payload, "exchange");

        if (tokens.RefreshToken is null)
        {
            // Not fatal — the access token works — but it means this link cannot survive its own
            // expiry, and the cause is almost always a missing access_type/prompt above.
            logger.LogWarning(
                "Google returned no refresh token for sub {Subject}; this link will need re-consent when the " +
                "access token expires.", identity.Subject);
        }

        return new GoogleAuthorizationResult(tokens, identity);
    }

    /// <summary>
    /// Spends the stored refresh token on a new access token.
    /// </summary>
    /// <remarks>
    /// Two differences from GitHub's refresh worth noticing. Google does not rotate the refresh
    /// token, so the response contains no <c>refresh_token</c> and the stored one stays in use —
    /// which makes the concurrency gate in <c>ProviderTokenService</c> less load-bearing here, though
    /// not wrong. And Google <em>does</em> return a fresh <c>id_token</c>, which is validated on the
    /// way through: no authorization request happened, so there is no nonce to bind to, and passing
    /// <c>null</c> for it is a statement rather than an omission.
    /// </remarks>
    /// <exception cref="RefreshTokenRejectedException">
    /// The grant is dead — revoked from the user's Google account page, expired (7 days while the
    /// consent screen is in Testing mode), or invalidated by a password change.
    /// </exception>
    public async Task<OAuthTokenResult> RefreshAccessTokenAsync(string refreshToken, CancellationToken ct)
    {
        var payload = await PostToTokenEndpointAsync(new Dictionary<string, string>
        {
            ["client_id"] = Options.ClientId,
            ["client_secret"] = Options.ClientSecret,
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
        }, ct);

        if (payload.Error is not null)
        {
            logger.LogWarning(
                "Google refused the refresh grant: {Error} ({ErrorDescription})",
                payload.Error, payload.ErrorDescription);

            throw IsDeadGrant(payload.Error)
                ? new RefreshTokenRejectedException(payload.Error, payload.ErrorDescription)
                : new InvalidOperationException($"Google token refresh failed: {payload.Error} ({payload.ErrorDescription})");
        }

        if (payload.IdToken is not null)
        {
            // Not needed to obtain the access token, and checked anyway: it is the cheapest available
            // confirmation that the grant still belongs to the account it was established for.
            var identity = await idTokens.ValidateAsync(
                payload.IdToken, Options.Authority, Options.ClientId, expectedNonce: null, ct);

            logger.LogDebug("The refreshed Google grant still asserts sub {Subject}.", identity.Subject);
        }

        return LogAndConvert(payload, "refresh");
    }

    /// <summary>
    /// Reads the linked account's identity by spending the access token on the userinfo endpoint.
    /// </summary>
    /// <remarks>
    /// Deliberately <em>not</em> what the link is established from — the <c>id_token</c> is, because
    /// a signed assertion beats an API response that merely arrived over TLS. This exists so
    /// <c>/api/connections/{provider}/check</c> has a real call to spend the stored token on: proving
    /// the ciphertext in SQLite still decrypts to a working credential requires actually using it.
    /// </remarks>
    public async Task<ProviderAccountInfo> GetAuthenticatedUserAsync(string accessToken, CancellationToken ct)
    {
        var user = await GetUserInfoJsonAsync(accessToken, ct);

        var id = user.TryGetProperty("sub", out var sub)
            ? sub.GetString() ?? throw new InvalidOperationException("Google userinfo returned a null sub.")
            : throw new InvalidOperationException("Google userinfo response was missing sub.");

        var displayName = user.TryGetProperty("email", out var email) ? email.GetString() : null;
        displayName ??= user.TryGetProperty("name", out var name) ? name.GetString() : null;

        return new ProviderAccountInfo(id, displayName ?? id);
    }

    /// <summary>
    /// The raw userinfo response, for the dashboard widget that renders more of it than a display
    /// name.
    /// </summary>
    /// <remarks>
    /// The endpoint comes from the discovery document like every other one. Note what userinfo is
    /// <em>not</em> used for: establishing the link. That comes from the signed <c>id_token</c>, and
    /// the difference matters — this response is trusted only as far as "it arrived over TLS from the
    /// discovered endpoint", which is enough to draw a card and not enough to key an account on.
    /// </remarks>
    public async Task<JsonElement> GetUserInfoJsonAsync(string accessToken, CancellationToken ct)
    {
        var document = await discovery.GetDocumentAsync(Options.Authority, ct);

        using var request = new HttpRequestMessage(HttpMethod.Get, document.UserInfoEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        using var response = await httpClient.SendAsync(request, ct);

        // Left to throw with its status code attached: a 401 here is exactly the signal
        // ProviderTokenService's reactive refresh trigger reads.
        response.EnsureSuccessStatusCode();

        return await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
    }

    // --- M5: revocation -------------------------------------------------------------------------

    /// <summary>
    /// Hands a token back to Google with instructions to destroy it, along with everything derived
    /// from it (RFC 7009).
    /// </summary>
    /// <remarks>
    /// <b>Which token to send matters, and the answer is the refresh token.</b> Revoking a refresh
    /// token invalidates the whole grant — the access tokens minted from it included. Revoking an
    /// access token invalidates that one string and leaves the refresh token able to mint another,
    /// which is an unlink that undoes itself the next time anything asks for a token. The caller
    /// picks; this method only says what it was given.
    /// <para>
    /// <b>The endpoint is discovered, not hardcoded.</b> <c>revocation_endpoint</c> is optional in
    /// OIDC Discovery, so its absence is a real answer — a provider that publishes no revocation
    /// endpoint cannot be asked to revoke, and pretending otherwise by guessing a URL would report a
    /// success that never happened. Google publishes one.
    /// </para>
    /// <para>
    /// <b>RFC 7009 says revoking an already-invalid token is a success.</b> Google disagrees and
    /// answers <c>400 invalid_token</c>, so that case is mapped explicitly: the state the caller
    /// asked for — this credential does not work — is the state that already holds. Reporting it as a
    /// failure would leave an unlink permanently blocked on revoking something that is already gone.
    /// </para>
    /// </remarks>
    public async Task<RevocationOutcome> RevokeTokenAsync(string token, CancellationToken ct)
    {
        var document = await discovery.GetDocumentAsync(Options.Authority, ct);

        if (document.RevocationEndpoint is null)
        {
            logger.LogWarning(
                "The discovery document for {Authority} publishes no revocation_endpoint; the grant cannot be revoked.",
                Options.Authority);

            return RevocationOutcome.Unsupported;
        }

        using var request = new HttpRequestMessage(HttpMethod.Post, document.RevocationEndpoint);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Content = new FormUrlEncodedContent(new Dictionary<string, string> { ["token"] = token });

        using var response = await httpClient.SendAsync(request, ct);

        if (response.IsSuccessStatusCode)
        {
            logger.LogInformation("Google revoked the grant behind this link.");
            return RevocationOutcome.Revoked;
        }

        // Read the body before deciding, for the same reason the token endpoint does: Google puts the
        // meaning in the body and the severity in the status code, and a client that reads only the
        // status turns "this token was already dead" into an outage.
        var body = await response.Content.ReadAsStringAsync(ct);

        if (response.StatusCode == HttpStatusCode.BadRequest
            && body.Contains("invalid_token", StringComparison.Ordinal))
        {
            logger.LogInformation("Google reports the token was already invalid; treating the grant as revoked.");
            return RevocationOutcome.AlreadyInvalid;
        }

        // Everything else is a transport-level problem and keeps its status code, so the caller can
        // tell "we asked and were refused" from "we never got to ask".
        response.EnsureSuccessStatusCode();
        return RevocationOutcome.Revoked;
    }

    /// <summary>
    /// Google reports every dead grant as RFC 6749's <c>invalid_grant</c> — revoked, expired, or
    /// invalidated by a password change all arrive under the same code, so the remedy is the same
    /// regardless: a new consent. <c>invalid_client</c> is deliberately absent: that means this
    /// app's own credentials are wrong, which no amount of user re-consent fixes.
    /// </summary>
    private static bool IsDeadGrant(string error) =>
        error is "invalid_grant" or "unauthorized_client";

    /// <summary>
    /// POSTs a form to the discovered token endpoint and reads the answer.
    /// </summary>
    /// <remarks>
    /// The status code is not the thing that decides success. Google reports an OAuth-level failure
    /// as <c>400</c> with a JSON error body, so <c>EnsureSuccessStatusCode</c> first would turn
    /// "your refresh token is dead" — a permanent, actionable condition — into a generic
    /// <c>HttpRequestException</c>, which <c>ProviderTokenService</c> quite correctly treats as a
    /// transient transport problem and does not latch on. The body is parsed first; the status code
    /// is only consulted for failures the body couldn't explain.
    /// </remarks>
    private async Task<GoogleTokenResponse> PostToTokenEndpointAsync(
        Dictionary<string, string> form, CancellationToken ct)
    {
        var document = await discovery.GetDocumentAsync(Options.Authority, ct);

        using var request = new HttpRequestMessage(HttpMethod.Post, document.TokenEndpoint);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Content = new FormUrlEncodedContent(form);

        using var response = await httpClient.SendAsync(request, ct);
        var body = await response.Content.ReadAsStringAsync(ct);

        GoogleTokenResponse? payload = null;
        try
        {
            payload = JsonSerializer.Deserialize<GoogleTokenResponse>(body);
        }
        catch (JsonException)
        {
            // A 5xx behind a load balancer arrives as HTML. Fall through to the status check.
        }

        if (payload?.Error is not null)
        {
            return payload;
        }

        response.EnsureSuccessStatusCode();

        return payload ?? throw new InvalidOperationException("Google's token endpoint returned an empty body.");
    }

    private OAuthTokenResult LogAndConvert(GoogleTokenResponse payload, string operation)
    {
        if (payload.AccessToken is null)
        {
            throw new InvalidOperationException("Google's token response was missing access_token.");
        }

        // Scope, type, length, lifetimes — never a value. Same rule as everywhere else, and it now
        // covers the id_token too: it is a bearer assertion, and one pasted into a log file is one
        // anybody who can read the log can replay.
        logger.LogInformation(
            "Obtained Google access token by {Operation} (scope: {Scope}, type: {TokenType}, length: {Length}, " +
            "expires_in: {ExpiresIn}, refresh_token_present: {HasRefreshToken}, id_token_present: {HasIdToken})",
            operation, payload.Scope, payload.TokenType, payload.AccessToken.Length,
            payload.ExpiresIn, payload.RefreshToken is not null, payload.IdToken is not null);

        return new OAuthTokenResult(
            AccessToken: payload.AccessToken,
            // Null on every refresh, because Google does not rotate. The caller must keep the stored
            // one rather than overwriting it — see LinkedAccountService.UpdateAfterRefreshAsync.
            RefreshToken: payload.RefreshToken,
            Scopes: payload.Scope,
            ExpiresAtUtc: SecondsFromNow(payload.ExpiresIn),
            // Google advertises no lifetime for the refresh token. It has one — 7 days while the
            // consent screen is in Testing mode, otherwise until it is revoked or goes six months
            // unused — but the provider never states it, and inventing a date here would be a
            // guess presented to the user as a fact.
            RefreshTokenExpiresAtUtc: null);
    }

    private static DateTimeOffset? SecondsFromNow(int? lifetimeSeconds) =>
        lifetimeSeconds is > 0 ? DateTimeOffset.UtcNow.AddSeconds(lifetimeSeconds.Value) : null;

    private record GoogleTokenResponse(
        [property: JsonPropertyName("access_token")] string? AccessToken,
        [property: JsonPropertyName("refresh_token")] string? RefreshToken,
        [property: JsonPropertyName("id_token")] string? IdToken,
        [property: JsonPropertyName("expires_in")] int? ExpiresIn,
        [property: JsonPropertyName("scope")] string? Scope,
        [property: JsonPropertyName("token_type")] string? TokenType,
        [property: JsonPropertyName("error")] string? Error,
        [property: JsonPropertyName("error_description")] string? ErrorDescription);
}
