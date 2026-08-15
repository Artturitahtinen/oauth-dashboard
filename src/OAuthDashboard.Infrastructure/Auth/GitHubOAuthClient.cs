using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace OAuthDashboard.Infrastructure.Auth;

/// <summary>
/// Talks to GitHub's OAuth endpoints directly over HttpClient — no
/// Microsoft.AspNetCore.Authentication.OAuth middleware — so the authorization-code exchange is
/// visible end to end instead of hidden behind a handler.
/// </summary>
public class GitHubOAuthClient(HttpClient httpClient, IOptions<GitHubOAuthOptions> options, ILogger<GitHubOAuthClient> logger)
{
    private const string AuthorizeEndpoint = "https://github.com/login/oauth/authorize";
    private const string TokenEndpoint = "https://github.com/login/oauth/access_token";
    private const string UserEndpoint = "https://api.github.com/user";

    // Still the minimum scope needed to prove the flow (read the profile). Widgets that need
    // repo/issue/PR data ask for those scopes when they're built (least privilege).
    private const string Scope = "read:user";

    /// <summary>
    /// Builds the URL the browser gets redirected to. Everything here is public by construction —
    /// it ends up in the address bar, browser history, and GitHub's logs — which is why the PKCE
    /// <em>challenge</em> goes in it and the verifier does not.
    /// </summary>
    public string BuildAuthorizationUrl(string state, string codeChallenge)
    {
        var opts = options.Value;
        var query = string.Join('&', new[]
        {
            $"client_id={Uri.EscapeDataString(opts.ClientId)}",
            $"redirect_uri={Uri.EscapeDataString(opts.RedirectUri)}",
            $"scope={Uri.EscapeDataString(Scope)}",
            $"state={Uri.EscapeDataString(state)}",
            $"code_challenge={Uri.EscapeDataString(codeChallenge)}",
            "code_challenge_method=S256",
        });

        return $"{AuthorizeEndpoint}?{query}";
    }

    /// <summary>
    /// Exchanges the authorization code for tokens over a direct server-to-server POST. The
    /// <paramref name="codeVerifier"/> is the other half of the PKCE pair: GitHub re-derives
    /// SHA-256 of it and compares against the challenge it stored at authorize time, so a code
    /// stolen from the redirect can't be redeemed without this value.
    /// </summary>
    public async Task<OAuthTokenResult> ExchangeCodeForTokenAsync(string code, string codeVerifier, CancellationToken ct)
    {
        var opts = options.Value;

        var payload = await PostToTokenEndpointAsync(new Dictionary<string, string>
        {
            ["client_id"] = opts.ClientId,
            ["client_secret"] = opts.ClientSecret,
            ["grant_type"] = "authorization_code",
            ["code"] = code,
            // Sent again at exchange time and compared by GitHub against the value from the
            // authorize step. It is not a redirect instruction — nothing gets redirected here — it's
            // a binding check, and it comes from configuration rather than from the request.
            ["redirect_uri"] = opts.RedirectUri,
            ["code_verifier"] = codeVerifier,
        }, ct);

        // GitHub answers a failed exchange with HTTP 200 and an error in the body, so
        // EnsureSuccessStatusCode inside the POST proves nothing on its own.
        if (payload.Error is not null)
        {
            throw new InvalidOperationException($"GitHub token exchange failed: {payload.Error} ({payload.ErrorDescription})");
        }

        return LogAndConvert(payload, "exchange");
    }

    /// <summary>
    /// Spends the refresh token on a new access token. This is the whole point of M3: the user
    /// consented once, and the app keeps working afterwards without sending them back to GitHub.
    /// </summary>
    /// <remarks>
    /// Three things about this grant are worth being explicit about, because each one is a way to
    /// get it quietly wrong:
    /// <list type="bullet">
    /// <item><b>No user is present.</b> There is no redirect, no browser, no <c>state</c> and no
    /// PKCE — those all protect a flow that travels through the user agent, and this one doesn't.
    /// What authenticates the caller here is the client secret plus possession of the refresh
    /// token.</item>
    /// <item><b>The refresh token rotates.</b> GitHub answers with a <em>new</em> refresh token and
    /// retires the one just used. Failing to store the new one means the next refresh presents a
    /// dead credential; replaying an old one is how a whole grant gets revoked for looking like
    /// theft. That's why the caller must persist the result before doing anything else, and why
    /// concurrent refreshes are serialized (see <c>ProviderTokenService</c>).</item>
    /// <item><b>"Rejected" is a different outcome from "failed".</b> A network blip should be
    /// retried; <c>bad_refresh_token</c> means this grant is over and no amount of retrying brings
    /// it back — the only way forward is a new authorization. Those are separated here rather than
    /// collapsed into one exception so the caller can tell "try again later" from "ask the user".</item>
    /// </list>
    /// </remarks>
    /// <exception cref="RefreshTokenRejectedException">
    /// The provider refused the refresh token itself — expired, already rotated, or revoked.
    /// </exception>
    public async Task<OAuthTokenResult> RefreshAccessTokenAsync(string refreshToken, CancellationToken ct)
    {
        var opts = options.Value;

        var payload = await PostToTokenEndpointAsync(new Dictionary<string, string>
        {
            ["client_id"] = opts.ClientId,
            ["client_secret"] = opts.ClientSecret,
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
        }, ct);

        if (payload.Error is not null)
        {
            // The error code is what separates "this grant is dead" from "something went wrong".
            // Logged without the refresh token value, same rule as everywhere else.
            logger.LogWarning(
                "GitHub refused the refresh grant: {Error} ({ErrorDescription})",
                payload.Error, payload.ErrorDescription);

            throw IsDeadGrant(payload.Error)
                ? new RefreshTokenRejectedException(payload.Error, payload.ErrorDescription)
                : new InvalidOperationException($"GitHub token refresh failed: {payload.Error} ({payload.ErrorDescription})");
        }

        return LogAndConvert(payload, "refresh");
    }

    /// <summary>
    /// The error codes that mean the refresh token will never work again, so retrying is pointless
    /// and the only remedy is a fresh authorization. <c>bad_refresh_token</c> is GitHub's spelling;
    /// <c>invalid_grant</c> is RFC 6749's, and is what Google answers with (M4).
    /// </summary>
    private static bool IsDeadGrant(string error) =>
        error is "bad_refresh_token" or "invalid_grant" or "unauthorized_client";

    /// <summary>
    /// Both grants POST to the same endpoint with the same content type and read back the same
    /// response shape; only the form fields and the error handling differ.
    /// </summary>
    private async Task<GitHubTokenResponse> PostToTokenEndpointAsync(Dictionary<string, string> form, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, TokenEndpoint);
        // Without this GitHub answers in form-urlencoded, which parses into an "empty" JSON object
        // and looks exactly like a missing access_token.
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Content = new FormUrlEncodedContent(form);

        using var response = await httpClient.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();

        return await response.Content.ReadFromJsonAsync<GitHubTokenResponse>(cancellationToken: ct)
               ?? throw new InvalidOperationException("GitHub token endpoint returned an empty body.");
    }

    private OAuthTokenResult LogAndConvert(GitHubTokenResponse payload, string operation)
    {
        if (payload.AccessToken is null)
        {
            throw new InvalidOperationException("GitHub token response was missing access_token.");
        }

        // Logs that a token was obtained (scope, type, length) and deliberately never its value.
        logger.LogInformation(
            "Obtained GitHub access token by {Operation} (scope: {Scope}, type: {TokenType}, length: {Length}, " +
            "expires_in: {ExpiresIn}, refresh_token_expires_in: {RefreshTokenExpiresIn}, rotated_refresh_token: {Rotated})",
            operation, payload.Scope, payload.TokenType, payload.AccessToken.Length,
            payload.ExpiresIn, payload.RefreshTokenExpiresIn, payload.RefreshToken is not null);

        return new OAuthTokenResult(
            AccessToken: payload.AccessToken,
            RefreshToken: payload.RefreshToken,
            Scopes: payload.Scope,
            // A standard OAuth App returns no expires_in and its token simply doesn't expire; only
            // GitHub Apps with expiring tokens populate this. Null therefore means "no expiry
            // advertised", which M3 treats differently from "expired".
            ExpiresAtUtc: SecondsFromNow(payload.ExpiresIn),
            RefreshTokenExpiresAtUtc: SecondsFromNow(payload.RefreshTokenExpiresIn));
    }

    /// <summary>
    /// Turns the provider's relative lifetime into an absolute instant. The conversion happens here,
    /// once, rather than at every read site: <c>expires_in</c> is only meaningful relative to the
    /// moment the response arrived, and a value stored as "3600" would silently mean something
    /// different every time it was later compared against the clock.
    /// </summary>
    private static DateTimeOffset? SecondsFromNow(int? lifetimeSeconds) =>
        lifetimeSeconds is > 0 ? DateTimeOffset.UtcNow.AddSeconds(lifetimeSeconds.Value) : null;

    /// <summary>
    /// Reads the linked account's identity. Called once at link time so the dashboard has a handle
    /// to show; the profile itself isn't mirrored into the local database.
    /// </summary>
    public async Task<ProviderAccountInfo> GetAuthenticatedUserAsync(string accessToken, CancellationToken ct)
    {
        var user = await GetUserJsonAsync(accessToken, ct);

        // GitHub's user id is a JSON number; it's stored as a string because the column has to hold
        // Google's opaque string subject too.
        var id = user.TryGetProperty("id", out var idProperty)
            ? idProperty.ToString()
            : throw new InvalidOperationException("GitHub /user response was missing id.");

        var login = user.TryGetProperty("login", out var loginProperty)
            ? loginProperty.GetString() ?? id
            : id;

        return new ProviderAccountInfo(id, login);
    }

    public async Task<JsonElement> GetUserJsonAsync(string accessToken, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, UserEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.UserAgent.Add(new ProductInfoHeaderValue("OAuthDashboard", "0.1"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));

        using var response = await httpClient.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();

        return await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
    }

    private record GitHubTokenResponse(
        [property: JsonPropertyName("access_token")] string? AccessToken,
        [property: JsonPropertyName("refresh_token")] string? RefreshToken,
        [property: JsonPropertyName("expires_in")] int? ExpiresIn,
        [property: JsonPropertyName("refresh_token_expires_in")] int? RefreshTokenExpiresIn,
        [property: JsonPropertyName("scope")] string? Scope,
        [property: JsonPropertyName("token_type")] string? TokenType,
        [property: JsonPropertyName("error")] string? Error,
        [property: JsonPropertyName("error_description")] string? ErrorDescription);
}
