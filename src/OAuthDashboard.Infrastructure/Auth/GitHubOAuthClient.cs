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

        using var request = new HttpRequestMessage(HttpMethod.Post, TokenEndpoint);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = opts.ClientId,
            ["client_secret"] = opts.ClientSecret,
            ["code"] = code,
            // Sent again at exchange time and compared by GitHub against the value from the
            // authorize step. It is not a redirect instruction — nothing gets redirected here — it's
            // a binding check, and it comes from configuration rather than from the request.
            ["redirect_uri"] = opts.RedirectUri,
            ["code_verifier"] = codeVerifier,
        });

        using var response = await httpClient.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();

        var payload = await response.Content.ReadFromJsonAsync<GitHubTokenResponse>(cancellationToken: ct)
            ?? throw new InvalidOperationException("GitHub token endpoint returned an empty body.");

        // GitHub answers a failed exchange with HTTP 200 and an error in the body, so
        // EnsureSuccessStatusCode above proves nothing on its own.
        if (payload.Error is not null)
        {
            throw new InvalidOperationException($"GitHub token exchange failed: {payload.Error} ({payload.ErrorDescription})");
        }

        if (payload.AccessToken is null)
        {
            throw new InvalidOperationException("GitHub token response was missing access_token.");
        }

        // Logs that a token was obtained (scope, type, length) and deliberately never its value.
        logger.LogInformation(
            "Obtained GitHub access token (scope: {Scope}, type: {TokenType}, length: {Length}, expires_in: {ExpiresIn})",
            payload.Scope, payload.TokenType, payload.AccessToken.Length, payload.ExpiresIn);

        return new OAuthTokenResult(
            AccessToken: payload.AccessToken,
            RefreshToken: payload.RefreshToken,
            Scopes: payload.Scope,
            // A standard OAuth App returns no expires_in and its token simply doesn't expire; only
            // GitHub Apps with expiring tokens populate this. Null therefore means "no expiry
            // advertised", which M3 has to treat differently from "expired".
            ExpiresAtUtc: payload.ExpiresIn is > 0
                ? DateTimeOffset.UtcNow.AddSeconds(payload.ExpiresIn.Value)
                : null);
    }

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
        [property: JsonPropertyName("scope")] string? Scope,
        [property: JsonPropertyName("token_type")] string? TokenType,
        [property: JsonPropertyName("error")] string? Error,
        [property: JsonPropertyName("error_description")] string? ErrorDescription);
}
