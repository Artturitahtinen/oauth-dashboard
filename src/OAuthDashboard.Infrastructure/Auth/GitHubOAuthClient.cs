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

    // M1 requests only the minimum scope needed to prove the flow (read the profile). Widgets
    // that need repo/issue/PR data ask for those scopes when they're built (least privilege).
    private const string Scope = "read:user";

    public string BuildAuthorizationUrl(string state)
    {
        var opts = options.Value;
        var query = string.Join('&', new[]
        {
            $"client_id={Uri.EscapeDataString(opts.ClientId)}",
            $"redirect_uri={Uri.EscapeDataString(opts.RedirectUri)}",
            $"scope={Uri.EscapeDataString(Scope)}",
            $"state={Uri.EscapeDataString(state)}",
        });

        return $"{AuthorizeEndpoint}?{query}";
    }

    public async Task<string> ExchangeCodeForAccessTokenAsync(string code, CancellationToken ct)
    {
        var opts = options.Value;

        using var request = new HttpRequestMessage(HttpMethod.Post, TokenEndpoint);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        request.Content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["client_id"] = opts.ClientId,
            ["client_secret"] = opts.ClientSecret,
            ["code"] = code,
            ["redirect_uri"] = opts.RedirectUri,
        });

        using var response = await httpClient.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();

        var payload = await response.Content.ReadFromJsonAsync<GitHubTokenResponse>(cancellationToken: ct)
            ?? throw new InvalidOperationException("GitHub token endpoint returned an empty body.");

        if (payload.Error is not null)
        {
            throw new InvalidOperationException($"GitHub token exchange failed: {payload.Error} ({payload.ErrorDescription})");
        }

        if (payload.AccessToken is null)
        {
            throw new InvalidOperationException("GitHub token response was missing access_token.");
        }

        // M1 has nothing hidden, including seeing the raw exchange succeed end to end, so this
        // logs that a token was obtained. It intentionally does NOT log the token value itself —
        // that habit needs to be right before M2 adds real persistence, not retrofitted after.
        logger.LogInformation(
            "Obtained GitHub access token (scope: {Scope}, type: {TokenType}, length: {Length})",
            payload.Scope, payload.TokenType, payload.AccessToken.Length);

        return payload.AccessToken;
    }

    public async Task<JsonElement> GetAuthenticatedUserAsync(string accessToken, CancellationToken ct)
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
        [property: JsonPropertyName("scope")] string? Scope,
        [property: JsonPropertyName("token_type")] string? TokenType,
        [property: JsonPropertyName("error")] string? Error,
        [property: JsonPropertyName("error_description")] string? ErrorDescription);
}
