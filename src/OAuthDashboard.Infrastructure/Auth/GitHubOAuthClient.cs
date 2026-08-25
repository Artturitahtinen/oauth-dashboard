using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using OAuthDashboard.Core.Accounts;

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
    private const string ApiRoot = "https://api.github.com";
    private const string UserEndpoint = $"{ApiRoot}/user";

    /// <summary>
    /// Builds the URL the browser gets redirected to. Everything here is public by construction —
    /// it ends up in the address bar, browser history, and GitHub's logs — which is why the PKCE
    /// <em>challenge</em> goes in it and the verifier does not.
    /// </summary>
    /// <param name="additionalScope">
    /// The one optional permission this authorization is adding, or null for a plain link. It comes
    /// from <see cref="ProviderScopes"/>, never from the request — see the note there on why a
    /// caller-supplied <c>scope</c> parameter on an authenticated endpoint is an escalation
    /// primitive.
    /// </param>
    /// <remarks>
    /// GitHub has no equivalent of Google's <c>include_granted_scopes</c> and does not need one: an
    /// authorization is a set that new scopes are unioned into, so a token minted here carries
    /// everything the user has previously granted plus whatever is requested now. The same property
    /// is why re-authorizing with a smaller set cannot take a scope <em>away</em>.
    /// </remarks>
    public string BuildAuthorizationUrl(string state, string codeChallenge, OptionalScope? additionalScope = null)
    {
        var opts = options.Value;
        var query = string.Join('&', new[]
        {
            $"client_id={Uri.EscapeDataString(opts.ClientId)}",
            $"redirect_uri={Uri.EscapeDataString(opts.RedirectUri)}",
            $"scope={Uri.EscapeDataString(ProviderScopes.RequestFor(OAuthProvider.GitHub, additionalScope))}",
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

    // --- M5: widget data ------------------------------------------------------------------------

    /// <summary>
    /// The repositories the user most recently pushed to, newest first.
    /// </summary>
    /// <remarks>
    /// <c>visibility=public</c> is sent even though the base <c>read:user</c> scope could not return
    /// a private repository anyway. It is a statement of intent rather than a filter that currently
    /// does anything: if this app ever holds a token with <c>repo</c> on it — granted for some
    /// unrelated widget — this call does not quietly start putting private repository names on a
    /// dashboard whose card says "public repositories". A request that only behaves correctly
    /// because of a scope it doesn't control is one scope change away from being wrong.
    /// </remarks>
    public async Task<List<GitHubRepository>> GetRecentRepositoriesAsync(
        string accessToken, int count, CancellationToken ct)
    {
        var url = $"{UserEndpoint}/repos?sort=pushed&direction=desc&visibility=public&affiliation=owner&per_page={count}";
        var payload = await GetJsonAsync(url, accessToken, ct);

        return payload.EnumerateArray()
            .Select(repo => new GitHubRepository(
                Name: repo.GetProperty("name").GetString() ?? "(unnamed)",
                Description: OptionalString(repo, "description"),
                Language: OptionalString(repo, "language"),
                StarCount: repo.TryGetProperty("stargazers_count", out var stars) ? stars.GetInt32() : 0,
                PushedAtUtc: OptionalTimestamp(repo, "pushed_at"),
                HtmlUrl: OptionalString(repo, "html_url")))
            .ToList();
    }

    /// <summary>
    /// The organizations the user belongs to. Needs the <c>read:org</c> scope, which is why the
    /// widget behind it is opt-in.
    /// </summary>
    public async Task<List<GitHubOrganization>> GetOrganizationsAsync(string accessToken, CancellationToken ct)
    {
        var payload = await GetJsonAsync($"{UserEndpoint}/orgs?per_page=10", accessToken, ct);

        return payload.EnumerateArray()
            .Select(org => new GitHubOrganization(
                Login: org.GetProperty("login").GetString() ?? "(unnamed)",
                Description: OptionalString(org, "description"),
                HtmlUrl: OptionalString(org, "html_url")))
            .ToList();
    }

    // --- M5: revocation -------------------------------------------------------------------------

    /// <summary>
    /// Revokes this app's entire authorization for the token's owner, so unlinking is something the
    /// provider knows about rather than a row this app quietly forgets.
    /// </summary>
    /// <remarks>
    /// <b>The grant, not the token.</b> GitHub offers both:
    /// <c>DELETE /applications/{client_id}/token</c> retires one access token, and
    /// <c>DELETE /applications/{client_id}/grant</c> retires the authorization itself along with
    /// every token issued under it. Only the second is an unlink. After the first, the user's
    /// authorization is still listed in their GitHub settings and this app can mint a new token
    /// through <c>/authorize</c> with <em>no consent screen shown</em>, because the user already
    /// consented and never took it back — so "unlink" would have removed a credential while leaving
    /// the permission that produces credentials.
    /// <para>
    /// <b>The client secret authenticates this call, not the user's token.</b> Basic auth with
    /// <c>client_id:client_secret</c> is what proves the caller is the application whose grant is
    /// being dropped; the access token in the body is the subject of the request, not the
    /// authorization for it. Sending it as a bearer token instead — the obvious guess — gets a 404,
    /// because the endpoint isn't addressed to the user.
    /// </para>
    /// </remarks>
    public async Task<RevocationOutcome> RevokeGrantAsync(string accessToken, CancellationToken ct)
    {
        var opts = options.Value;

        using var request = new HttpRequestMessage(
            HttpMethod.Delete, $"{ApiRoot}/applications/{Uri.EscapeDataString(opts.ClientId)}/grant");

        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Basic",
            Convert.ToBase64String(Encoding.UTF8.GetBytes($"{opts.ClientId}:{opts.ClientSecret}")));
        request.Headers.UserAgent.Add(new ProductInfoHeaderValue("OAuthDashboard", "0.1"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));

        // The token is the object of the request. It is sent, once, to be destroyed — and it is not
        // logged here or anywhere on this path.
        request.Content = new StringContent(
            JsonSerializer.Serialize(new { access_token = accessToken }), Encoding.UTF8, "application/json");

        using var response = await httpClient.SendAsync(request, ct);

        switch (response.StatusCode)
        {
            case HttpStatusCode.NoContent:
                logger.LogInformation("GitHub revoked this application's grant.");
                return RevocationOutcome.Revoked;

            // 404 is the honest answer to "revoke a grant that isn't there" — a user who already
            // revoked it from their GitHub settings page, or a token that expired out from under us.
            // The end state is exactly the one asked for, so treating it as a failure would leave a
            // local row that can never be deleted.
            case HttpStatusCode.NotFound:
            // 422 means GitHub could not match the token to this application, which likewise means
            // there is nothing here of ours left to revoke.
            case HttpStatusCode.UnprocessableEntity:
                logger.LogInformation(
                    "GitHub reports no live grant to revoke ({Status}); treating the link as already revoked.",
                    (int)response.StatusCode);
                return RevocationOutcome.AlreadyInvalid;

            default:
                // Anything else — 5xx, a rate limit, a proxy — is a transport failure and is allowed
                // to propagate as one. The caller decides what to do about a revocation that could
                // not be attempted, and that decision is deliberately not made here.
                response.EnsureSuccessStatusCode();
                return RevocationOutcome.Revoked;
        }
    }

    private async Task<JsonElement> GetJsonAsync(string url, string accessToken, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.UserAgent.Add(new ProductInfoHeaderValue("OAuthDashboard", "0.1"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));

        using var response = await httpClient.SendAsync(request, ct);

        if (response.StatusCode == HttpStatusCode.Forbidden)
        {
            // GitHub spends 403 on two unrelated things, and the header is what separates them: a
            // depleted rate limit reports `x-ratelimit-remaining: 0`, while a missing scope does not.
            // Collapsing them would either latch a permission problem as a temporary outage or tell a
            // rate-limited user to grant a scope they already granted.
            var rateLimited = response.Headers.TryGetValues("x-ratelimit-remaining", out var remaining)
                              && remaining.FirstOrDefault() == "0";

            if (!rateLimited)
            {
                throw new ProviderPermissionException("insufficient_scope");
            }
        }

        // Left to throw with the status attached. A 401 here is what ProviderTokenService's reactive
        // refresh trigger reads, so it has to keep its status code to stay distinguishable further up.
        response.EnsureSuccessStatusCode();

        return await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
    }

    private static string? OptionalString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind is JsonValueKind.String
            ? value.GetString()
            : null;

    private static DateTimeOffset? OptionalTimestamp(JsonElement element, string property) =>
        DateTimeOffset.TryParse(OptionalString(element, property), out var parsed) ? parsed : null;

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

/// <summary>
/// One repository, cut down to the fields the widget renders.
/// </summary>
/// <remarks>
/// GitHub's repository object has well over a hundred fields. Modelling five of them is not
/// laziness: the dashboard is a BFF, and a BFF that forwards a provider's response verbatim
/// re-creates in the browser exactly the data exposure it was built to prevent. What the SPA cannot
/// receive, an XSS bug on the SPA cannot read.
/// </remarks>
public record GitHubRepository(
    string Name,
    string? Description,
    string? Language,
    int StarCount,
    DateTimeOffset? PushedAtUtc,
    string? HtmlUrl);

public record GitHubOrganization(string Login, string? Description, string? HtmlUrl);
