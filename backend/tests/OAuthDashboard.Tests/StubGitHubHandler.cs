using System.Collections.Concurrent;
using System.Net;
using System.Text;

namespace OAuthDashboard.Tests;

/// <summary>
/// Stands in for github.com at the transport layer, so the refresh flow can be tested without a
/// network or a real grant.
/// </summary>
/// <remarks>
/// Substituting the <see cref="HttpMessageHandler"/> rather than an interface in front of
/// <c>GitHubOAuthClient</c> is deliberate: the parts of M3 most likely to be wrong are the wire
/// details — which form fields the refresh grant sends, that a failure arrives as HTTP 200 with an
/// error in the body, that <c>expires_in</c> is a relative lifetime. A hand-written fake of the
/// client would assume all of that is right and test only the code above it.
/// </remarks>
internal sealed class StubGitHubHandler(
    Func<StubGitHubRequest, HttpResponseMessage> respond) : HttpMessageHandler
{
    private readonly ConcurrentQueue<StubGitHubRequest> _requests = new();

    public IReadOnlyCollection<StubGitHubRequest> Requests => _requests;

    public int TokenEndpointCallCount => _requests.Count(r => r.IsTokenEndpoint);

    /// <summary>
    /// How long to hold a request before answering it, per request. Awaited rather than slept, which
    /// matters more than it sounds: a stub that blocks its calling thread also blocks the branch that
    /// was about to start, so a fan-out under test never actually overlaps and a concurrency assertion
    /// passes without the concurrency ever happening.
    /// </summary>
    public Func<StubGitHubRequest, TimeSpan>? DelayFor { get; set; }

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null
            ? string.Empty
            : await request.Content.ReadAsStringAsync(cancellationToken);

        var captured = new StubGitHubRequest(
            request.Method.Method,
            request.RequestUri!.ToString(),
            body,
            request.Headers.Authorization?.Scheme,
            request.Headers.Authorization?.Parameter);

        _requests.Enqueue(captured);

        if (DelayFor?.Invoke(captured) is { } delay && delay > TimeSpan.Zero)
        {
            await Task.Delay(delay, cancellationToken);
        }

        return respond(captured);
    }

    public static HttpResponseMessage NoContent() => new(HttpStatusCode.NoContent);

    /// <summary>A 200 carrying a JSON body, which is how GitHub answers both success and failure.</summary>
    public static HttpResponseMessage Json(string json) => new(HttpStatusCode.OK)
    {
        Content = new StringContent(json, Encoding.UTF8, "application/json"),
    };

    public static HttpResponseMessage Status(HttpStatusCode status) => new(status)
    {
        Content = new StringContent("{}", Encoding.UTF8, "application/json"),
    };

    public static string TokenJson(
        string accessToken,
        string? refreshToken = null,
        int? expiresIn = null,
        int? refreshTokenExpiresIn = null,
        string scope = "read:user")
    {
        var fields = new List<string>
        {
            $"\"access_token\":\"{accessToken}\"",
            $"\"scope\":\"{scope}\"",
            "\"token_type\":\"bearer\"",
        };

        if (refreshToken is not null) fields.Add($"\"refresh_token\":\"{refreshToken}\"");
        if (expiresIn is not null) fields.Add($"\"expires_in\":{expiresIn}");
        if (refreshTokenExpiresIn is not null) fields.Add($"\"refresh_token_expires_in\":{refreshTokenExpiresIn}");

        return "{" + string.Join(',', fields) + "}";
    }

    public static string ErrorJson(string error) =>
        $"{{\"error\":\"{error}\",\"error_description\":\"simulated {error}\"}}";
}

/// <param name="AuthorizationScheme">
/// <c>Bearer</c> for a call made on the user's behalf, <c>Basic</c> for one the application makes as
/// itself. M5's revocation endpoint is the second kind, and the distinction is the point: a
/// revocation authenticated with the user's token would be a different request than the one GitHub
/// documents, and the obvious mistake to make.
/// </param>
/// <param name="AuthorizationParameter">Whatever followed the scheme, verbatim.</param>
internal record StubGitHubRequest(
    string Method, string Url, string Body, string? AuthorizationScheme, string? AuthorizationParameter)
{
    /// <summary>The bearer token the request carried — null when it authenticated some other way.</summary>
    public string? AccessToken =>
        AuthorizationScheme == "Bearer" ? AuthorizationParameter : null;

    public bool IsTokenEndpoint => Url.Contains("/login/oauth/access_token", StringComparison.Ordinal);

    /// <summary>The profile endpoint itself, and not the sub-resources hanging off it.</summary>
    public bool IsUserEndpoint => Url.TrimEnd('/').EndsWith("api.github.com/user", StringComparison.Ordinal);

    public bool IsRepositoriesEndpoint => Url.Contains("api.github.com/user/repos", StringComparison.Ordinal);

    public bool IsOrganizationsEndpoint => Url.Contains("api.github.com/user/orgs", StringComparison.Ordinal);

    public bool IsGrantRevocation =>
        Method == "DELETE" && Url.Contains("/applications/", StringComparison.Ordinal)
                           && Url.EndsWith("/grant", StringComparison.Ordinal);

    /// <summary>The narrower endpoint GitHub also offers, which revokes a token and leaves the grant.</summary>
    public bool IsTokenRevocation =>
        Method == "DELETE" && Url.Contains("/applications/", StringComparison.Ordinal)
                           && Url.EndsWith("/token", StringComparison.Ordinal);

    /// <summary>Reads one field out of a JSON request body without deserializing into a type.</summary>
    public string? JsonField(string name)
    {
        using var document = System.Text.Json.JsonDocument.Parse(Body);

        return document.RootElement.TryGetProperty(name, out var value) ? value.GetString() : null;
    }

    /// <summary>Reads one field back out of the form-urlencoded request body.</summary>
    public string? Form(string name) => Body
        .Split('&')
        .Select(pair => pair.Split('=', 2))
        .Where(parts => parts.Length == 2 && Uri.UnescapeDataString(parts[0]) == name)
        .Select(parts => Uri.UnescapeDataString(parts[1].Replace('+', ' ')))
        .FirstOrDefault();
}
