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

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null
            ? string.Empty
            : await request.Content.ReadAsStringAsync(cancellationToken);

        var captured = new StubGitHubRequest(
            request.RequestUri!.ToString(),
            body,
            request.Headers.Authorization?.Parameter);

        _requests.Enqueue(captured);

        return respond(captured);
    }

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

/// <param name="AccessToken">The bearer token the request carried, if any.</param>
internal record StubGitHubRequest(string Url, string Body, string? AccessToken)
{
    public bool IsTokenEndpoint => Url.Contains("/login/oauth/access_token", StringComparison.Ordinal);

    public bool IsUserEndpoint => Url.Contains("api.github.com/user", StringComparison.Ordinal);

    /// <summary>Reads one field back out of the form-urlencoded request body.</summary>
    public string? Form(string name) => Body
        .Split('&')
        .Select(pair => pair.Split('=', 2))
        .Where(parts => parts.Length == 2 && Uri.UnescapeDataString(parts[0]) == name)
        .Select(parts => Uri.UnescapeDataString(parts[1].Replace('+', ' ')))
        .FirstOrDefault();
}
