using System.Net;

namespace OAuthDashboard.Tests;

/// <summary>
/// A github.com that behaves the way the real one does in the ways that matter: it accepts exactly
/// one access token at a time, rotates the refresh token on every refresh, reports OAuth failures as
/// HTTP 200 with an error in the body, and answers 204 to a grant revocation.
/// </summary>
/// <remarks>
/// Lifted out of <c>TokenRefreshTests</c> in M5, where a second and third suite needed the same
/// provider. Its M3 surface is unchanged — the refresh behaviour those tests assert on is the same
/// object — with the widget endpoints and the revocation endpoint added beside it.
/// </remarks>
internal sealed class FakeGitHub
{
    public const string ClientId = "test-client-id";
    public const string ClientSecret = "test-client-secret";

    private int _refreshCount;
    private int _userCallCount;
    private int _repositoryCallCount;
    private int _organizationCallCount;
    private int _revocationCallCount;

    public string AcceptedAccessToken { get; set; } = "";

    /// <summary>Set to make the refresh grant fail with this error code.</summary>
    public string? RefreshError { get; set; }

    /// <summary>When false, even a freshly minted token is refused — a grant revoked mid-flight.</summary>
    public bool AcceptRefreshedTokens { get; set; } = true;

    public HttpStatusCode? UserEndpointStatus { get; set; }

    /// <summary>Forces a status on the repositories endpoint alone, to fail one widget and not the rest.</summary>
    public HttpStatusCode? RepositoriesEndpointStatus { get; set; }

    /// <summary>
    /// When set, the organizations endpoint answers 403 — the provider disagreeing with the scope
    /// string this app stored. <c>true</c> additionally reports a depleted rate limit, which is the
    /// other thing GitHub spends 403 on.
    /// </summary>
    public bool OrganizationsForbidden { get; set; }

    public bool OrganizationsRateLimited { get; set; }

    public TimeSpan RefreshDelay { get; set; }

    /// <summary>
    /// Replaces the repositories payload. Used to serve a response the widget's parsing cannot handle,
    /// which is how the aggregator's failure isolation gets tested against something other than a
    /// status code.
    /// </summary>
    public string? RepositoriesJsonOverride { get; set; }

    /// <summary>What the revocation endpoint answers. 204 is the real one's success.</summary>
    public HttpStatusCode RevocationStatus { get; set; } = HttpStatusCode.NoContent;

    /// <summary>The token the revocation request carried in its body, once one has arrived.</summary>
    public string? RevokedToken { get; private set; }

    /// <summary>The credentials the revocation request authenticated with, decoded.</summary>
    public string? RevocationBasicCredentials { get; private set; }

    public int RefreshCount => Volatile.Read(ref _refreshCount);

    public int UserCallCount => Volatile.Read(ref _userCallCount);

    public int RepositoryCallCount => Volatile.Read(ref _repositoryCallCount);

    public int OrganizationCallCount => Volatile.Read(ref _organizationCallCount);

    public int RevocationCallCount => Volatile.Read(ref _revocationCallCount);

    public HttpResponseMessage Respond(StubGitHubRequest request)
    {
        if (request.IsTokenEndpoint)
        {
            Interlocked.Increment(ref _refreshCount);

            // Held long enough for the other racers to arrive, so the lock is genuinely contended
            // rather than the test just happening to run them one after another.
            if (RefreshDelay > TimeSpan.Zero)
            {
                Thread.Sleep(RefreshDelay);
            }

            if (RefreshError is not null)
            {
                return StubGitHubHandler.Json(StubGitHubHandler.ErrorJson(RefreshError));
            }

            if (AcceptRefreshedTokens)
            {
                AcceptedAccessToken = "gho_refreshed";
            }

            return StubGitHubHandler.Json(StubGitHubHandler.TokenJson(
                "gho_refreshed", refreshToken: "ghr_rotated", expiresIn: 28800, refreshTokenExpiresIn: 15811200));
        }

        if (request.IsGrantRevocation || request.IsTokenRevocation)
        {
            Interlocked.Increment(ref _revocationCallCount);

            RevokedToken = request.JsonField("access_token");
            RevocationBasicCredentials = request.AuthorizationScheme == "Basic" && request.AuthorizationParameter is { } blob
                ? System.Text.Encoding.UTF8.GetString(System.Convert.FromBase64String(blob))
                : null;

            return new HttpResponseMessage(RevocationStatus);
        }

        if (request.IsRepositoriesEndpoint)
        {
            Interlocked.Increment(ref _repositoryCallCount);

            if (RepositoriesEndpointStatus is { } repoStatus)
            {
                return StubGitHubHandler.Status(repoStatus);
            }

            return request.AccessToken == AcceptedAccessToken
                ? StubGitHubHandler.Json(RepositoriesJsonOverride ?? RepositoriesJson)
                : StubGitHubHandler.Status(HttpStatusCode.Unauthorized);
        }

        if (request.IsOrganizationsEndpoint)
        {
            Interlocked.Increment(ref _organizationCallCount);

            if (OrganizationsForbidden)
            {
                var forbidden = StubGitHubHandler.Status(HttpStatusCode.Forbidden);

                // The header is the only thing separating "you lack the scope" from "you are rate
                // limited", so the fake has to be able to send it — otherwise the client's
                // distinction is untestable and would pass by accident.
                forbidden.Headers.Add("x-ratelimit-remaining", OrganizationsRateLimited ? "0" : "4999");

                return forbidden;
            }

            return request.AccessToken == AcceptedAccessToken
                ? StubGitHubHandler.Json(OrganizationsJson)
                : StubGitHubHandler.Status(HttpStatusCode.Unauthorized);
        }

        Interlocked.Increment(ref _userCallCount);

        if (UserEndpointStatus is { } status)
        {
            return StubGitHubHandler.Status(status);
        }

        return request.AccessToken == AcceptedAccessToken
            ? StubGitHubHandler.Json(UserJson)
            : StubGitHubHandler.Status(HttpStatusCode.Unauthorized);
    }

    private const string UserJson =
        """{"id":583231,"login":"octocat","name":"The Octocat","public_repos":8,"followers":42,"html_url":"https://github.com/octocat"}""";

    private const string RepositoriesJson =
        """
        [
          {"name":"hello-world","description":"My first repository","language":"C#","stargazers_count":3,
           "pushed_at":"2026-08-20T09:15:00Z","html_url":"https://github.com/octocat/hello-world","private":false},
          {"name":"dotfiles","description":null,"language":null,"stargazers_count":0,
           "pushed_at":"2026-08-11T18:02:00Z","html_url":"https://github.com/octocat/dotfiles","private":false}
        ]
        """;

    private const string OrganizationsJson =
        """
        [
          {"login":"acme-industries","description":"Anvils since 1949","html_url":"https://github.com/acme-industries"}
        ]
        """;
}
