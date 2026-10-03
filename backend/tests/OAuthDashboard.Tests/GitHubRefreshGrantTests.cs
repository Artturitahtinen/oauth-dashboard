using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using OAuthDashboard.Infrastructure.Auth;

namespace OAuthDashboard.Tests;

/// <summary>
/// The refresh grant as it goes over the wire: what gets sent, how the answer is read, and which
/// failures mean "this grant is over" rather than "try again".
/// </summary>
public class GitHubRefreshGrantTests
{
    private const string StoredRefreshToken = "ghr_stored";

    /// <summary>
    /// The refresh grant is a different request from the code exchange, and getting its shape wrong
    /// fails as an opaque <c>invalid_request</c>. In particular there is no <c>code</c>, no
    /// <c>redirect_uri</c> and no <c>code_verifier</c> — PKCE protects a flow that passes through a
    /// browser, and this one never leaves the server.
    /// </summary>
    [Fact]
    public async Task RefreshAccessTokenAsync_SendsTheRefreshTokenGrantWithClientCredentials()
    {
        var (client, handler) = CreateClient(_ => StubGitHubHandler.Json(StubGitHubHandler.TokenJson("gho_new")));

        await client.RefreshAccessTokenAsync(StoredRefreshToken, CancellationToken.None);

        var request = Assert.Single(handler.Requests);
        Assert.True(request.IsTokenEndpoint);
        Assert.Equal("refresh_token", request.Form("grant_type"));
        Assert.Equal(StoredRefreshToken, request.Form("refresh_token"));
        Assert.Equal("test-client-id", request.Form("client_id"));
        Assert.Equal("test-client-secret", request.Form("client_secret"));
        Assert.Null(request.Form("code"));
        Assert.Null(request.Form("code_verifier"));
    }

    /// <summary>
    /// GitHub rotates the refresh token on every use. Losing the new value means the next refresh
    /// presents a retired credential, so it has to survive out of the client, not just the access
    /// token beside it.
    /// </summary>
    [Fact]
    public async Task RefreshAccessTokenAsync_ReturnsTheRotatedRefreshToken()
    {
        var (client, _) = CreateClient(_ => StubGitHubHandler.Json(
            StubGitHubHandler.TokenJson("gho_new", refreshToken: "ghr_rotated", expiresIn: 28800)));

        var result = await client.RefreshAccessTokenAsync(StoredRefreshToken, CancellationToken.None);

        Assert.Equal("gho_new", result.AccessToken);
        Assert.Equal("ghr_rotated", result.RefreshToken);
    }

    /// <summary>
    /// <c>expires_in</c> is a lifetime in seconds, meaningful only relative to the moment the answer
    /// arrived. Storing it unconverted would mean "3600" silently changed meaning every time it was
    /// later compared against the clock.
    /// </summary>
    [Fact]
    public async Task RefreshAccessTokenAsync_ConvertsRelativeLifetimesToAbsoluteInstants()
    {
        var (client, _) = CreateClient(_ => StubGitHubHandler.Json(StubGitHubHandler.TokenJson(
            "gho_new", refreshToken: "ghr_rotated", expiresIn: 28800, refreshTokenExpiresIn: 15811200)));

        var before = DateTimeOffset.UtcNow;
        var result = await client.RefreshAccessTokenAsync(StoredRefreshToken, CancellationToken.None);

        Assert.NotNull(result.ExpiresAtUtc);
        Assert.InRange(result.ExpiresAtUtc.Value, before.AddSeconds(28800), DateTimeOffset.UtcNow.AddSeconds(28800));

        Assert.NotNull(result.RefreshTokenExpiresAtUtc);
        Assert.InRange(
            result.RefreshTokenExpiresAtUtc.Value,
            before.AddSeconds(15811200),
            DateTimeOffset.UtcNow.AddSeconds(15811200));
    }

    /// <summary>
    /// A GitHub OAuth App's token has no advertised expiry. Null has to stay null: flattened to a
    /// date it would either look permanently expired or permanently valid, and both are wrong.
    /// </summary>
    [Fact]
    public async Task RefreshAccessTokenAsync_LeavesAnUnadvertisedExpiryNull()
    {
        var (client, _) = CreateClient(_ => StubGitHubHandler.Json(StubGitHubHandler.TokenJson("gho_new")));

        var result = await client.RefreshAccessTokenAsync(StoredRefreshToken, CancellationToken.None);

        Assert.Null(result.ExpiresAtUtc);
        Assert.Null(result.RefreshTokenExpiresAtUtc);
    }

    /// <summary>
    /// The failure that defines the milestone's unhappy path. It arrives as HTTP 200 with an error
    /// in the body — the response is a perfectly successful HTTP transaction reporting an
    /// unsuccessful OAuth one, so status-code checking alone would read this as a token.
    /// </summary>
    [Theory]
    [InlineData("bad_refresh_token")]
    [InlineData("invalid_grant")]
    [InlineData("unauthorized_client")]
    public async Task RefreshAccessTokenAsync_TreatsADeadGrantAsRejection(string error)
    {
        var (client, _) = CreateClient(_ => StubGitHubHandler.Json(StubGitHubHandler.ErrorJson(error)));

        var ex = await Assert.ThrowsAsync<RefreshTokenRejectedException>(
            () => client.RefreshAccessTokenAsync(StoredRefreshToken, CancellationToken.None));

        Assert.Equal(error, ex.Error);
    }

    /// <summary>
    /// And the other half of that distinction: an error that isn't about the refresh token must not
    /// be reported as a dead grant, or a bad minute at the provider would demand the user re-consent.
    /// </summary>
    [Fact]
    public async Task RefreshAccessTokenAsync_DoesNotTreatAGenericFailureAsADeadGrant()
    {
        var (client, _) = CreateClient(_ => StubGitHubHandler.Json(StubGitHubHandler.ErrorJson("server_error")));

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.RefreshAccessTokenAsync(StoredRefreshToken, CancellationToken.None));
    }

    private static (GitHubOAuthClient Client, StubGitHubHandler Handler) CreateClient(
        Func<StubGitHubRequest, HttpResponseMessage> respond)
    {
        var handler = new StubGitHubHandler(respond);

        var client = new GitHubOAuthClient(
            new HttpClient(handler),
            Options.Create(new GitHubOAuthOptions
            {
                ClientId = "test-client-id",
                ClientSecret = "test-client-secret",
                RedirectUri = "https://localhost:7236/api/auth/github/callback",
            }),
            NullLogger<GitHubOAuthClient>.Instance);

        return (client, handler);
    }
}
