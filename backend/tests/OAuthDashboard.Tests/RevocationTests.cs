using System.Net;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using OAuthDashboard.Core.Accounts;
using OAuthDashboard.Core.Users;
using OAuthDashboard.Infrastructure.Accounts;
using OAuthDashboard.Infrastructure.Auth;
using OAuthDashboard.Infrastructure.Persistence;
using OAuthDashboard.Infrastructure.Security;

namespace OAuthDashboard.Tests;

/// <summary>
/// M5's other half: unlinking that the provider is told about.
/// </summary>
/// <remarks>
/// The claim under test is not "a request was sent" but "the right request was sent to the right
/// endpoint with the right credential, and every way it can fail is distinguished". Each of those is
/// a way to ship a revocation that reports success and revokes nothing:
/// <list type="bullet">
/// <item>GitHub's token endpoint instead of its grant endpoint — 204, and the authorization survives.</item>
/// <item>Google's access token instead of its refresh token — 200, and the grant survives.</item>
/// <item>A bearer token instead of Basic auth on GitHub — 404, indistinguishable from "already gone".</item>
/// <item>A dead grant treated as an error — the local row can then never be deleted.</item>
/// </list>
/// </remarks>
public class RevocationTests : IAsyncLifetime
{
    private const string GitHubAccessToken = "gho_the-live-one";
    private const string GitHubRefreshToken = "ghr_the-live-one";
    private const string GoogleAccessToken = "ya29.the-live-one";
    private const string GoogleRefreshToken = "1//the-live-one";

    private SqliteConnection _connection = null!;
    private DashboardDbContext _db = null!;
    private LinkedAccountService _accounts = null!;
    private FakeGitHub _gitHub = null!;
    private StubGitHubHandler _gitHubHandler = null!;
    private FakeGoogle _google = null!;
    private int _userId;

    public async Task InitializeAsync()
    {
        _connection = new SqliteConnection("Data Source=:memory:");
        await _connection.OpenAsync();

        _db = new DashboardDbContext(
            new DbContextOptionsBuilder<DashboardDbContext>().UseSqlite(_connection).Options);
        await _db.Database.EnsureCreatedAsync();

        _accounts = new LinkedAccountService(_db, new TokenProtector(new EphemeralDataProtectionProvider()));
        _gitHub = new FakeGitHub();
        _gitHubHandler = new StubGitHubHandler(_gitHub.Respond);
        _google = new FakeGoogle();

        var user = new User
        {
            Username = "tester",
            PasswordHash = PasswordHasher.Hash("a-long-enough-password"),
            CreatedAtUtc = DateTimeOffset.UtcNow,
        };
        _db.Users.Add(user);
        await _db.SaveChangesAsync();
        _userId = user.Id;
    }

    public async Task DisposeAsync()
    {
        _google.Dispose();
        _gitHubHandler.Dispose();
        await _db.DisposeAsync();
        await _connection.DisposeAsync();
    }

    // --- GitHub -------------------------------------------------------------------------------------

    /// <summary>
    /// The wire format, in full. Three things have to be right at once, and each one is a way to
    /// revoke nothing while getting an encouraging status code back.
    /// </summary>
    [Fact]
    public async Task GitHub_RevokesTheGrantWithTheApplicationsOwnCredentials()
    {
        await LinkGitHubAsync();

        var report = await Service().RevokeAsync(_userId, OAuthProvider.GitHub, CancellationToken.None);

        Assert.Equal(RevocationOutcome.Revoked, report.Outcome);
        Assert.True(report.GrantIsGone);

        var request = Requests().Single();

        // The grant endpoint, not the token endpoint. `/token` retires one access token and leaves the
        // authorization listed in the user's GitHub settings — after which this app can mint a fresh
        // token with no consent screen, because the user never took the permission back.
        Assert.True(request.IsGrantRevocation, $"expected a grant revocation, got {request.Method} {request.Url}");
        Assert.False(request.IsTokenRevocation);

        // Authenticated as the application, not as the user. Sending the user's token as a bearer
        // credential — the obvious guess — gets a 404 from GitHub, which this code would then read as
        // "there was no grant", and the unlink would report success having revoked nothing.
        Assert.Equal("Basic", request.AuthorizationScheme);
        Assert.Equal($"{FakeGitHub.ClientId}:{FakeGitHub.ClientSecret}", _gitHub.RevocationBasicCredentials);

        // And the token is the *subject* of the request, carried in the body.
        Assert.Equal(GitHubAccessToken, _gitHub.RevokedToken);
    }

    /// <summary>
    /// A grant that is already gone — the user revoked it from their own settings page, which is
    /// exactly the sequence a careful user performs — must not block the unlink. GitHub answers 404,
    /// and the end state is the one that was asked for.
    /// </summary>
    [Theory]
    [InlineData(HttpStatusCode.NotFound)]
    [InlineData(HttpStatusCode.UnprocessableEntity)]
    public async Task GitHub_TreatsAGrantThatIsAlreadyGoneAsSuccess(HttpStatusCode status)
    {
        await LinkGitHubAsync();
        _gitHub.RevocationStatus = status;

        var report = await Service().RevokeAsync(_userId, OAuthProvider.GitHub, CancellationToken.None);

        Assert.Equal(RevocationOutcome.AlreadyInvalid, report.Outcome);
        Assert.True(report.GrantIsGone);
    }

    /// <summary>
    /// A provider outage is the one outcome that leaves a live credential somewhere, and it has to be
    /// reported as itself rather than folded into either success or "already gone". The detail says
    /// <c>provider_refused</c> rather than <c>provider_unreachable</c> because the provider did answer
    /// — the distinction is what stops a reader hunting for an outage when the real cause was a
    /// rejected request.
    /// </summary>
    [Fact]
    public async Task GitHub_ReportsAnOutageAsUnreachableRatherThanAsRevoked()
    {
        await LinkGitHubAsync();
        _gitHub.RevocationStatus = HttpStatusCode.ServiceUnavailable;

        var report = await Service().RevokeAsync(_userId, OAuthProvider.GitHub, CancellationToken.None);

        Assert.Equal(RevocationOutcome.Unreachable, report.Outcome);
        Assert.False(report.GrantIsGone);
        Assert.Equal("provider_refused", report.Detail);
    }

    // --- Google -------------------------------------------------------------------------------------

    /// <summary>
    /// Google revokes by token and infers the grant from it, so <em>which</em> token is sent decides
    /// what actually happens. The refresh token is the credential the whole grant hangs from;
    /// revoking it takes the derived access tokens with it. Sending the access token instead would get
    /// a cheerful 200 and leave the grant able to mint another one — an unlink that undoes itself.
    /// </summary>
    [Fact]
    public async Task Google_RevokesTheRefreshTokenAndNotTheAccessToken()
    {
        await LinkGoogleAsync();

        var report = await Service().RevokeAsync(_userId, OAuthProvider.Google, CancellationToken.None);

        Assert.Equal(RevocationOutcome.Revoked, report.Outcome);
        Assert.Equal(1, _google.RevocationCalls);
        Assert.Equal(GoogleRefreshToken, _google.RevokedToken);
        Assert.NotEqual(GoogleAccessToken, _google.RevokedToken);
    }

    /// <summary>
    /// A link authorized without <c>access_type=offline</c> has no refresh token to revoke. Revoking
    /// the access token is worth doing and worth not overstating — it retires that one string.
    /// </summary>
    [Fact]
    public async Task Google_FallsBackToTheAccessTokenWhenThereIsNoRefreshToken()
    {
        await LinkGoogleAsync(refreshToken: null);

        var report = await Service().RevokeAsync(_userId, OAuthProvider.Google, CancellationToken.None);

        Assert.Equal(RevocationOutcome.Revoked, report.Outcome);
        Assert.Equal(GoogleAccessToken, _google.RevokedToken);
    }

    /// <summary>
    /// RFC 7009 says revoking an already-invalid token is a success; Google answers
    /// <c>400 invalid_token</c>. Reading the status code alone turns "this was already dead" into an
    /// outage, and the user is then told to go finish a revocation that had already happened.
    /// </summary>
    [Fact]
    public async Task Google_ReadsInvalidTokenOutOfA400RatherThanCallingItAnOutage()
    {
        await LinkGoogleAsync();
        _google.RevocationStatus = HttpStatusCode.BadRequest;

        var report = await Service().RevokeAsync(_userId, OAuthProvider.Google, CancellationToken.None);

        Assert.Equal(RevocationOutcome.AlreadyInvalid, report.Outcome);
        Assert.True(report.GrantIsGone);
    }

    /// <summary>
    /// The mirror of the above: a 400 that isn't about the token is not a dead grant. Answering
    /// <c>AlreadyInvalid</c> to <c>invalid_client</c> would report the grant as gone when this app's
    /// own credentials were the problem and the grant is untouched.
    /// </summary>
    [Fact]
    public async Task Google_DoesNotTreatAnyOld400AsAnAlreadyDeadToken()
    {
        await LinkGoogleAsync();
        _google.RevocationStatus = HttpStatusCode.BadRequest;
        _google.RevocationErrorBody = """{"error":"invalid_client"}""";

        var report = await Service().RevokeAsync(_userId, OAuthProvider.Google, CancellationToken.None);

        Assert.Equal(RevocationOutcome.Unreachable, report.Outcome);
        Assert.False(report.GrantIsGone);
    }

    /// <summary>
    /// <c>revocation_endpoint</c> is optional in OIDC Discovery. A provider that publishes none cannot
    /// be asked to revoke, and guessing a URL would report a success that never happened.
    /// </summary>
    [Fact]
    public async Task Google_ReportsUnsupportedWhenTheProviderPublishesNoRevocationEndpoint()
    {
        await LinkGoogleAsync();
        _google.OmitRevocationEndpoint = true;

        var report = await Service().RevokeAsync(_userId, OAuthProvider.Google, CancellationToken.None);

        Assert.Equal(RevocationOutcome.Unsupported, report.Outcome);
        Assert.False(report.GrantIsGone);
        Assert.Equal(0, _google.RevocationCalls);
    }

    // --- the invariants around the call --------------------------------------------------------------

    /// <summary>
    /// The invariant that makes revocation an explicit exception to "everything that spends a token
    /// goes through <c>ProviderTokenService</c>". Refreshing in order to revoke mints a credential for
    /// the sole purpose of destroying it, and with GitHub's rotation it spends the stored refresh token
    /// to do so — after which a revocation that failed at the transport level would leave the row
    /// holding a credential the provider had already retired and that can never be revoked.
    /// </summary>
    [Fact]
    public async Task Revocation_DoesNotRefreshFirstEvenWhenTheStoredTokenHasExpired()
    {
        await LinkGitHubAsync(expiresAtUtc: DateTimeOffset.UtcNow.AddMinutes(-30));

        var report = await Service().RevokeAsync(_userId, OAuthProvider.GitHub, CancellationToken.None);

        Assert.Equal(RevocationOutcome.Revoked, report.Outcome);

        // No refresh POST at all, and the expired token is the one that got sent.
        Assert.Equal(0, _gitHub.RefreshCount);
        Assert.Equal(GitHubAccessToken, _gitHub.RevokedToken);
    }

    /// <summary>
    /// A link already latched as needing re-authorization is the most likely one to be unlinked, and
    /// the token service would refuse to hand out a token for it at all — turning "this link is
    /// broken" into "you may not remove it". Revocation reads the row directly for that reason.
    /// </summary>
    [Fact]
    public async Task Revocation_StillAttemptsAGrantThatIsAlreadyLatchedAsBroken()
    {
        await LinkGitHubAsync();
        await _accounts.MarkReauthorizationRequiredAsync(_userId, OAuthProvider.GitHub, CancellationToken.None);

        var report = await Service().RevokeAsync(_userId, OAuthProvider.GitHub, CancellationToken.None);

        Assert.Equal(RevocationOutcome.Revoked, report.Outcome);
        Assert.Equal(1, _gitHub.RevocationCallCount);
    }

    /// <summary>
    /// Nothing stored, nothing to send — and no exception either, because the caller's next step
    /// (delete the row) is the same regardless.
    /// </summary>
    [Fact]
    public async Task Revocation_ReportsNothingToRevokeForAProviderThatWasNeverLinked()
    {
        var report = await Service().RevokeAsync(_userId, OAuthProvider.Google, CancellationToken.None);

        Assert.Equal(RevocationOutcome.NothingToRevoke, report.Outcome);
        Assert.Equal("not_linked", report.Detail);
        Assert.Equal(0, _google.RevocationCalls);
    }

    /// <summary>
    /// The local row goes even when the provider could not be reached. Keeping a token this app was
    /// told to discard, in order to preserve the ability to revoke it later, is the worse of the two
    /// failures — and it would leave a user unable to unlink for as long as the provider is down.
    /// </summary>
    [Fact]
    public async Task Unlink_DeletesTheLocalRowEvenWhenRevocationCouldNotBeCompleted()
    {
        await LinkGitHubAsync();
        _gitHub.RevocationStatus = HttpStatusCode.ServiceUnavailable;

        var report = await Service().RevokeAsync(_userId, OAuthProvider.GitHub, CancellationToken.None);
        var deleted = await _accounts.DeleteAsync(_userId, OAuthProvider.GitHub, CancellationToken.None);

        Assert.Equal(RevocationOutcome.Unreachable, report.Outcome);
        Assert.True(deleted);
        Assert.Empty(await _accounts.GetLinkStatesAsync(_userId, CancellationToken.None));
    }

    // --- harness ------------------------------------------------------------------------------------

    private ProviderRevocationService Service() => new(
        _accounts,
        new GitHubOAuthClient(
            new HttpClient(_gitHubHandler, disposeHandler: false),
            Options.Create(new GitHubOAuthOptions
            {
                ClientId = FakeGitHub.ClientId,
                ClientSecret = FakeGitHub.ClientSecret,
                RedirectUri = "https://localhost:7236/api/auth/github/callback",
            }),
            NullLogger<GitHubOAuthClient>.Instance),
        _google.CreateClient(),
        NullLogger<ProviderRevocationService>.Instance);

    /// <summary>Every request the GitHub stub saw, in order — the handler is shared across the test.</summary>
    private List<StubGitHubRequest> Requests() => [.. _gitHubHandler.Requests];

    private Task LinkGitHubAsync(DateTimeOffset? expiresAtUtc = null) =>
        _accounts.UpsertAsync(
            _userId,
            OAuthProvider.GitHub,
            new OAuthTokenResult(GitHubAccessToken, GitHubRefreshToken, "read:user", expiresAtUtc),
            new ProviderAccountInfo("583231", "octocat"),
            CancellationToken.None);

    private Task LinkGoogleAsync(string? refreshToken = GoogleRefreshToken) =>
        _accounts.UpsertAsync(
            _userId,
            OAuthProvider.Google,
            new OAuthTokenResult(GoogleAccessToken, refreshToken, "openid email profile", null),
            new ProviderAccountInfo(FakeGoogle.Subject, FakeGoogle.Email),
            CancellationToken.None);
}
