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
/// M3's actual claim: a linked account keeps working after its access token expires, without the
/// user going near a consent screen — and when it genuinely can't, the app says so instead of
/// retrying forever.
/// </summary>
/// <remarks>
/// Runs against real SQLite and a stubbed github.com, with a fresh <see cref="DashboardDbContext"/>
/// per simulated request. The per-request context is not incidental: it's what makes the
/// concurrency test mean anything, since in the running app each request gets its own scope and two
/// requests really can be mid-refresh at the same time.
/// </remarks>
public class TokenRefreshTests : IAsyncLifetime
{
    private const string OriginalAccessToken = "gho_original";
    private const string OriginalRefreshToken = "ghr_original";

    // A temp file rather than the in-memory database the M2 tests use, because a SQLite in-memory
    // database lives inside a single connection that every context would then have to share — and a
    // shared connection is exactly what the concurrency test below must not have. Backed by a file,
    // each simulated request opens its own connection, like the real app.
    private string _databasePath = null!;
    private string _connectionString = null!;
    private TokenProtector _protector = null!;
    private RefreshLockRegistry _locks = null!;
    private FakeGitHub _gitHub = null!;
    private GitHubOAuthClient _client = null!;
    private readonly List<DashboardDbContext> _contexts = [];
    private int _userId;

    public async Task InitializeAsync()
    {
        _databasePath = Path.Combine(Path.GetTempPath(), $"oauthdash-refresh-tests-{Guid.NewGuid():N}.db");
        _connectionString = $"Data Source={_databasePath}";

        // One protector across every context: separate EphemeralDataProtectionProvider instances
        // hold separate keys, so a per-context protector could not read what another one wrote.
        _protector = new TokenProtector(new EphemeralDataProtectionProvider());
        _locks = new RefreshLockRegistry();
        _gitHub = new FakeGitHub();

        _client = new GitHubOAuthClient(
            new HttpClient(new StubGitHubHandler(_gitHub.Respond)),
            Options.Create(new GitHubOAuthOptions
            {
                ClientId = "test-client-id",
                ClientSecret = "test-client-secret",
                RedirectUri = "https://localhost:7236/api/auth/github/callback",
            }),
            NullLogger<GitHubOAuthClient>.Instance);

        var db = NewContext();
        await db.Database.EnsureCreatedAsync();

        var user = new User
        {
            Username = "tester",
            PasswordHash = PasswordHasher.Hash("a-long-enough-password"),
            CreatedAtUtc = DateTimeOffset.UtcNow,
        };
        db.Users.Add(user);
        await db.SaveChangesAsync();
        _userId = user.Id;
    }

    public async Task DisposeAsync()
    {
        foreach (var context in _contexts)
        {
            await context.DisposeAsync();
        }

        // Pooled connections keep the file handle open on Windows, so the delete below fails
        // silently without this.
        SqliteConnection.ClearAllPools();

        try
        {
            File.Delete(_databasePath);
        }
        catch (IOException)
        {
            // A leftover temp file is not worth failing a green test run over.
        }
    }

    /// <summary>
    /// The GitHub OAuth App case, and the one that must not regress: no advertised expiry means the
    /// token is good indefinitely. Refreshing here would be wrong twice over — there is no refresh
    /// token to do it with, so "refresh anything without an expiry" would turn every working link
    /// into a demand to re-consent.
    /// </summary>
    [Fact]
    public async Task GetAccessTokenAsync_DoesNotRefreshATokenWithNoAdvertisedExpiry()
    {
        await LinkAsync(expiresAtUtc: null, refreshToken: null);

        var token = await CreateService().GetAccessTokenAsync(_userId, OAuthProvider.GitHub, CancellationToken.None);

        Assert.Equal(OriginalAccessToken, token.Value);
        Assert.False(token.Refreshed);
        Assert.Equal(0, _gitHub.RefreshCount);
    }

    [Fact]
    public async Task GetAccessTokenAsync_DoesNotRefreshATokenThatIsStillComfortablyValid()
    {
        await LinkAsync(expiresAtUtc: DateTimeOffset.UtcNow.AddHours(4));

        var token = await CreateService().GetAccessTokenAsync(_userId, OAuthProvider.GitHub, CancellationToken.None);

        Assert.Equal(OriginalAccessToken, token.Value);
        Assert.False(token.Refreshed);
        Assert.Equal(0, _gitHub.RefreshCount);
    }

    /// <summary>
    /// The proactive trigger. The token here has not expired — it expires in seconds — and a naive
    /// <c>ExpiresAtUtc &gt; UtcNow</c> check would happily send it, only for it to die in flight.
    /// </summary>
    [Fact]
    public async Task GetAccessTokenAsync_RefreshesATokenInsideTheExpiryLeeway()
    {
        await LinkAsync(expiresAtUtc: DateTimeOffset.UtcNow + ProviderTokenService.ExpiryLeeway - TimeSpan.FromSeconds(10));

        var token = await CreateService().GetAccessTokenAsync(_userId, OAuthProvider.GitHub, CancellationToken.None);

        Assert.Equal("gho_refreshed", token.Value);
        Assert.True(token.Refreshed);
        Assert.Equal(1, _gitHub.RefreshCount);
    }

    /// <summary>
    /// The refreshed token has to reach SQLite, and so does the rotated refresh token — GitHub
    /// retired the old one the moment it answered, so a refresh that isn't persisted has traded a
    /// working credential for one the provider will now refuse.
    /// </summary>
    [Fact]
    public async Task GetAccessTokenAsync_PersistsBothTheNewAccessTokenAndTheRotatedRefreshToken()
    {
        await LinkAsync(expiresAtUtc: DateTimeOffset.UtcNow.AddMinutes(-1));

        await CreateService().GetAccessTokenAsync(_userId, OAuthProvider.GitHub, CancellationToken.None);

        var stored = await Accounts().GetTokenStateAsync(_userId, OAuthProvider.GitHub, CancellationToken.None);
        Assert.NotNull(stored);
        Assert.Equal("gho_refreshed", stored.AccessToken);
        Assert.Equal("ghr_rotated", stored.RefreshToken);
        Assert.NotNull(stored.ExpiresAtUtc);
        Assert.True(stored.ExpiresAtUtc > DateTimeOffset.UtcNow.AddHours(1));
    }

    /// <summary>
    /// A refresh is not a re-link. The consent that established this grant happened once, and
    /// <c>ObtainedAtUtc</c> has to keep pointing at it — otherwise "how old is this authorization"
    /// becomes unanswerable, and the refresh-token expiry that hangs off it looks perpetually fresh.
    /// </summary>
    [Fact]
    public async Task GetAccessTokenAsync_RecordsTheRefreshWithoutDisturbingTheOriginalGrantTimestamp()
    {
        var linkedAt = DateTimeOffset.UtcNow.AddDays(-30);
        await LinkAsync(expiresAtUtc: DateTimeOffset.UtcNow.AddMinutes(-1), obtainedAtUtc: linkedAt);

        await CreateService().GetAccessTokenAsync(_userId, OAuthProvider.GitHub, CancellationToken.None);

        var summary = Assert.Single(await Accounts().GetSummariesAsync(_userId, CancellationToken.None));
        Assert.Equal(linkedAt.ToUnixTimeSeconds(), summary.ObtainedAtUtc.ToUnixTimeSeconds());
        Assert.NotNull(summary.RefreshedAtUtc);
        Assert.True(summary.RefreshedAtUtc > DateTimeOffset.UtcNow.AddMinutes(-1));
    }

    /// <summary>
    /// The reactive trigger. Stored metadata says this token is valid for hours; GitHub says
    /// otherwise, which is what a revocation from the user's settings page looks like from here.
    /// Proactive expiry checking alone cannot see this coming.
    /// </summary>
    [Fact]
    public async Task CallAsync_RefreshesAndRetriesWhenTheProviderRejectsASupposedlyValidToken()
    {
        await LinkAsync(expiresAtUtc: DateTimeOffset.UtcNow.AddHours(4));
        _gitHub.AcceptedAccessToken = "nothing-matches-this";

        var result = await CreateService().CallAsync(
            _userId, OAuthProvider.GitHub, _client.GetAuthenticatedUserAsync, CancellationToken.None);

        Assert.Equal("octocat", result.Value.DisplayName);
        Assert.True(result.Refreshed);
        Assert.Equal(1, _gitHub.RefreshCount);
    }

    /// <summary>
    /// The dead-refresh-token path: nothing is left to try, so the link is latched as needing a
    /// fresh authorization rather than retried on every future request.
    /// </summary>
    [Fact]
    public async Task GetAccessTokenAsync_LatchesTheLinkWhenTheRefreshTokenIsRejected()
    {
        await LinkAsync(expiresAtUtc: DateTimeOffset.UtcNow.AddMinutes(-1));
        _gitHub.RefreshError = "bad_refresh_token";

        var ex = await Assert.ThrowsAsync<ReauthorizationRequiredException>(
            () => CreateService().GetAccessTokenAsync(_userId, OAuthProvider.GitHub, CancellationToken.None));

        Assert.Equal("refresh_token_rejected", ex.Reason);

        var summary = Assert.Single(await Accounts().GetSummariesAsync(_userId, CancellationToken.None));
        Assert.True(summary.ReauthorizationRequired);
    }

    /// <summary>
    /// Once latched, the grant is not re-attempted. Rediscovering the same rejection on every page
    /// load would spend provider rate limit to learn nothing, and each attempt is one more chance to
    /// look like credential stuffing.
    /// </summary>
    [Fact]
    public async Task GetAccessTokenAsync_StopsCallingTheProviderOnceTheLinkIsLatched()
    {
        await LinkAsync(expiresAtUtc: DateTimeOffset.UtcNow.AddMinutes(-1));
        _gitHub.RefreshError = "bad_refresh_token";

        await Assert.ThrowsAsync<ReauthorizationRequiredException>(
            () => CreateService().GetAccessTokenAsync(_userId, OAuthProvider.GitHub, CancellationToken.None));

        var afterFirstAttempt = _gitHub.RefreshCount;

        await Assert.ThrowsAsync<ReauthorizationRequiredException>(
            () => CreateService().GetAccessTokenAsync(_userId, OAuthProvider.GitHub, CancellationToken.None));

        Assert.Equal(afterFirstAttempt, _gitHub.RefreshCount);
    }

    /// <summary>
    /// An expired token and no refresh token is not an error to swallow — it's the same dead end,
    /// reached without the provider having to say anything. This is where a GitHub OAuth App link
    /// lands once its token is revoked.
    /// </summary>
    [Fact]
    public async Task GetAccessTokenAsync_RequiresReauthorizationWhenThereIsNoRefreshTokenToUse()
    {
        await LinkAsync(expiresAtUtc: DateTimeOffset.UtcNow.AddMinutes(-1), refreshToken: null);

        var ex = await Assert.ThrowsAsync<ReauthorizationRequiredException>(
            () => CreateService().GetAccessTokenAsync(_userId, OAuthProvider.GitHub, CancellationToken.None));

        Assert.Equal("no_refresh_token", ex.Reason);
        Assert.Equal(0, _gitHub.RefreshCount);
    }

    /// <summary>
    /// A token minted seconds ago and refused immediately means the refresh succeeded against a
    /// grant that no longer authorizes anything. Retrying past this point is a loop, so it stops.
    /// </summary>
    [Fact]
    public async Task CallAsync_GivesUpAfterExactlyOneRetry()
    {
        await LinkAsync(expiresAtUtc: DateTimeOffset.UtcNow.AddHours(4));
        _gitHub.AcceptedAccessToken = "nothing-matches-this";
        _gitHub.AcceptRefreshedTokens = false;

        var ex = await Assert.ThrowsAsync<ReauthorizationRequiredException>(
            () => CreateService().CallAsync(
                _userId, OAuthProvider.GitHub, _client.GetAuthenticatedUserAsync, CancellationToken.None));

        Assert.Equal("token_rejected_after_refresh", ex.Reason);
        Assert.Equal(1, _gitHub.RefreshCount);
        Assert.Equal(2, _gitHub.UserCallCount);
    }

    /// <summary>
    /// When the proactive path already replaced the token and the provider refuses it anyway, the
    /// grant behind it is dead. Refreshing a second time would spend another rotation to obtain
    /// another token from the same dead grant, so it doesn't.
    /// </summary>
    [Fact]
    public async Task CallAsync_DoesNotRefreshTwiceWhenAFreshlyRefreshedTokenIsRejected()
    {
        await LinkAsync(expiresAtUtc: DateTimeOffset.UtcNow.AddMinutes(-1));
        _gitHub.AcceptRefreshedTokens = false;

        var ex = await Assert.ThrowsAsync<ReauthorizationRequiredException>(
            () => CreateService().CallAsync(
                _userId, OAuthProvider.GitHub, _client.GetAuthenticatedUserAsync, CancellationToken.None));

        Assert.Equal("token_rejected_after_refresh", ex.Reason);
        Assert.Equal(1, _gitHub.RefreshCount);
        Assert.Equal(1, _gitHub.UserCallCount);
    }

    /// <summary>
    /// A provider that is merely unreachable must not be mistaken for a broken link. The remedy for
    /// a 503 is to try again later; telling the user to re-authorize would be advice that can't help.
    /// </summary>
    [Fact]
    public async Task CallAsync_LetsATransportFailureThroughWithoutBreakingTheLink()
    {
        await LinkAsync(expiresAtUtc: DateTimeOffset.UtcNow.AddHours(4));
        _gitHub.UserEndpointStatus = HttpStatusCode.ServiceUnavailable;

        await Assert.ThrowsAsync<HttpRequestException>(
            () => CreateService().CallAsync(
                _userId, OAuthProvider.GitHub, _client.GetAuthenticatedUserAsync, CancellationToken.None));

        var summary = Assert.Single(await Accounts().GetSummariesAsync(_userId, CancellationToken.None));
        Assert.False(summary.ReauthorizationRequired);
        Assert.Equal(0, _gitHub.RefreshCount);
    }

    /// <summary>
    /// The race this milestone can lose quietly. Several widgets loading at once all notice the same
    /// expired token; because the refresh token rotates, a second POST would present a credential
    /// the provider just retired — which providers treat as a replayed token and answer by killing
    /// the whole grant. One refresh, and everyone else uses its result.
    /// </summary>
    [Fact]
    public async Task GetAccessTokenAsync_RefreshesOnlyOnceWhenSeveralRequestsRaceForTheSameLink()
    {
        await LinkAsync(expiresAtUtc: DateTimeOffset.UtcNow.AddMinutes(-1));
        _gitHub.RefreshDelay = TimeSpan.FromMilliseconds(100);

        // Each task gets its own service and DbContext, exactly as separate requests would.
        var services = Enumerable.Range(0, 5).Select(_ => CreateService()).ToList();
        var tokens = await Task.WhenAll(services.Select(service => Task.Run(() =>
            service.GetAccessTokenAsync(_userId, OAuthProvider.GitHub, CancellationToken.None))));

        Assert.Equal(1, _gitHub.RefreshCount);
        Assert.All(tokens, token => Assert.Equal("gho_refreshed", token.Value));
    }

    [Fact]
    public async Task GetAccessTokenAsync_ReportsAnUnlinkedProviderAsDistinctFromABrokenOne()
    {
        await LinkAsync(expiresAtUtc: null);

        await Assert.ThrowsAsync<ProviderNotLinkedException>(
            () => CreateService().GetAccessTokenAsync(_userId, OAuthProvider.Google, CancellationToken.None));
    }

    /// <summary>
    /// Re-linking is the only thing that clears the latch, and it has to actually clear it —
    /// otherwise the user completes a consent screen and the dashboard still shows "Reconnect".
    /// </summary>
    [Fact]
    public async Task UpsertAsync_ClearsTheReauthorizationLatchOnAFreshConsent()
    {
        await LinkAsync(expiresAtUtc: DateTimeOffset.UtcNow.AddMinutes(-1));
        _gitHub.RefreshError = "bad_refresh_token";

        await Assert.ThrowsAsync<ReauthorizationRequiredException>(
            () => CreateService().GetAccessTokenAsync(_userId, OAuthProvider.GitHub, CancellationToken.None));

        await LinkAsync(expiresAtUtc: DateTimeOffset.UtcNow.AddHours(8));

        var summary = Assert.Single(await Accounts().GetSummariesAsync(_userId, CancellationToken.None));
        Assert.False(summary.ReauthorizationRequired);
        Assert.Null(summary.RefreshedAtUtc);
    }

    /// <summary>
    /// The BFF boundary has to survive the new fields: M3 added several, and a token accidentally
    /// among them would ship straight to the browser.
    /// </summary>
    [Fact]
    public async Task GetSummariesAsync_StillExposesNoTokenMaterialAfterARefresh()
    {
        await LinkAsync(expiresAtUtc: DateTimeOffset.UtcNow.AddMinutes(-1));
        await CreateService().GetAccessTokenAsync(_userId, OAuthProvider.GitHub, CancellationToken.None);

        var summary = Assert.Single(await Accounts().GetSummariesAsync(_userId, CancellationToken.None));
        var serialized = System.Text.Json.JsonSerializer.Serialize(summary);

        Assert.DoesNotContain("gho_", serialized, StringComparison.Ordinal);
        Assert.DoesNotContain("ghr_", serialized, StringComparison.Ordinal);
        Assert.True(summary.CanRefresh);
    }

    // --- fixture plumbing -----------------------------------------------------------------------

    private DashboardDbContext NewContext()
    {
        var context = new DashboardDbContext(
            new DbContextOptionsBuilder<DashboardDbContext>().UseSqlite(_connectionString).Options);

        _contexts.Add(context);
        return context;
    }

    private LinkedAccountService Accounts() => new(NewContext(), _protector);

    private ProviderTokenService CreateService() => new(
        Accounts(), _client, _locks, NullLogger<ProviderTokenService>.Instance);

    private async Task LinkAsync(
        DateTimeOffset? expiresAtUtc,
        string? refreshToken = OriginalRefreshToken,
        DateTimeOffset? obtainedAtUtc = null)
    {
        var accounts = Accounts();
        await accounts.UpsertAsync(
            _userId,
            OAuthProvider.GitHub,
            new OAuthTokenResult(OriginalAccessToken, refreshToken, "read:user", expiresAtUtc),
            new ProviderAccountInfo("583231", "octocat"),
            CancellationToken.None);

        if (obtainedAtUtc is not null)
        {
            var db = NewContext();
            var row = await db.LinkedAccounts.SingleAsync(a => a.UserId == _userId);
            row.ObtainedAtUtc = obtainedAtUtc.Value;
            await db.SaveChangesAsync();
        }

        _gitHub.AcceptedAccessToken = OriginalAccessToken;
    }

    /// <summary>
    /// A github.com that behaves the way the real one does in the ways that matter here: it accepts
    /// exactly one access token at a time, rotates the refresh token on every refresh, and reports
    /// OAuth failures as HTTP 200 with an error in the body.
    /// </summary>
    private sealed class FakeGitHub
    {
        private int _refreshCount;
        private int _userCallCount;

        public string AcceptedAccessToken { get; set; } = "";

        /// <summary>Set to make the refresh grant fail with this error code.</summary>
        public string? RefreshError { get; set; }

        /// <summary>When false, even a freshly minted token is refused — a grant revoked mid-flight.</summary>
        public bool AcceptRefreshedTokens { get; set; } = true;

        public HttpStatusCode? UserEndpointStatus { get; set; }

        public TimeSpan RefreshDelay { get; set; }

        public int RefreshCount => Volatile.Read(ref _refreshCount);

        public int UserCallCount => Volatile.Read(ref _userCallCount);

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

            Interlocked.Increment(ref _userCallCount);

            if (UserEndpointStatus is { } status)
            {
                return StubGitHubHandler.Status(status);
            }

            return request.AccessToken == AcceptedAccessToken
                ? StubGitHubHandler.Json("""{"id":583231,"login":"octocat"}""")
                : StubGitHubHandler.Status(HttpStatusCode.Unauthorized);
        }
    }
}
