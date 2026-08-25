using System.Net;
using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using OAuthDashboard.Core.Accounts;
using OAuthDashboard.Core.Users;
using OAuthDashboard.Infrastructure.Accounts;
using OAuthDashboard.Infrastructure.Auth;
using OAuthDashboard.Infrastructure.Dashboard;
using OAuthDashboard.Infrastructure.Persistence;
using OAuthDashboard.Infrastructure.Security;

namespace OAuthDashboard.Tests;

/// <summary>
/// M5's aggregator: one request, every linked provider, and no single provider able to ruin the
/// answer.
/// </summary>
/// <remarks>
/// Runs against a real dependency-injection container rather than hand-constructed services, which is
/// the only way most of this is testable at all. The claim under test is partly <em>about</em> the
/// container — that each concurrent branch gets its own <c>DbContext</c> while sharing one
/// <c>RefreshLockRegistry</c> — and a test that wired the objects up by hand would be asserting
/// against its own wiring rather than the app's.
/// <para>
/// The database is a temp <b>file</b>, not SQLite's in-memory mode, for the same reason
/// <c>TokenRefreshTests</c> uses one: an in-memory database lives inside a single connection that every
/// context would have to share, and a shared connection is exactly what the concurrency assertions
/// here must not have.
/// </para>
/// </remarks>
public class DashboardAggregationTests : IAsyncLifetime
{
    private const string GitHubScopes = "read:user,read:org";
    private const string GoogleBaseScopes = "openid email profile";
    private const string GoogleCalendarScopes =
        "openid email profile https://www.googleapis.com/auth/calendar.events.readonly";

    private string _databasePath = null!;

    // One protector for the whole test, shared by every container built below. Separate
    // EphemeralDataProtectionProvider instances hold separate keys, so a second protector cannot read
    // what the first one wrote — it fails at Unprotect with a cryptographic error that looks nothing
    // like the problem it actually is.
    private TokenProtector _protector = null!;

    private FakeGitHub _gitHub = null!;
    private StubGitHubHandler _gitHubHandler = null!;
    private FakeGoogle _google = null!;
    private ServiceProvider _services = null!;
    private int _userId;

    public async Task InitializeAsync()
    {
        _databasePath = Path.Combine(Path.GetTempPath(), $"oauthdash-dashboard-tests-{Guid.NewGuid():N}.db");

        _protector = new TokenProtector(new EphemeralDataProtectionProvider());
        _gitHub = new FakeGitHub { AcceptedAccessToken = "gho_stored" };
        _gitHubHandler = new StubGitHubHandler(_gitHub.Respond);
        _google = new FakeGoogle { AcceptedAccessToken = "ya29.stored" };

        _services = BuildContainer(widgetTimeout: null);

        await using var scope = _services.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<DashboardDbContext>();
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
        await _services.DisposeAsync();
        _google.Dispose();
        _gitHubHandler.Dispose();

        // Pooled connections keep the file handle open on Windows, so the delete below fails silently
        // without this.
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

    // --- the happy path -----------------------------------------------------------------------------

    /// <summary>
    /// Both providers, every widget, one request. Also the test that would fail loudly if the fan-out
    /// shared one <c>DbContext</c> across branches: five concurrent widgets on one context is the
    /// "second operation started on this context" that EF Core refuses, and it would show up here as
    /// widgets reporting <c>unavailable</c> rather than as an obvious wiring error.
    /// </summary>
    [Fact]
    public async Task Build_RendersEveryProvidersWidgetsInOneResponse()
    {
        await LinkGitHubAsync();
        await LinkGoogleAsync(GoogleCalendarScopes);

        var response = await BuildAsync();

        Assert.Equal(DashboardWidgets.All.Count, response.Widgets.Count);
        Assert.All(response.Widgets, widget =>
            Assert.Equal(WidgetStatus.Ok, widget.Status));

        // Both providers really were called, rather than the whole thing being served from the link row.
        Assert.True(_gitHub.RepositoryCallCount > 0);
        Assert.True(_google.CalendarCalls > 0);
    }

    /// <summary>
    /// Provider-shaped responses arrive as one shape. This is what lets the SPA have a single renderer,
    /// and — more to the point — it is what keeps a hundred-field repository object and a calendar
    /// event's attendee list from being forwarded into the browser wholesale.
    /// </summary>
    [Fact]
    public async Task Build_NormalizesEveryProvidersDataIntoTheSameItemShape()
    {
        await LinkGitHubAsync();
        await LinkGoogleAsync(GoogleCalendarScopes);

        var response = await BuildAsync();

        var repo = Widget(response, "github.repositories").Items!.First();
        Assert.Equal("hello-world", repo.Title);
        Assert.Equal("My first repository", repo.Subtitle);
        Assert.Equal("C# · ★3", repo.Detail);
        Assert.NotNull(repo.TimestampUtc);

        var orgs = Widget(response, "github.organizations").Items!;
        Assert.Equal("acme-industries", orgs.Single().Title);

        var events = Widget(response, "google.calendar").Items!;
        Assert.Equal(2, events.Count);

        // A timed event keeps its instant; the all-day one is flagged rather than being given an
        // invented midnight, which would read as the previous evening anywhere west of Greenwich.
        Assert.False(events[0].IsDateOnly);
        Assert.Equal("Room 4", events[0].Subtitle);
        Assert.True(events[1].IsDateOnly);
        Assert.Equal(new DateTimeOffset(2026, 8, 28, 0, 0, 0, TimeSpan.Zero), events[1].TimestampUtc);
    }

    /// <summary>
    /// Nothing linked means five cards that say so, and — the part worth asserting — not one outbound
    /// request. Every provider call the dashboard can avoid is rate limit it does not spend to learn
    /// something the local row already knew.
    /// </summary>
    [Fact]
    public async Task Build_AnswersForEveryWidgetWithoutCallingAnyProviderWhenNothingIsLinked()
    {
        var response = await BuildAsync();

        Assert.All(response.Widgets, widget => Assert.Equal(WidgetStatus.NotLinked, widget.Status));
        Assert.Empty(_gitHubHandler.Requests);
        Assert.Empty(_google.Requests);
    }

    // --- isolation ----------------------------------------------------------------------------------

    /// <summary>
    /// The milestone's central claim. One provider failing costs one card — and note what
    /// <c>Task.WhenAll</c> would otherwise do here: surface the first exception and discard the rest,
    /// so a single GitHub outage would take the response down while hiding what Google said.
    /// </summary>
    [Fact]
    public async Task Build_IsolatesOneWidgetsFailureFromEveryOtherWidget()
    {
        await LinkGitHubAsync();
        await LinkGoogleAsync(GoogleCalendarScopes);

        _gitHub.RepositoriesEndpointStatus = HttpStatusCode.InternalServerError;

        var response = await BuildAsync();

        var broken = Widget(response, "github.repositories");
        Assert.Equal(WidgetStatus.Unavailable, broken.Status);
        Assert.Equal("provider_unreachable", broken.Reason);

        // The same provider's other widgets are fine, and so is the other provider entirely.
        Assert.Equal(WidgetStatus.Ok, Widget(response, "github.account").Status);
        Assert.Equal(WidgetStatus.Ok, Widget(response, "github.organizations").Status);
        Assert.Equal(WidgetStatus.Ok, Widget(response, "google.calendar").Status);
    }

    /// <summary>
    /// Isolation has to hold for a malformed <em>response</em>, not just a bad status code — a provider
    /// that changes a field's shape is the likelier event, and it arrives as an exception from the
    /// widget's own parsing rather than from HTTP.
    /// </summary>
    [Fact]
    public async Task Build_IsolatesAWidgetWhoseParsingThrows()
    {
        await LinkGitHubAsync();
        await LinkGoogleAsync(GoogleBaseScopes);

        // A repository object with no name at all: not a status code, not a network problem, just a
        // shape the widget's mapping cannot handle.
        _gitHub.RepositoriesJsonOverride = """[{"description":"no name here"}]""";

        var response = await BuildAsync();

        var broken = Widget(response, "github.repositories");
        Assert.Equal(WidgetStatus.Unavailable, broken.Status);
        Assert.Equal("widget_failed", broken.Reason);

        Assert.Equal(WidgetStatus.Ok, Widget(response, "github.account").Status);
        Assert.Equal(WidgetStatus.Ok, Widget(response, "google.account").Status);
    }

    /// <summary>
    /// A slow provider costs its own card and does not hold the page. Run with a deliberately tiny
    /// budget so the assertion is about the mechanism rather than about waiting ten seconds.
    /// </summary>
    [Fact]
    public async Task Build_TimesOutOneSlowWidgetWithoutLosingTheOthers()
    {
        await LinkGitHubAsync();
        await LinkGoogleAsync(GoogleCalendarScopes);

        _google.CalendarDelay = TimeSpan.FromSeconds(5);

        await using var services = BuildContainer(widgetTimeout: TimeSpan.FromMilliseconds(200));
        var response = await BuildAsync(services);

        var slow = Widget(response, "google.calendar");
        Assert.Equal(WidgetStatus.TimedOut, slow.Status);
        Assert.Equal("widget_timeout", slow.Reason);

        Assert.Equal(WidgetStatus.Ok, Widget(response, "google.account").Status);
        Assert.Equal(WidgetStatus.Ok, Widget(response, "github.repositories").Status);
    }

    // --- what gets decided without asking the provider -----------------------------------------------

    /// <summary>
    /// The least-privilege payoff. A widget whose scope was never granted is not an error and does not
    /// cost a request: it reports what it would need, why, and the key to ask for it by. The alternative
    /// — call the provider and translate the 403 — spends rate limit to be told something the stored
    /// scope string already said, and arrives as a status code that means several other things too.
    /// </summary>
    [Fact]
    public async Task Build_DoesNotCallTheProviderForAWidgetWhoseScopeWasNeverGranted()
    {
        await LinkGoogleAsync(GoogleBaseScopes);

        var response = await BuildAsync();

        var calendar = Widget(response, "google.calendar");
        Assert.Equal(WidgetStatus.ScopeRequired, calendar.Status);
        Assert.Equal("calendar", calendar.GrantKey);
        Assert.Equal("https://www.googleapis.com/auth/calendar.events.readonly", calendar.RequiredScope);
        Assert.False(string.IsNullOrWhiteSpace(calendar.ScopePurpose));

        Assert.Equal(0, _google.CalendarCalls);

        // The base-scope widget on the same link still works — enabling a widget is per-widget, and a
        // link is not "incomplete" for not having every scope.
        Assert.Equal(WidgetStatus.Ok, Widget(response, "google.account").Status);
    }

    /// <summary>
    /// M3's latch, read rather than rediscovered. A link known to be dead must not produce a provider
    /// call per widget on every page load: that is rate limit spent to learn nothing, and from the
    /// provider's side it looks like an application retrying rejected credentials in a loop.
    /// </summary>
    [Fact]
    public async Task Build_ReportsALatchedLinkWithoutCallingTheProviderAtAll()
    {
        await LinkGitHubAsync();
        await Accounts().MarkReauthorizationRequiredAsync(_userId, OAuthProvider.GitHub, CancellationToken.None);

        var response = await BuildAsync();

        Assert.All(
            response.Widgets.Where(w => w.Provider == nameof(OAuthProvider.GitHub)),
            widget => Assert.Equal(WidgetStatus.ReauthorizationRequired, widget.Status));

        Assert.Empty(_gitHubHandler.Requests);
    }

    /// <summary>
    /// The mirror case: the stored scope string says the grant is sufficient and the provider disagrees.
    /// That is a genuinely different state from "we never asked for the scope" — the reason travels so a
    /// card can distinguish "grant this" from "this API is not enabled for this application", which no
    /// amount of re-consenting fixes.
    /// </summary>
    [Theory]
    [InlineData("insufficientPermissions")]
    [InlineData("accessNotConfigured")]
    public async Task Build_ReportsPermissionDeniedWhenTheProviderRefusesADocumentedlySufficientGrant(string reason)
    {
        await LinkGoogleAsync(GoogleCalendarScopes);
        _google.CalendarForbiddenReason = reason;

        var response = await BuildAsync();

        var calendar = Widget(response, "google.calendar");
        Assert.Equal(WidgetStatus.PermissionDenied, calendar.Status);
        Assert.Equal(reason, calendar.Reason);

        // It was actually asked — this is the provider's answer, not a local decision.
        Assert.Equal(1, _google.CalendarCalls);
    }

    /// <summary>
    /// GitHub spends 403 on two unrelated things. A depleted rate limit is temporary and says nothing
    /// about permissions; treating it as a permission problem would tell the user to grant a scope they
    /// already granted, and treating a missing scope as a rate limit would suggest waiting for something
    /// that will never change.
    /// </summary>
    [Fact]
    public async Task Build_DistinguishesAMissingScopeFromADepletedRateLimit()
    {
        await LinkGitHubAsync();
        _gitHub.OrganizationsForbidden = true;

        var scopeProblem = Widget(await BuildAsync(), "github.organizations");
        Assert.Equal(WidgetStatus.PermissionDenied, scopeProblem.Status);
        Assert.Equal("insufficient_scope", scopeProblem.Reason);

        _gitHub.OrganizationsRateLimited = true;

        var rateLimited = Widget(await BuildAsync(), "github.organizations");
        Assert.Equal(WidgetStatus.Unavailable, rateLimited.Status);
        Assert.Equal("provider_unreachable", rateLimited.Reason);
    }

    // --- the concurrency M3 built the gate for -------------------------------------------------------

    /// <summary>
    /// The test this milestone exists to make possible. Three GitHub widgets load at once against a link
    /// whose access token has expired, so all three notice the same expiry at the same moment.
    /// </summary>
    /// <remarks>
    /// Without the singleton <c>RefreshLockRegistry</c>, all three would POST the same refresh token.
    /// GitHub rotates it, so two of them would be presenting a credential it had already retired —
    /// which is precisely the signal a provider reads as a stolen refresh token and answers by revoking
    /// the whole grant. The dashboard would log the user out of a provider nobody attacked.
    /// <para>
    /// M3 asserted this with three synthetic concurrent requests. This asserts it against the thing that
    /// actually causes it, and the number that carries it is <c>RefreshCount == 1</c>.
    /// </para>
    /// <para>
    /// <b>The delay has to be awaited rather than slept, or this test proves nothing.</b> A stub that
    /// blocks its calling thread also blocks the branch that was about to start, because
    /// <c>Task.WhenAll</c> over a <c>Select</c> only begins each branch when the previous one yields.
    /// Fully serialized, branch two reads an already-refreshed row and never refreshes — so
    /// <c>RefreshCount</c> is 1 whether the lock exists or not, and the assertion holds for the wrong
    /// reason. With the delay awaited, all three branches really are inside the refresh path at once.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task Build_RefreshesExactlyOnceForAllOfOneProvidersWidgets()
    {
        await LinkGitHubAsync(expiresAtUtc: DateTimeOffset.UtcNow.AddMinutes(-5));

        // Held long enough that the other two branches are genuinely queued on the gate rather than
        // arriving after the first one finished.
        _gitHubHandler.DelayFor = request =>
            request.IsTokenEndpoint ? TimeSpan.FromMilliseconds(250) : TimeSpan.Zero;

        var response = await BuildAsync();

        var gitHubWidgets = response.Widgets.Where(w => w.Provider == nameof(OAuthProvider.GitHub)).ToList();

        Assert.Equal(3, gitHubWidgets.Count);
        Assert.All(gitHubWidgets, widget => Assert.Equal(WidgetStatus.Ok, widget.Status));

        // One refresh POST, not three. This is the assertion the milestone rests on.
        Assert.Equal(1, _gitHub.RefreshCount);

        // At least one card reports the refresh — M3's observable, surfaced per widget. Not asserted
        // for all three, because the flag means "this call refreshed" rather than "a refresh happened
        // somewhere": a branch that reaches the row after the refresh has already been committed finds
        // a healthy token and correctly reports false. Which branches those are is a matter of timing,
        // and a test that pinned it down would be asserting on the scheduler.
        Assert.Contains(gitHubWidgets, widget => widget.Refreshed);
    }

    /// <summary>
    /// The reactive trigger, through the fan-out: the stored expiry looks healthy and the provider
    /// answers 401 anyway. Each widget's fetch has to be re-runnable for this to work, which is why the
    /// catalog holds a delegate rather than a pre-fetched result.
    /// </summary>
    [Fact]
    public async Task Build_RecoversFromAStoredTokenTheProviderRejectsDespiteItsRecordedExpiry()
    {
        await LinkGitHubAsync(expiresAtUtc: DateTimeOffset.UtcNow.AddHours(4));

        // The database believes the stored token is good for four more hours. GitHub disagrees.
        _gitHub.AcceptedAccessToken = "gho_something-else-entirely";

        var response = await BuildAsync();

        var gitHubWidgets = response.Widgets.Where(w => w.Provider == nameof(OAuthProvider.GitHub)).ToList();

        // Every card renders, and the recovery cost exactly one refresh across all three of them.
        Assert.All(gitHubWidgets, widget => Assert.Equal(WidgetStatus.Ok, widget.Status));
        Assert.Equal(1, _gitHub.RefreshCount);
        Assert.Contains(gitHubWidgets, widget => widget.Refreshed);
    }

    /// <summary>
    /// A dead grant discovered mid-fan-out latches once and reports M3's own reason on every card, so
    /// "reconnect" can be offered with an explanation rather than as a shrug.
    /// </summary>
    [Fact]
    public async Task Build_ReportsADeadGrantWithTheReasonM3Established()
    {
        await LinkGitHubAsync(expiresAtUtc: DateTimeOffset.UtcNow.AddMinutes(-5));
        _gitHub.RefreshError = "bad_refresh_token";

        var response = await BuildAsync();

        var gitHubWidgets = response.Widgets.Where(w => w.Provider == nameof(OAuthProvider.GitHub)).ToList();

        Assert.All(gitHubWidgets, widget =>
            Assert.Equal(WidgetStatus.ReauthorizationRequired, widget.Status));

        Assert.Contains(gitHubWidgets, widget => widget.Reason == "refresh_token_rejected");

        // The latch is now set, so a second load costs nothing at the provider.
        var before = _gitHubHandler.Requests.Count;
        await BuildAsync();
        Assert.Equal(before, _gitHubHandler.Requests.Count);
    }

    // --- the BFF boundary ---------------------------------------------------------------------------

    /// <summary>
    /// The invariant every milestone has to re-prove for its new response type: no token material
    /// crosses to the browser, not even ciphertext. Asserted against the serialized JSON rather than the
    /// object graph, because serialization is what actually leaves the process.
    /// </summary>
    [Fact]
    public async Task Build_KeepsEveryTokenVocabularyOutOfTheSerializedResponse()
    {
        await LinkGitHubAsync();
        await LinkGoogleAsync(GoogleCalendarScopes);

        var json = JsonSerializer.Serialize(await BuildAsync());

        foreach (var marker in new[] { "gho_", "ghr_", "ya29.", "1//", "CfDJ8" })
        {
            Assert.DoesNotContain(marker, json);
        }
    }

    // --- harness ------------------------------------------------------------------------------------

    /// <summary>
    /// The same object graph <c>Program.cs</c> builds, with the two providers' <c>HttpClient</c>s
    /// pointed at stub handlers. The lifetimes are the ones that matter and are copied deliberately:
    /// <c>DbContext</c> and the token service scoped, the lock registry and the discovery cache
    /// singletons.
    /// </summary>
    private ServiceProvider BuildContainer(TimeSpan? widgetTimeout)
    {
        var services = new ServiceCollection();

        services.AddSingleton<ILoggerFactory>(NullLoggerFactory.Instance);
        services.AddSingleton(typeof(ILogger<>), typeof(NullLogger<>));

        services.AddDbContext<DashboardDbContext>(options => options.UseSqlite($"Data Source={_databasePath}"));

        services.AddSingleton(_protector);
        services.AddScoped<LinkedAccountService>();

        // The singleton that makes concurrent refresh safe. Registered scoped, it would hand every
        // branch its own private mutex and the refresh-once assertion above would fail.
        services.AddSingleton<RefreshLockRegistry>();
        services.AddScoped<ProviderTokenService>();

        services.AddScoped(_ => new GitHubOAuthClient(
            new HttpClient(_gitHubHandler, disposeHandler: false),
            Options.Create(new GitHubOAuthOptions
            {
                ClientId = FakeGitHub.ClientId,
                ClientSecret = FakeGitHub.ClientSecret,
                RedirectUri = "https://localhost:7236/api/auth/github/callback",
            }),
            NullLogger<GitHubOAuthClient>.Instance));

        // One discovery cache for the whole container, as in production — scoped, it would refetch
        // Google's key set once per widget.
        services.AddSingleton(_ => _google.CreateDiscoveryCache());
        services.AddScoped(provider =>
            _google.CreateClient(provider.GetRequiredService<OpenIdConnectDiscoveryCache>()));
        services.AddScoped(_ => _google.CreateCalendarClient());

        if (widgetTimeout is null)
        {
            // Registered exactly the way Program.cs does it, which is the only way to find out that the
            // container can satisfy a constructor whose last parameter is an optional TimeSpan?. A test
            // that always used the explicit factory below would pass against a registration the running
            // app throws on at the first request.
            services.AddScoped<DashboardService>();
        }
        else
        {
            services.AddScoped(provider => new DashboardService(
                provider.GetRequiredService<IServiceScopeFactory>(),
                provider.GetRequiredService<LinkedAccountService>(),
                NullLogger<DashboardService>.Instance,
                widgetTimeout));
        }

        return services.BuildServiceProvider();
    }

    private Task<DashboardResponse> BuildAsync() => BuildAsync(_services);

    private async Task<DashboardResponse> BuildAsync(IServiceProvider services)
    {
        await using var scope = services.CreateAsyncScope();

        return await scope.ServiceProvider.GetRequiredService<DashboardService>()
            .BuildAsync(_userId, CancellationToken.None);
    }

    private static DashboardWidgetResult Widget(DashboardResponse response, string key) =>
        response.Widgets.Single(widget => widget.Key == key);

    /// <summary>A short-lived service on its own scope, for the arrange steps.</summary>
    private LinkedAccountService Accounts() =>
        _services.CreateScope().ServiceProvider.GetRequiredService<LinkedAccountService>();

    private Task LinkGitHubAsync(DateTimeOffset? expiresAtUtc = null) =>
        Accounts().UpsertAsync(
            _userId,
            OAuthProvider.GitHub,
            new OAuthTokenResult("gho_stored", "ghr_stored", GitHubScopes, expiresAtUtc),
            new ProviderAccountInfo("583231", "octocat"),
            CancellationToken.None);

    private Task LinkGoogleAsync(string scopes) =>
        Accounts().UpsertAsync(
            _userId,
            OAuthProvider.Google,
            new OAuthTokenResult("ya29.stored", "1//stored", scopes, DateTimeOffset.UtcNow.AddHours(1)),
            new ProviderAccountInfo(FakeGoogle.Subject, FakeGoogle.Email),
            CancellationToken.None);
}
