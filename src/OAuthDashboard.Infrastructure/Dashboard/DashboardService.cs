using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OAuthDashboard.Core.Accounts;
using OAuthDashboard.Infrastructure.Accounts;
using OAuthDashboard.Infrastructure.Auth;

namespace OAuthDashboard.Infrastructure.Dashboard;

/// <summary>
/// M5: one request that asks every linked provider for its part of the dashboard, concurrently, and
/// never lets one of them ruin the answer.
/// </summary>
/// <remarks>
/// <b>Per-widget isolation is the whole design, and <c>Task.WhenAll</c> is why it has to be
/// deliberate.</b> <c>WhenAll</c> surfaces the <em>first</em> exception its branches threw and
/// discards the rest, so an aggregator whose branches are allowed to throw doesn't just fail — it
/// fails while hiding what the other providers said. Every branch here converts its own failure into
/// a <see cref="DashboardWidgetResult"/> instead, which is what makes "GitHub is down, the calendar
/// still renders" true rather than aspirational.
/// <para>
/// <b>Each branch gets its own DI scope, and this is not a style choice.</b> <c>DbContext</c> is not
/// thread-safe, and everything the token path touches — <c>LinkedAccountService</c>,
/// <c>ProviderTokenService</c> — is scoped and shares the request's context. Fanning out five widgets
/// over one scope means five concurrent operations on one <c>DbContext</c>, which EF Core refuses
/// outright ("a second operation was started on this context"). So each widget runs in a child scope
/// with its own context. The lock registry stays a singleton across all of them, which is precisely
/// what keeps the next paragraph true.
/// </para>
/// <para>
/// <b>The fan-out is the scenario M3's rotation gate was built for.</b> Three GitHub widgets loading
/// at once against a link whose token expired five minutes ago is three concurrent requests all
/// noticing the same expiry. Without the per-(user, provider) gate, all three would POST the same
/// refresh token; GitHub rotates it, so two of them would be presenting a credential it had already
/// retired — which is exactly the signal a provider reads as a stolen refresh token and answers by
/// killing the grant. The dashboard would log the user out of a provider nobody attacked. With the
/// gate, one branch refreshes and the other two re-read the row and use its result. M3 predicted this
/// case in the abstract; M5 is the code that actually causes it.
/// </para>
/// <para>
/// <b>What is decided locally, before any request goes out.</b> Not linked, latched as needing
/// re-authorization, or missing the scope the widget needs — all three are answerable from the link
/// row, and all three are answered there. Spending a provider request to be told something the
/// database already knew costs rate limit to learn nothing, and in the scope case the provider's
/// answer would arrive as a 403 that looks like several other problems.
/// </para>
/// </remarks>
public class DashboardService(
    IServiceScopeFactory scopeFactory,
    LinkedAccountService accounts,
    ILogger<DashboardService> logger,
    TimeSpan? widgetTimeout = null)
{
    /// <summary>
    /// How long one widget may take before the dashboard stops waiting for it.
    /// </summary>
    /// <remarks>
    /// A per-widget budget rather than one for the whole request: the point of the fan-out is that a
    /// slow provider costs its own card and nothing else. Without this, the dashboard's latency is
    /// whatever the worst provider's is today, and a hung connection holds the request until the
    /// client gives up — which the user experiences as the entire dashboard being broken.
    /// <para>
    /// Overridable so the timeout can be tested from both sides without a test that takes ten
    /// seconds. Production never passes it — same arrangement as
    /// <c>OpenIdConnectDiscoveryCache</c>'s cache intervals.
    /// </para>
    /// </remarks>
    public static readonly TimeSpan DefaultWidgetTimeout = TimeSpan.FromSeconds(10);

    private readonly TimeSpan _widgetTimeout = widgetTimeout ?? DefaultWidgetTimeout;

    public async Task<DashboardResponse> BuildAsync(int userId, CancellationToken ct)
    {
        // Read once, sequentially, on the request's own DbContext — before any concurrency exists.
        var links = (await accounts.GetLinkStatesAsync(userId, ct))
            .ToDictionary(state => state.Provider);

        var widgets = await Task.WhenAll(DashboardWidgets.All.Select(
            widget => BuildWidgetAsync(userId, widget, links.GetValueOrDefault(widget.Provider), ct)));

        return new DashboardResponse(DateTimeOffset.UtcNow, [.. widgets]);
    }

    private async Task<DashboardWidgetResult> BuildWidgetAsync(
        int userId, DashboardWidget widget, LinkedAccountState? link, CancellationToken ct)
    {
        if (link is null)
        {
            return Empty(widget, WidgetStatus.NotLinked);
        }

        if (link.ReauthorizationRequired)
        {
            // M3's latch, read rather than rediscovered. The remedy is a consent screen, and no number
            // of dashboard loads will produce one.
            return Empty(widget, WidgetStatus.ReauthorizationRequired, "reauthorization_required");
        }

        if (widget.RequiredGrant is { } grant && !ProviderScopes.IsGranted(link.Scopes, grant.Scope))
        {
            // Not a failure — the ordinary resting state of an opt-in widget. The card carries the
            // grant key, the scope and the reason for wanting it, so the SPA can ask for exactly this
            // one permission instead of the user being sent back through a consent screen for
            // everything at once.
            return new DashboardWidgetResult(
                widget.Key,
                widget.Provider.ToString(),
                widget.Title,
                WidgetStatus.ScopeRequired,
                GrantKey: grant.Key,
                RequiredScope: grant.Scope,
                ScopePurpose: grant.Purpose);
        }

        // A child scope per branch: its own DbContext, its own LinkedAccountService, its own
        // ProviderTokenService. The RefreshLockRegistry behind them is the singleton every branch
        // shares, which is what serializes concurrent refreshes across these scopes.
        using var scope = scopeFactory.CreateScope();

        // Linked so a client that goes away still cancels the work, but with a budget of its own so a
        // slow provider is this widget's problem and not the dashboard's.
        using var budget = CancellationTokenSource.CreateLinkedTokenSource(ct);
        budget.CancelAfter(_widgetTimeout);

        try
        {
            var providerTokens = scope.ServiceProvider.GetRequiredService<ProviderTokenService>();

            // CallAsync, not GetAccessTokenAsync: the fetch has to be re-runnable so a 401 can be
            // answered by refreshing and trying the request again. The token never leaves this call.
            var result = await providerTokens.CallAsync(
                userId,
                widget.Provider,
                (accessToken, callCt) => widget.Fetch(scope.ServiceProvider, accessToken, callCt),
                budget.Token);

            return new DashboardWidgetResult(
                widget.Key,
                widget.Provider.ToString(),
                widget.Title,
                WidgetStatus.Ok,
                Refreshed: result.Refreshed,
                Items: result.Value);
        }
        catch (ProviderNotLinkedException)
        {
            // The link was there when the states were read and is not there now — an unlink landed
            // mid-fan-out. Reported as what it is rather than as an error.
            return Empty(widget, WidgetStatus.NotLinked);
        }
        catch (ReauthorizationRequiredException ex)
        {
            // Discovered during the call this time: the refresh was attempted and the grant turned out
            // to be dead. The reason is M3's vocabulary — no_refresh_token, refresh_token_rejected,
            // token_rejected_after_refresh — so the card can explain itself.
            return Empty(widget, WidgetStatus.ReauthorizationRequired, ex.Reason);
        }
        catch (ProviderPermissionException ex)
        {
            // The token was accepted and the request refused. Distinct from the scope check above,
            // which is local: reaching here means the stored scope string and the provider disagree,
            // or the API is not enabled for this app at all — which a re-consent would not fix.
            logger.LogWarning(
                "The provider refused {Widget} for user {UserId} despite an apparently sufficient grant ({Reason}).",
                widget.Key, userId, ex.Reason);

            return Empty(widget, WidgetStatus.PermissionDenied, ex.Reason ?? "forbidden");
        }
        catch (OperationCanceledException) when (!ct.IsCancellationRequested)
        {
            // Our budget fired, not the caller's. If the caller had cancelled, the guard is false and
            // this propagates — there is no dashboard left to render for a request nobody is waiting
            // on, and swallowing it would turn a cancelled request into a page full of timeouts.
            logger.LogWarning("{Widget} for user {UserId} exceeded its {Timeout}s budget.",
                widget.Key, userId, _widgetTimeout.TotalSeconds);

            return Empty(widget, WidgetStatus.TimedOut, "widget_timeout");
        }
        catch (HttpRequestException ex)
        {
            logger.LogWarning(ex, "{Widget} for user {UserId} could not be loaded from the provider.", widget.Key, userId);
            return Empty(widget, WidgetStatus.Unavailable, "provider_unreachable");
        }
        catch (OpenIdConnectDiscoveryException ex)
        {
            logger.LogWarning(ex, "{Widget} for user {UserId} could not resolve the provider's metadata.", widget.Key, userId);
            return Empty(widget, WidgetStatus.Unavailable, "provider_metadata_unavailable");
        }
        catch (Exception ex)
        {
            // A deliberate catch-all — one of only two in this codebase that convert an unexpected
            // failure into a reported outcome rather than rethrowing it as a typed one (the other is
            // ProviderRevocationService's unreadable-credentials path). A provider that
            // changes a field's type, a null where the shape promised a string — anything unhandled in
            // one widget's parsing must cost that widget and not the page. Logged at Error precisely
            // because this branch also catches genuine bugs, and a bug that only shows up as a grey
            // card is a bug nobody fixes.
            logger.LogError(ex, "{Widget} for user {UserId} failed unexpectedly.", widget.Key, userId);
            return Empty(widget, WidgetStatus.Unavailable, "widget_failed");
        }
    }

    private static DashboardWidgetResult Empty(DashboardWidget widget, string status, string? reason = null) =>
        new(widget.Key,
            widget.Provider.ToString(),
            widget.Title,
            status,
            Reason: reason,
            // Carried even on a failure: a widget the user has never granted the scope for should
            // still be able to say what it would ask for, whatever else went wrong.
            GrantKey: widget.RequiredGrant?.Key,
            RequiredScope: widget.RequiredGrant?.Scope,
            ScopePurpose: widget.RequiredGrant?.Purpose);
}
