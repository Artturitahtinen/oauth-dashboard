namespace OAuthDashboard.Infrastructure.Dashboard;

/// <summary>
/// The states a widget can come back in. Strings rather than an enum because this crosses to the SPA
/// and a renumbering must not silently change what a card says.
/// </summary>
/// <remarks>
/// Every one of these is a <em>200</em> on the dashboard response. The HTTP status describes the
/// aggregation, not the providers: the request succeeded, and here is what each provider said.
/// Answering 409 because one of five widgets needs re-consent would make a working dashboard look
/// broken, and answering 200-with-no-explanation would make a broken widget look empty.
/// </remarks>
public static class WidgetStatus
{
    public const string Ok = "ok";

    /// <summary>The provider isn't linked at all. The remedy is "connect", not "reconnect".</summary>
    public const string NotLinked = "not_linked";

    /// <summary>M3's latch: the link is broken past what a refresh can fix.</summary>
    public const string ReauthorizationRequired = "reauthorization_required";

    /// <summary>
    /// The link is healthy and has never been granted the scope this widget needs. Not an error —
    /// it's the normal state of an opt-in widget, and the card is an invitation rather than a failure.
    /// </summary>
    public const string ScopeRequired = "scope_required";

    /// <summary>
    /// The provider accepted the token and refused the request anyway. Distinct from
    /// <see cref="ScopeRequired"/>, which is decided locally: this one is the provider disagreeing
    /// with what the stored scope string claims, or an API this app was never enabled for.
    /// </summary>
    public const string PermissionDenied = "permission_denied";

    /// <summary>The provider couldn't be reached, or answered with something unusable.</summary>
    public const string Unavailable = "unavailable";

    /// <summary>The provider was too slow, and the rest of the dashboard did not wait for it.</summary>
    public const string TimedOut = "timed_out";
}

/// <summary>
/// One row inside a widget, in the same shape whatever provider it came from.
/// </summary>
/// <remarks>
/// Normalizing here rather than in the SPA is the BFF earning its name twice over. Once for
/// simplicity — one renderer instead of one per provider. And once for exposure: a repository object
/// from GitHub has over a hundred fields and a calendar event carries attendee email addresses, and a
/// backend that forwards either verbatim has put all of it in the browser's memory, its network log,
/// and the reach of any script on the page. Five fields go out because five fields get drawn.
/// </remarks>
/// <param name="Title">The line the user reads first.</param>
/// <param name="Subtitle">Context: a description, a location, a login.</param>
/// <param name="Detail">A short trailing fact — a language, a star count.</param>
/// <param name="TimestampUtc">When this item happened or will, if that means anything for it.</param>
/// <param name="IsDateOnly">
/// True when <paramref name="TimestampUtc"/> is a calendar date with no meaningful time of day, so
/// the SPA renders "Thursday" instead of inventing a midnight.
/// </param>
/// <param name="Url">Where the user goes to see the real thing, if there is such a place.</param>
public record DashboardItem(
    string Title,
    string? Subtitle = null,
    string? Detail = null,
    DateTimeOffset? TimestampUtc = null,
    bool IsDateOnly = false,
    string? Url = null);

/// <param name="Key">Stable widget identifier, e.g. <c>github.repositories</c>.</param>
/// <param name="Status">One of <see cref="WidgetStatus"/>.</param>
/// <param name="Reason">
/// A machine-readable cause when the status is a failure — the same vocabulary M3 established
/// (<c>no_refresh_token</c>, <c>refresh_token_rejected</c>) plus this milestone's additions.
/// </param>
/// <param name="GrantKey">
/// On <see cref="WidgetStatus.ScopeRequired"/>, the key to pass as
/// <c>/api/auth/{provider}/authorize?grant=…</c>. The SPA is handed the key, not the scope, for the
/// same reason the endpoint only accepts a key.
/// </param>
/// <param name="RequiredScope">The scope that would be requested, shown so the ask isn't a mystery.</param>
/// <param name="ScopePurpose">Why this app wants it, in a sentence a user can weigh.</param>
/// <param name="Refreshed">
/// Whether serving this widget required the refresh grant. M3's observable, carried per widget — and
/// on a fan-out over an expired link, the field that shows one refresh served every widget.
/// </param>
public record DashboardWidgetResult(
    string Key,
    string Provider,
    string Title,
    string Status,
    string? Reason = null,
    string? GrantKey = null,
    string? RequiredScope = null,
    string? ScopePurpose = null,
    bool Refreshed = false,
    List<DashboardItem>? Items = null);

/// <param name="GeneratedAtUtc">
/// When the fan-out ran. Worth stating: a widget that reports <c>unavailable</c> is showing the state
/// of the world at this instant, not a cached failure.
/// </param>
public record DashboardResponse(DateTimeOffset GeneratedAtUtc, List<DashboardWidgetResult> Widgets);
