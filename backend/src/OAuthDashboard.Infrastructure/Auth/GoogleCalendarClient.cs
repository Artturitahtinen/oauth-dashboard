using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace OAuthDashboard.Infrastructure.Auth;

/// <summary>
/// Reads the next few events from the user's primary Google Calendar.
/// </summary>
/// <remarks>
/// <b>This is a resource server, and that is why it is a separate class.</b> Everything in
/// <see cref="GoogleOAuthClient"/> talks to the <em>authorization</em> server — the place that
/// issues, refreshes and revokes tokens, and that publishes where all of that lives in a discovery
/// document. Calendar is a different service that merely accepts those tokens, and OIDC Discovery
/// says nothing about it: the metadata contract covers identity endpoints, not APIs. So this URL is
/// a constant, and it has to be, which is worth knowing rather than discovering by grepping the
/// discovery document for something that was never going to be in it.
/// <para>
/// The practical consequence is that an access token is only as narrow as the scope it carries. This
/// client sends a token minted for <c>calendar.events.readonly</c>; the same token would be refused
/// by every other Google API, and that separation is the entire value of scoping a token rather than
/// issuing one credential that opens everything.
/// </para>
/// </remarks>
public class GoogleCalendarClient(HttpClient httpClient, ILogger<GoogleCalendarClient> logger)
{
    /// <summary>
    /// <c>primary</c> is the alias for whichever calendar is the account's own, so no calendar id has
    /// to be discovered or stored — which also means this client never needs the calendar-listing
    /// scope that discovering one would have required.
    /// </summary>
    private const string EventsEndpoint = "https://www.googleapis.com/calendar/v3/calendars/primary/events";

    public async Task<List<CalendarEvent>> GetUpcomingEventsAsync(string accessToken, int count, CancellationToken ct)
    {
        var query = string.Join('&', new[]
        {
            $"timeMin={Uri.EscapeDataString(DateTimeOffset.UtcNow.ToString("o"))}",
            $"maxResults={count}",

            // Both are required together to get what "the next few events" means. singleEvents
            // expands a recurring series into its individual occurrences — without it a weekly
            // standup arrives as one event dated whenever the series began — and orderBy=startTime is
            // only accepted once they are expanded, because an unexpanded series has no single start.
            "singleEvents=true",
            "orderBy=startTime",
        });

        using var request = new HttpRequestMessage(HttpMethod.Get, $"{EventsEndpoint}?{query}");
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

        using var response = await httpClient.SendAsync(request, ct);

        if (response.StatusCode == HttpStatusCode.Forbidden)
        {
            // A 403 here has two very different causes and only one of them is the user's to fix.
            // `insufficientPermissions` means the token lacks the calendar scope — re-consent helps.
            // `accessNotConfigured` means the Calendar API is not enabled on this app's Google Cloud
            // project — re-consenting a thousand times will not help, and telling the user to try is
            // worse than telling them nothing. So the reason is read out and carried up rather than
            // flattened into "forbidden".
            var body = await response.Content.ReadAsStringAsync(ct);
            var reason = ExtractReason(body);

            logger.LogWarning("Google Calendar refused the request ({Reason}).", reason ?? "no reason given");

            throw new ProviderPermissionException(reason);
        }

        // A 401 keeps its status so ProviderTokenService's reactive refresh trigger still sees it.
        response.EnsureSuccessStatusCode();

        var payload = await response.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);

        if (!payload.TryGetProperty("items", out var items) || items.ValueKind != JsonValueKind.Array)
        {
            return [];
        }

        return items.EnumerateArray().Select(ToEvent).ToList();
    }

    private static CalendarEvent ToEvent(JsonElement item)
    {
        var (startsAt, allDay) = ReadStart(item);

        return new CalendarEvent(
            // A calendar event with no summary is normal — Google renders it as "(No title)" — and a
            // null here would show up as an empty row rather than an event.
            Summary: OptionalString(item, "summary") ?? "(no title)",
            StartsAtUtc: startsAt,
            IsAllDay: allDay,
            Location: OptionalString(item, "location"),
            HtmlLink: OptionalString(item, "htmlLink"));
    }

    /// <summary>
    /// Reads the start of an event, which Google expresses in one of two mutually exclusive shapes.
    /// </summary>
    /// <remarks>
    /// A timed event carries <c>start.dateTime</c> (an RFC 3339 instant with an offset); an all-day
    /// event carries <c>start.date</c> (a bare calendar date, deliberately without a time zone,
    /// because "all day" means all day wherever the reader is). Parsing the second as an instant
    /// silently invents midnight UTC, which is the previous evening for anyone west of Greenwich —
    /// so the distinction is kept rather than normalized away.
    /// </remarks>
    private static (DateTimeOffset? StartsAt, bool AllDay) ReadStart(JsonElement item)
    {
        if (!item.TryGetProperty("start", out var start))
        {
            return (null, false);
        }

        if (DateTimeOffset.TryParse(OptionalString(start, "dateTime"), out var instant))
        {
            return (instant, false);
        }

        if (DateOnly.TryParse(OptionalString(start, "date"), out var date))
        {
            return (new DateTimeOffset(date.ToDateTime(TimeOnly.MinValue), TimeSpan.Zero), true);
        }

        return (null, false);
    }

    /// <summary>
    /// Pulls <c>error.errors[0].reason</c> out of a Google API error body without deserializing into
    /// a type. Best-effort by design: the reason improves the message and nothing depends on it.
    /// </summary>
    private static string? ExtractReason(string body)
    {
        try
        {
            using var document = JsonDocument.Parse(body);

            return document.RootElement.TryGetProperty("error", out var error)
                   && error.TryGetProperty("errors", out var errors)
                   && errors.ValueKind == JsonValueKind.Array
                   && errors.GetArrayLength() > 0
                ? OptionalString(errors[0], "reason")
                : null;
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string? OptionalString(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind is JsonValueKind.String
            ? value.GetString()
            : null;
}

/// <param name="IsAllDay">
/// True when the provider gave a date with no time. Carried rather than resolved because the widget
/// has to render it differently — "Thursday" is correct where "Thursday 00:00" is a fabrication.
/// </param>
public record CalendarEvent(
    string Summary,
    DateTimeOffset? StartsAtUtc,
    bool IsAllDay,
    string? Location,
    string? HtmlLink);

/// <summary>
/// The provider accepted the token and still refused the request: the scope is missing, or the API
/// is not enabled for this application at all.
/// </summary>
/// <remarks>
/// Kept apart from the M3 taxonomy on purpose. A 401 means "this credential is no good", which is
/// something a refresh can fix and <c>ProviderTokenService</c> knows how to try. A 403 means "this
/// credential is fine and is not allowed to do that", which no refresh can fix — retrying it is a
/// wasted request, and latching the link as needing re-authorization would be wrong too, since
/// everything else about the link still works.
/// </remarks>
public class ProviderPermissionException(string? reason)
    : Exception($"The provider refused the request: {reason ?? "no reason given"}")
{
    /// <summary>The provider's own reason code, when it gave one.</summary>
    public string? Reason { get; } = reason;
}
