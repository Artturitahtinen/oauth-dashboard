using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using OAuthDashboard.Core.Accounts;
using OAuthDashboard.Infrastructure.Auth;

namespace OAuthDashboard.Infrastructure.Dashboard;

/// <summary>
/// One panel on the dashboard: what it is called, which provider it reads, what permission it needs,
/// and how to fetch it given a usable access token.
/// </summary>
/// <param name="RequiredGrant">
/// The optional scope this widget cannot work without, or null if the base link already covers it.
/// This is the field that makes least privilege enforceable rather than aspirational: it is checked
/// against what the provider said it granted <em>before</em> any request goes out.
/// </param>
/// <param name="Fetch">
/// Runs inside <c>ProviderTokenService.CallAsync</c>, so it may be invoked twice — once with the
/// stored token and, if the provider answers 401, once more with a freshly refreshed one. It must
/// therefore be safe to repeat, which reading data is and which is worth noticing before something
/// with a side effect is ever put behind this delegate.
/// </param>
public record DashboardWidget(
    string Key,
    OAuthProvider Provider,
    string Title,
    OptionalScope? RequiredGrant,
    Func<IServiceProvider, string, CancellationToken, Task<List<DashboardItem>>> Fetch);

/// <summary>
/// The catalog. Adding a panel to the dashboard means adding an entry here and nothing else — the
/// fan-out, the per-widget failure isolation, the scope check and the refresh handling are all
/// generic over this list.
/// </summary>
/// <remarks>
/// Each widget resolves its own client out of the <see cref="IServiceProvider"/> it is handed, which
/// is the child scope <c>DashboardService</c> created for that branch. Closing over an injected
/// client instead would put every concurrent branch on one <c>DbContext</c>, which is the bug this
/// milestone's fan-out exists to not have.
/// </remarks>
public static class DashboardWidgets
{
    private const int RowsPerWidget = 5;

    public static readonly IReadOnlyList<DashboardWidget> All =
    [
        new DashboardWidget(
            "github.account",
            OAuthProvider.GitHub,
            "GitHub account",
            RequiredGrant: null,
            Fetch: async (services, token, ct) =>
            {
                var user = await services.GetRequiredService<GitHubOAuthClient>().GetUserJsonAsync(token, ct);

                // Three facts out of a response with several dozen fields. The rest — email, company,
                // plan, the URLs of eleven sub-resources — is read and dropped rather than forwarded,
                // because the card draws three lines.
                return
                [
                    new DashboardItem(
                        Title: String(user, "login") ?? "(unknown)",
                        Subtitle: String(user, "name"),
                        Detail: String(user, "html_url"),
                        Url: String(user, "html_url")),
                    new DashboardItem(
                        Title: $"{Number(user, "public_repos")} public repositories",
                        Subtitle: $"{Number(user, "followers")} followers"),
                ];
            }),

        new DashboardWidget(
            "github.repositories",
            OAuthProvider.GitHub,
            "Recently pushed repositories",

            // No optional grant, and that is the interesting part. Listing *public* repositories needs
            // nothing beyond the base read:user scope; seeing private ones would need `repo`, which is
            // read *and write* on everything and has no read-only counterpart for an OAuth App. The
            // widget is narrower than it could be because the permission that would widen it is much
            // wider than the widget. See ProviderScopes.GitHubBase.
            RequiredGrant: null,
            Fetch: async (services, token, ct) =>
            {
                var repos = await services.GetRequiredService<GitHubOAuthClient>()
                    .GetRecentRepositoriesAsync(token, RowsPerWidget, ct);

                return repos
                    .Select(repo => new DashboardItem(
                        Title: repo.Name,
                        Subtitle: repo.Description,
                        Detail: repo.Language is null ? null : $"{repo.Language} · ★{repo.StarCount}",
                        TimestampUtc: repo.PushedAtUtc,
                        Url: repo.HtmlUrl))
                    .ToList();
            }),

        new DashboardWidget(
            "github.organizations",
            OAuthProvider.GitHub,
            "Organizations",
            RequiredGrant: Grant("organizations"),
            Fetch: async (services, token, ct) =>
            {
                var orgs = await services.GetRequiredService<GitHubOAuthClient>().GetOrganizationsAsync(token, ct);

                return orgs
                    .Select(org => new DashboardItem(
                        Title: org.Login,
                        Subtitle: org.Description,
                        Url: org.HtmlUrl))
                    .ToList();
            }),

        new DashboardWidget(
            "google.account",
            OAuthProvider.Google,
            "Google account",
            RequiredGrant: null,
            Fetch: async (services, token, ct) =>
            {
                var user = await services.GetRequiredService<GoogleOAuthClient>().GetUserInfoJsonAsync(token, ct);

                var verified = user.TryGetProperty("email_verified", out var flag)
                               && flag.ValueKind == JsonValueKind.True;

                return
                [
                    new DashboardItem(
                        Title: String(user, "email") ?? String(user, "sub") ?? "(unknown)",
                        Subtitle: String(user, "name"),
                        // Shown because it changes what the address means. An unverified address from
                        // any provider is a string the user typed, and the reason M4's link is keyed
                        // on `sub` instead.
                        Detail: verified ? "email verified" : "email NOT verified"),
                ];
            }),

        new DashboardWidget(
            "google.calendar",
            OAuthProvider.Google,
            "Next up",
            RequiredGrant: Grant("calendar"),
            Fetch: async (services, token, ct) =>
            {
                var events = await services.GetRequiredService<GoogleCalendarClient>()
                    .GetUpcomingEventsAsync(token, RowsPerWidget, ct);

                return events
                    .Select(item => new DashboardItem(
                        Title: item.Summary,
                        Subtitle: item.Location,
                        TimestampUtc: item.StartsAtUtc,
                        IsDateOnly: item.IsAllDay,
                        Url: item.HtmlLink))
                    .ToList();
            }),
    ];

    /// <summary>
    /// Resolves an optional scope by key at startup rather than at request time, so a typo here is a
    /// crash on the first dashboard build instead of a widget that silently never asks for anything
    /// and reports <c>permission_denied</c> forever.
    /// </summary>
    private static OptionalScope Grant(string key) =>
        ProviderScopes.Optional.FirstOrDefault(scope => scope.Key == key)
        ?? throw new InvalidOperationException($"No optional scope is registered under the key '{key}'.");

    private static string? String(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind is JsonValueKind.String
            ? value.GetString()
            : null;

    private static int Number(JsonElement element, string property) =>
        element.TryGetProperty(property, out var value) && value.ValueKind is JsonValueKind.Number
            ? value.GetInt32()
            : 0;
}
