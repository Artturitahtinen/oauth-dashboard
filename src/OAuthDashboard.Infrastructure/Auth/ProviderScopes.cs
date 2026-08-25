using OAuthDashboard.Core.Accounts;

namespace OAuthDashboard.Infrastructure.Auth;

/// <summary>
/// One optional permission a widget needs, and the key the SPA asks for it by.
/// </summary>
/// <param name="Key">
/// What a request is allowed to name. Short, provider-scoped, and meaningless to the provider.
/// </param>
/// <param name="Scope">The actual scope string sent to the provider. Never supplied by a caller.</param>
/// <param name="Purpose">
/// Why this app wants it, in words a consent screen's worth of context can be built from. Written
/// down next to the scope because "we asked for calendar access" and "we asked for calendar access
/// in order to list your next five events" are different requests to a user, and only one of them
/// can be checked against what the code actually does.
/// </param>
public record OptionalScope(string Key, OAuthProvider Provider, string Scope, string Purpose);

/// <summary>
/// M5's least-privilege seam: which scopes a link starts with, which ones individual widgets add,
/// and what a caller is allowed to ask for.
/// </summary>
/// <remarks>
/// <b>The base scopes are the ones a link cannot exist without</b> — GitHub's <c>read:user</c> to
/// put a name on the connection card, Google's <c>openid email profile</c> to get an
/// <c>id_token</c> at all. Everything past that is a widget's business and is asked for when that
/// widget is enabled, which is the entire content of the phrase "least privilege" here. The
/// alternative — front-loading every scope the dashboard might one day want into the first consent
/// screen — is how users learn that consent screens are a button you click past.
/// <para>
/// <b>A request names a key, never a scope.</b> <see cref="TryResolve"/> is an allowlist lookup, and
/// that is the whole reason it exists: <c>/authorize?scope=repo,admin:org</c> on an authenticated
/// endpoint is a privilege-escalation primitive handed to anyone who can get the user's browser to
/// follow a link, while <c>/authorize?grant=organizations</c> can only ever produce a scope this
/// code already decided to ask for. The provider would happily honour either one.
/// </para>
/// <para>
/// <b>Neither provider lets a grant be narrowed by re-authorizing.</b> GitHub unions the new scopes
/// into the existing authorization and never removes any; Google keeps every scope the user has ever
/// granted this client. So the only way back down is revocation — which is the other half of M5, and
/// not a coincidence: "ask for less later" is only a real option if "give it all back" exists.
/// </para>
/// </remarks>
public static class ProviderScopes
{
    /// <summary>
    /// GitHub: the minimum needed to read the profile the connection card shows.
    /// </summary>
    /// <remarks>
    /// Notably absent: <c>repo</c>. The repositories widget lists public repositories, which needs no
    /// scope beyond this, and GitHub's <c>repo</c> scope is not a read-only upgrade — it is full
    /// read <em>and write</em> on every private repository the user can reach, with no narrower
    /// alternative available to an OAuth App. Asking for write access to everything in order to
    /// render a five-row list is the exact trade least privilege exists to refuse, so the widget is
    /// public-only instead and the limitation is stated on the card rather than bought out with a
    /// scope.
    /// </remarks>
    public const string GitHubBase = "read:user";

    /// <summary>
    /// Google: <c>openid</c> is what makes this OIDC rather than OAuth2 — without it there is no
    /// <c>id_token</c> and therefore no verified identity to key the link on.
    /// </summary>
    public const string GoogleBase = "openid email profile";

    /// <summary>
    /// Everything a widget may additionally ask for, and the only scope strings this app will ever
    /// send. Both are read-only and as narrow as the provider offers.
    /// </summary>
    public static readonly IReadOnlyList<OptionalScope> Optional =
    [
        new OptionalScope(
            "organizations",
            OAuthProvider.GitHub,
            "read:org",
            "List the organizations you belong to. Read-only, and narrower than 'repo' — it grants no "
            + "access to code."),

        new OptionalScope(
            "calendar",
            OAuthProvider.Google,
            // calendar.events.readonly, not calendar.readonly: the widget reads events and nothing
            // else, and the narrower scope excludes calendar metadata and sharing rules it has no
            // business seeing. Google offers both; picking the wider one because it is the more
            // familiar name is how scope creep happens.
            "https://www.googleapis.com/auth/calendar.events.readonly",
            "Read the next few events on your primary calendar. Read-only, events only — no access to "
            + "calendar settings or sharing."),
    ];

    /// <summary>The scopes a first link requests: base only, for both providers.</summary>
    public static string BaseFor(OAuthProvider provider) => provider switch
    {
        OAuthProvider.GitHub => GitHubBase,
        OAuthProvider.Google => GoogleBase,
        _ => throw new NotSupportedException($"No base scope set is defined for {provider}."),
    };

    /// <summary>
    /// Looks up a caller-supplied grant key. A false return is the allowlist doing its job and must
    /// be answered with a refusal, not by passing the value along to the provider.
    /// </summary>
    public static bool TryResolve(OAuthProvider provider, string key, out OptionalScope? grant)
    {
        grant = Optional.FirstOrDefault(
            candidate => candidate.Provider == provider
                         && string.Equals(candidate.Key, key, StringComparison.OrdinalIgnoreCase));

        return grant is not null;
    }

    /// <summary>
    /// Whether the scopes the provider says it granted include <paramref name="scope"/>.
    /// </summary>
    /// <remarks>
    /// The delimiter is the trap. RFC 6749 says a scope <em>request</em> is space-delimited, and
    /// Google's responses follow suit — but GitHub answers with a <b>comma</b>-separated list
    /// (<c>"read:user,read:org"</c>). Splitting on space alone finds one scope named
    /// <c>read:user,read:org</c>, which matches nothing, and the widget then reports that a scope the
    /// user actually granted is missing. Both separators are accepted here rather than in a
    /// per-provider branch, because the check is about what a scope string can look like, not about
    /// which provider sent it.
    /// </remarks>
    public static bool IsGranted(string? grantedScopes, string scope)
    {
        if (string.IsNullOrWhiteSpace(grantedScopes))
        {
            return false;
        }

        return grantedScopes
            .Split([' ', ',', '\t'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            // Ordinal, not case-insensitive: scope strings are opaque identifiers and a provider that
            // distinguishes two scopes by case is entitled to. Matching loosely here would report a
            // permission as granted on the strength of a near miss.
            .Contains(scope, StringComparer.Ordinal);
    }

    /// <summary>
    /// The scope string to send for an incremental authorization: the base set plus the one grant
    /// being added.
    /// </summary>
    /// <remarks>
    /// The base set is re-sent rather than only the new scope, because a token scoped to nothing but
    /// <c>read:org</c> could not read the profile the connection card is drawn from. Google needs
    /// <c>include_granted_scopes=true</c> alongside this to keep scopes granted in <em>earlier</em>
    /// rounds on the new token — see <c>GoogleOAuthClient.BuildAuthorizationUrlAsync</c>.
    /// </remarks>
    public static string RequestFor(OAuthProvider provider, OptionalScope? additional) =>
        additional is null ? BaseFor(provider) : $"{BaseFor(provider)} {additional.Scope}";
}
