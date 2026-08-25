using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using OAuthDashboard.Core.Accounts;
using OAuthDashboard.Infrastructure.Auth;

namespace OAuthDashboard.Tests;

/// <summary>
/// M5's least-privilege half: what a link starts with, what a widget may add, and what a caller is
/// allowed to ask for.
/// </summary>
/// <remarks>
/// The tests worth having here are the negative ones. A scope registry that hands out whatever it is
/// asked for passes every happy-path test — the provider will honour the request, the flow will
/// complete, the widget will work — and the only thing wrong with it is that the request came from
/// outside.
/// </remarks>
public class ProviderScopeTests
{
    private const string State = "state-value";
    private const string Challenge = "challenge-value";
    private const string Nonce = "nonce-value";

    // --- the allowlist ------------------------------------------------------------------------------

    /// <summary>
    /// The property that makes <c>?grant=</c> safe on an authenticated redirect endpoint. Anything the
    /// registry does not already know about is refused, so the worst a caller can do by choosing the
    /// parameter is pick between scopes this app had already decided it wanted.
    /// </summary>
    [Theory]
    [InlineData("repo")]                                    // a real GitHub scope, just not one we ask for
    [InlineData("admin:org")]                               // the escalation an attacker would actually want
    [InlineData("read:org extra:thing")]                    // a smuggled second scope
    [InlineData("https://www.googleapis.com/auth/gmail.readonly")]
    [InlineData("")]
    public void TryResolve_RefusesAnythingThatIsNotARegisteredKey(string requested)
    {
        Assert.False(ProviderScopes.TryResolve(OAuthProvider.GitHub, requested, out var grant));
        Assert.Null(grant);
    }

    /// <summary>
    /// Keys are namespaced to their provider, so <c>calendar</c> is meaningless on GitHub. Without
    /// this, a key would resolve to a scope string one provider has never heard of and the failure
    /// would surface as an opaque <c>invalid_scope</c> three redirects away.
    /// </summary>
    [Fact]
    public void TryResolve_DoesNotLeakOneProvidersKeysIntoAnother()
    {
        Assert.True(ProviderScopes.TryResolve(OAuthProvider.Google, "calendar", out _));
        Assert.False(ProviderScopes.TryResolve(OAuthProvider.GitHub, "calendar", out _));

        Assert.True(ProviderScopes.TryResolve(OAuthProvider.GitHub, "organizations", out _));
        Assert.False(ProviderScopes.TryResolve(OAuthProvider.Google, "organizations", out _));
    }

    /// <summary>
    /// Every optional scope on offer is read-only. Asserted rather than assumed, because "we only ask
    /// for read access" is the kind of claim a README makes and a later commit quietly breaks — and
    /// the failure is invisible from the outside, since a wider scope works perfectly.
    /// </summary>
    [Fact]
    public void Optional_OffersOnlyReadOnlyScopes()
    {
        Assert.All(ProviderScopes.Optional, scope =>
            Assert.True(
                scope.Scope.Contains("read", StringComparison.Ordinal)
                || scope.Scope.EndsWith("readonly", StringComparison.Ordinal),
                $"'{scope.Scope}' is not obviously read-only."));

        // The one that would be easiest to reach for and hardest to justify: GitHub's `repo` is read
        // *and write* on every private repository, with no narrower alternative for an OAuth App.
        Assert.DoesNotContain(ProviderScopes.Optional, scope => scope.Scope == "repo");
    }

    /// <summary>Every optional scope explains itself, because a consent prompt with no reason is a dark pattern.</summary>
    [Fact]
    public void Optional_StatesWhyEachScopeIsWanted()
    {
        Assert.All(ProviderScopes.Optional, scope => Assert.False(string.IsNullOrWhiteSpace(scope.Purpose)));
    }

    // --- granted-scope parsing ----------------------------------------------------------------------

    /// <summary>
    /// The delimiter trap. RFC 6749 makes a scope <em>request</em> space-delimited and Google's
    /// responses follow suit, but GitHub answers with a comma-separated list. A parser that splits on
    /// space alone finds one scope called <c>read:user,read:org</c>, matches nothing, and reports a
    /// permission the user actually granted as missing — which sends them back through a consent
    /// screen that cannot fix it.
    /// </summary>
    [Theory]
    [InlineData("read:user,read:org", "read:org", true)]                 // GitHub's spelling
    [InlineData("read:user read:org", "read:org", true)]                 // the RFC's
    [InlineData("read:user, read:org", "read:org", true)]                // both, with whitespace
    [InlineData("read:user", "read:org", false)]
    [InlineData("", "read:org", false)]
    [InlineData(null, "read:org", false)]
    public void IsGranted_UnderstandsBothDelimiters(string? granted, string required, bool expected)
    {
        Assert.Equal(expected, ProviderScopes.IsGranted(granted, required));
    }

    /// <summary>
    /// A near miss is not a match. Prefix-matching would make <c>read:org</c> satisfiable by
    /// <c>read:organization_hooks</c>, and substring-matching would make it satisfiable by anything
    /// containing those nine characters — both of which report a permission as held on the strength
    /// of a coincidence.
    /// </summary>
    [Theory]
    [InlineData("read:organization_hooks")]
    [InlineData("admin:read:org")]
    [InlineData("READ:ORG")]
    public void IsGranted_DoesNotMatchOnResemblance(string granted)
    {
        Assert.False(ProviderScopes.IsGranted(granted, "read:org"));
    }

    /// <summary>The Google scope is a URL, so it has to survive being a single token with slashes and dots.</summary>
    [Fact]
    public void IsGranted_HandlesGooglesUrlShapedScopes()
    {
        const string calendar = "https://www.googleapis.com/auth/calendar.events.readonly";
        var granted = $"openid email profile {calendar}";

        Assert.True(ProviderScopes.IsGranted(granted, calendar));
        Assert.False(ProviderScopes.IsGranted(granted, "https://www.googleapis.com/auth/calendar.readonly"));
    }

    // --- what actually goes on the wire -------------------------------------------------------------

    /// <summary>
    /// A plain link asks for the base scope and nothing more. This is the assertion that keeps M5's
    /// widgets from being paid for at link time: adding a widget must not widen the first consent
    /// screen everyone sees.
    /// </summary>
    [Fact]
    public void GitHubAuthorizeUrl_AsksForBaseScopeOnlyWhenNoGrantIsRequested()
    {
        var url = GitHubClient().BuildAuthorizationUrl(State, Challenge);

        Assert.Contains($"scope={Uri.EscapeDataString(ProviderScopes.GitHubBase)}", url);
        Assert.DoesNotContain("read%3Aorg", url);
    }

    /// <summary>
    /// An incremental authorization sends base <em>plus</em> the one grant. Sending only the new scope
    /// would return a token that can list organizations and can no longer read the profile the
    /// connection card is drawn from.
    /// </summary>
    [Fact]
    public void GitHubAuthorizeUrl_AddsTheOneRequestedGrantOnTopOfTheBase()
    {
        Assert.True(ProviderScopes.TryResolve(OAuthProvider.GitHub, "organizations", out var grant));

        var url = GitHubClient().BuildAuthorizationUrl(State, Challenge, grant);
        var scope = Uri.UnescapeDataString(Query(url, "scope"));

        Assert.Equal("read:user read:org", scope);
    }

    /// <summary>
    /// Google's incremental-authorization switch. Without <c>include_granted_scopes=true</c>, the
    /// token minted for this request carries only the scopes this request named — so enabling the
    /// calendar widget would silently break the account widget that was working a moment ago.
    /// </summary>
    [Fact]
    public async Task GoogleAuthorizeUrl_AlwaysAsksForPreviouslyGrantedScopesToBeIncluded()
    {
        using var google = new FakeGoogle();

        var url = await google.CreateClient()
            .BuildAuthorizationUrlAsync(State, Challenge, Nonce, additionalScope: null, CancellationToken.None);

        Assert.Contains("include_granted_scopes=true", url);
    }

    [Fact]
    public async Task GoogleAuthorizeUrl_AddsTheOneRequestedGrantOnTopOfTheBase()
    {
        using var google = new FakeGoogle();
        Assert.True(ProviderScopes.TryResolve(OAuthProvider.Google, "calendar", out var grant));

        var url = await google.CreateClient()
            .BuildAuthorizationUrlAsync(State, Challenge, Nonce, grant, CancellationToken.None);

        var scope = Uri.UnescapeDataString(Query(url, "scope"));

        Assert.Equal("openid email profile https://www.googleapis.com/auth/calendar.events.readonly", scope);

        // Still an OIDC authorization request, and still one that can produce a refresh token: the
        // incremental scope must not cost the parameters M3 and M4 depend on.
        Assert.Contains("access_type=offline", url);
        Assert.Contains("prompt=consent", url);
        Assert.Contains($"nonce={Nonce}", url);
        Assert.Contains("code_challenge_method=S256", url);
    }

    private static GitHubOAuthClient GitHubClient() => new(
        new HttpClient(new StubGitHubHandler(_ => StubGitHubHandler.Json("{}"))),
        Options.Create(new GitHubOAuthOptions
        {
            ClientId = FakeGitHub.ClientId,
            ClientSecret = FakeGitHub.ClientSecret,
            RedirectUri = "https://localhost:7236/api/auth/github/callback",
        }),
        NullLogger<GitHubOAuthClient>.Instance);

    private static string Query(string url, string name) => url
        .Split('?', 2)[1]
        .Split('&')
        .Select(pair => pair.Split('=', 2))
        .Where(parts => parts.Length == 2 && parts[0] == name)
        .Select(parts => parts[1])
        .Single();
}
