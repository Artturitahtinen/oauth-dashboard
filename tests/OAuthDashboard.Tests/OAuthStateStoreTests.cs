using Microsoft.Extensions.Caching.Memory;
using OAuthDashboard.Core.Accounts;
using OAuthDashboard.Infrastructure.Auth;

namespace OAuthDashboard.Tests;

public class OAuthStateStoreTests
{
    private static OAuthStateStore NewStore() => new(new MemoryCache(new MemoryCacheOptions()));

    [Fact]
    public void TryConsume_ReturnsTheEntryThatWasIssued()
    {
        var store = NewStore();
        var issued = store.Issue(OAuthProvider.GitHub, userId: 7);

        Assert.True(store.TryConsume(issued.State, out var consumed));
        Assert.Equal(issued.CodeVerifier, consumed!.CodeVerifier);
        Assert.Equal(OAuthProvider.GitHub, consumed.Provider);
        Assert.Equal(7, consumed.UserId);
    }

    /// <summary>
    /// The CSRF protection on the link action: a captured callback URL replayed a second time must
    /// fail, because the first callback consumed the state.
    /// </summary>
    [Fact]
    public void TryConsume_SucceedsOnlyOnce()
    {
        var store = NewStore();
        var issued = store.Issue(OAuthProvider.GitHub, userId: 1);

        Assert.True(store.TryConsume(issued.State, out _));
        Assert.False(store.TryConsume(issued.State, out var replayed));
        Assert.Null(replayed);
    }

    [Fact]
    public void TryConsume_RejectsAStateItNeverIssued()
    {
        var store = NewStore();
        store.Issue(OAuthProvider.GitHub, userId: 1);

        Assert.False(store.TryConsume("attacker-supplied-state", out var pending));
        Assert.Null(pending);
    }

    [Fact]
    public void Issue_MintsAFreshStateAndVerifierEveryTime()
    {
        var store = NewStore();

        var issued = Enumerable.Range(0, 50).Select(_ => store.Issue(OAuthProvider.GitHub, 1)).ToList();

        Assert.Equal(issued.Count, issued.Select(p => p.State).Distinct().Count());
        Assert.Equal(issued.Count, issued.Select(p => p.CodeVerifier).Distinct().Count());
    }

    /// <summary>
    /// Two concurrent flows must not be able to consume each other's entries — this is what lets the
    /// callback assert the flow is being finished by the session that started it.
    /// </summary>
    [Fact]
    public void TryConsume_KeepsConcurrentFlowsIndependent()
    {
        var store = NewStore();
        var alice = store.Issue(OAuthProvider.GitHub, userId: 1);
        var bob = store.Issue(OAuthProvider.GitHub, userId: 2);

        Assert.True(store.TryConsume(alice.State, out var alicePending));
        Assert.Equal(1, alicePending!.UserId);

        Assert.True(store.TryConsume(bob.State, out var bobPending));
        Assert.Equal(2, bobPending!.UserId);
    }

    /// <summary>
    /// The state goes into a URL, so it has to survive one unescaped.
    /// </summary>
    [Fact]
    public void Issue_ProducesAUrlSafeState()
    {
        var state = NewStore().Issue(OAuthProvider.GitHub, 1).State;

        Assert.Equal(state, Uri.EscapeDataString(state));
    }
}
