using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OAuthDashboard.Core.Accounts;
using OAuthDashboard.Infrastructure.Persistence;
using OAuthDashboard.Infrastructure.Security;

namespace OAuthDashboard.Api.Controllers;

/// <summary>
/// Development-only controls for putting a link into each of the states M3 has to handle, so the
/// refresh flow can be exercised on demand instead of by waiting out a token lifetime.
/// </summary>
/// <remarks>
/// M3's verification step is "force-expire a token and confirm the call transparently refreshes it".
/// Without something like this, that reads as "wait eight hours", and the interesting failure paths
/// — a rejected refresh token, a token revoked upstream — can't be reproduced at all without
/// clicking around in GitHub's settings.
/// <para>
/// <b>Why this is safe to have, and how it stays that way.</b> Every action here only ever
/// <em>damages</em> the caller's own link: it writes values that are guaranteed not to work. There
/// is no action that mints a token, widens a scope, or reads one out. It is additionally
/// <c>[Authorize]</c>d, scoped to the calling user's own rows, and returns <c>404</c> outside
/// Development, checked at the top of every action rather than once at registration — a controller
/// that is only conditionally routed is one refactor away from being unconditionally routed, and
/// this failure has to be closed by default.
/// </para>
/// <para>
/// The sabotaged values still go through <see cref="TokenProtector"/> rather than being written as
/// plaintext. Writing raw junk into the column would fail at the <c>Unprotect</c> call with a
/// cryptographic error, which is a different failure than the one being simulated — the point is to
/// exercise "the provider rejected a perfectly well-formed stored token", so the ciphertext has to
/// be real.
/// </para>
/// </remarks>
[ApiController]
[Route("api/dev/connections")]
[Authorize]
public class TokenLabController(
    DashboardDbContext db,
    TokenProtector protector,
    IHostEnvironment environment,
    ILogger<TokenLabController> logger) : ControllerBase
{
    /// <summary>
    /// Backdates the recorded expiry so the very next use trips the <em>proactive</em> refresh
    /// trigger, before any request is sent to the provider.
    /// </summary>
    [HttpPost("{provider}/expire-access-token")]
    public Task<IActionResult> ExpireAccessToken(OAuthProvider provider, CancellationToken ct) =>
        MutateAsync(provider, "expire-access-token", account =>
        {
            account.ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1);
        }, ct);

    /// <summary>
    /// Replaces the stored access token with a well-formed but worthless one, leaving the recorded
    /// expiry alone. The stored metadata still claims the token is good, so this trips the
    /// <em>reactive</em> trigger instead: the provider answers 401 and the refresh happens on the
    /// way back. Simulates a token revoked from the user's provider settings page.
    /// </summary>
    [HttpPost("{provider}/revoke-access-token")]
    public Task<IActionResult> RevokeAccessToken(OAuthProvider provider, CancellationToken ct) =>
        MutateAsync(provider, "revoke-access-token", account =>
        {
            account.EncryptedAccessToken = protector.Protect(FakeAccessToken(provider));
        }, ct);

    /// <summary>
    /// Corrupts the refresh token too, so the refresh attempt itself is rejected. This is the
    /// dead-grant path: the app should latch the link as needing re-authorization rather than
    /// retrying.
    /// </summary>
    [HttpPost("{provider}/break-refresh-token")]
    public Task<IActionResult> BreakRefreshToken(OAuthProvider provider, CancellationToken ct) =>
        MutateAsync(provider, "break-refresh-token", account =>
        {
            account.EncryptedRefreshToken = protector.Protect(FakeRefreshToken(provider));
            account.ExpiresAtUtc = DateTimeOffset.UtcNow.AddMinutes(-1);
        }, ct);

    /// <summary>
    /// A well-formed but worthless token, shaped like the provider's own. The shape is cosmetic —
    /// what matters is that the provider will refuse it — but a <c>gho_</c> value sitting in a Google
    /// row makes a debugging session harder than it needs to be.
    /// </summary>
    private static string FakeAccessToken(OAuthProvider provider) => provider switch
    {
        OAuthProvider.Google => $"ya29.notarealtoken{Guid.NewGuid():N}",
        _ => $"gho_notarealtoken{Guid.NewGuid():N}",
    };

    private static string FakeRefreshToken(OAuthProvider provider) => provider switch
    {
        OAuthProvider.Google => $"1//notarealtoken{Guid.NewGuid():N}",
        _ => $"ghr_notarealtoken{Guid.NewGuid():N}",
    };

    /// <summary>
    /// Clears the "needs re-authorization" latch without going through a consent screen, so the
    /// other simulations can be re-run against the same link.
    /// </summary>
    /// <remarks>
    /// Note what this does <em>not</em> do: it doesn't repair anything. Clearing the latch on a link
    /// whose tokens are genuinely dead just means the next call rediscovers that and sets it again,
    /// which is worth seeing once — the latch is a cache of a provider fact, not the fact itself.
    /// </remarks>
    [HttpPost("{provider}/clear-reauthorization-latch")]
    public Task<IActionResult> ClearLatch(OAuthProvider provider, CancellationToken ct) =>
        MutateAsync(provider, "clear-reauthorization-latch", account =>
        {
            account.ReauthorizationRequiredAtUtc = null;
        }, ct);

    private async Task<IActionResult> MutateAsync(
        OAuthProvider provider, string action, Action<LinkedAccount> mutate, CancellationToken ct)
    {
        if (!environment.IsDevelopment())
        {
            // Fail closed, and fail as if the route didn't exist — there's no reason to confirm to a
            // production caller that a token-sabotage endpoint is compiled in.
            return NotFound();
        }

        var userId = User.GetUserId();
        var account = await db.LinkedAccounts
            .SingleOrDefaultAsync(a => a.UserId == userId && a.Provider == provider, ct);

        if (account is null)
        {
            return NotFound(new { error = "not_linked" });
        }

        mutate(account);
        await db.SaveChangesAsync(ct);

        logger.LogWarning(
            "DEV: applied {Action} to the {Provider} link for user {UserId}. This deliberately breaks the stored credential.",
            action, provider, userId);

        return Ok(new
        {
            action,
            provider = provider.ToString(),
            account.ExpiresAtUtc,
            account.RefreshedAtUtc,
            reauthorizationRequired = account.ReauthorizationRequiredAtUtc is not null,
        });
    }
}
