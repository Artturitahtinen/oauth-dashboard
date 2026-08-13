using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OAuthDashboard.Core.Accounts;
using OAuthDashboard.Infrastructure.Accounts;

namespace OAuthDashboard.Api.Controllers;

/// <summary>
/// What the SPA is allowed to know about the current user's provider links.
/// </summary>
/// <remarks>
/// The response is intentionally metadata only — provider, account name, granted scopes, timestamps.
/// No token, and not even the ciphertext: handing the SPA an encrypted token would still put it in
/// the browser's memory and network log for no benefit. This is the BFF boundary at its narrowest
/// point, and it's the endpoint to check first if that boundary is ever suspected of leaking.
/// </remarks>
[ApiController]
[Route("api/connections")]
[Authorize]
public class ConnectionsController(
    LinkedAccountService linkedAccounts,
    ILogger<ConnectionsController> logger) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<List<LinkedAccountSummary>>> Get(CancellationToken ct) =>
        await linkedAccounts.GetSummariesAsync(User.GetUserId(), ct);

    /// <summary>
    /// Drops the local link. Route-bound to the <see cref="OAuthProvider"/> enum, so an unknown
    /// provider name fails model binding with a 400 and never reaches the database as a string.
    /// </summary>
    /// <remarks>
    /// This is a local delete, not a revocation: GitHub still considers the grant live and the token
    /// this app just discarded would keep working if a copy existed elsewhere. M5 replaces this with
    /// a real unlink that calls the provider's revoke endpoint first, then deletes.
    /// </remarks>
    [HttpDelete("{provider}")]
    public async Task<IActionResult> Delete(OAuthProvider provider, CancellationToken ct)
    {
        var userId = User.GetUserId();
        var deleted = await linkedAccounts.DeleteAsync(userId, provider, ct);

        if (!deleted)
        {
            return NotFound(new { error = "not_linked" });
        }

        logger.LogInformation(
            "Deleted local {Provider} link for user {UserId} (token discarded locally; not yet revoked upstream).",
            provider, userId);

        return NoContent();
    }
}
