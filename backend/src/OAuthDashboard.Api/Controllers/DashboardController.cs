using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OAuthDashboard.Infrastructure.Dashboard;

namespace OAuthDashboard.Api.Controllers;

/// <summary>
/// The one endpoint the SPA's dashboard screen calls (M5).
/// </summary>
/// <remarks>
/// <b>One call, not one per provider, and that is the BFF's job description.</b> The alternative
/// architecture — the SPA calling GitHub and Google directly — requires the SPA to hold provider
/// tokens, which is the single thing this project has spent five milestones not doing. Every token
/// stays here; what crosses to the browser is a normalized list of rows with no credential of any
/// kind in it.
/// <para>
/// <b>This endpoint answers 200 for almost everything.</b> A provider being down, a grant needing
/// re-consent, a scope never granted: all of those are facts about one card, reported inside the
/// body, and none of them makes the request itself unsuccessful. The status code is reserved for the
/// only thing that can actually fail here — the local session, which is what <c>[Authorize]</c>
/// already answers with a 401. Mapping the worst widget's state onto the HTTP status would make a
/// dashboard where four widgets work look broken, and would send a SPA that branches on 401 to the
/// login screen because GitHub had a bad minute.
/// </para>
/// </remarks>
[ApiController]
[Route("api/dashboard")]
[Authorize]
public class DashboardController(DashboardService dashboard, ILogger<DashboardController> logger) : ControllerBase
{
    [HttpGet]
    public async Task<ActionResult<DashboardResponse>> Get(CancellationToken ct)
    {
        var userId = User.GetUserId();
        var response = await dashboard.BuildAsync(userId, ct);

        // One line per load, at the level of "which cards worked" — never the contents, which are the
        // user's own data and have no business in a log file.
        logger.LogInformation(
            "Built the dashboard for user {UserId}: {Summary}.",
            userId,
            string.Join(", ", response.Widgets.Select(w => $"{w.Key}={w.Status}")));

        return response;
    }
}
