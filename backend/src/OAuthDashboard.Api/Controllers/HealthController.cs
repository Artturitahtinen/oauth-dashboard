using Microsoft.AspNetCore.Mvc;

namespace OAuthDashboard.Api.Controllers;

/// <summary>
/// M0 connectivity probe. Proves two separate things the BFF depends on: that the SPA can reach
/// this API cross-origin, and that a cookie this API sets comes back on the following call.
/// Only the second one really exercises the credentialed path — a CORS policy that forgot
/// AllowCredentials still lets a plain anonymous GET through and looks healthy.
/// </summary>
[ApiController]
[Route("api/[controller]")]
public class HealthController(IWebHostEnvironment environment) : ControllerBase
{
    private const string ProbeCookieName = "oauthdash.probe";

    [HttpGet]
    public ActionResult<HealthResponse> Get()
    {
        var cookieEchoed = Request.Cookies.ContainsKey(ProbeCookieName);

        if (!cookieEchoed)
        {
            // The SPA page is http://localhost:5173 while this API is https://localhost:7236.
            // Sites are compared including the scheme, so http -> https counts as cross-*site*,
            // not merely cross-origin, and a default (Lax) cookie would never be sent back.
            // SameSite=None lifts that, and SameSite=None is only accepted alongside Secure.
            // The real session cookie in M1 needs exactly the same treatment.
            Response.Cookies.Append(ProbeCookieName, "1", new CookieOptions
            {
                
                HttpOnly = true,
                Secure = true,
                SameSite = SameSiteMode.None,
                MaxAge = TimeSpan.FromMinutes(10),
            });
        }

        return new HealthResponse("ok", environment.EnvironmentName, cookieEchoed);
    }
}

public record HealthResponse(string Status, string Environment, bool CookieEchoed);
