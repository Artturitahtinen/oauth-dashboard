using System.Security.Claims;

namespace OAuthDashboard.Api;

public static class ClaimsPrincipalExtensions
{
    /// <summary>
    /// Reads the local user id out of the session cookie's claims.
    /// </summary>
    /// <remarks>
    /// Throws rather than returning null: every caller sits behind <c>[Authorize]</c>, so a missing
    /// or unparseable id means the cookie was issued without the claim — a bug in sign-in, not a
    /// situation to paper over with a default user id of 0.
    /// </remarks>
    public static int GetUserId(this ClaimsPrincipal principal)
    {
        var raw = principal.FindFirstValue(ClaimTypes.NameIdentifier);

        return int.TryParse(raw, out var userId)
            ? userId
            : throw new InvalidOperationException(
                "Authenticated principal has no usable NameIdentifier claim.");
    }
}
