using OAuthDashboard.Core.Accounts;

namespace OAuthDashboard.Infrastructure.Auth;

/// <summary>
/// The provider refused the refresh token itself: expired, already rotated, or revoked from the
/// user's GitHub/Google settings page.
/// </summary>
/// <remarks>
/// This is a <em>provider fact</em>, raised by the provider client, and it is deliberately not the
/// same type as <see cref="ReauthorizationRequiredException"/>. Keeping them apart is what stops a
/// transport failure from being treated as a dead grant: a 503 or a DNS failure means "try again",
/// while this means "there is nothing left to try". Collapsing the two would make the dashboard
/// demand a re-link every time GitHub had a bad minute.
/// </remarks>
public class RefreshTokenRejectedException(string error, string? errorDescription)
    : Exception($"The provider rejected the refresh token: {error} ({errorDescription})")
{
    /// <summary>The provider's own error code, e.g. <c>bad_refresh_token</c>.</summary>
    public string Error { get; } = error;

    public string? ErrorDescription { get; } = errorDescription;
}

/// <summary>
/// This link cannot be repaired automatically — the user has to walk the consent screen again.
/// </summary>
/// <remarks>
/// Where <see cref="RefreshTokenRejectedException"/> reports what the provider said, this reports
/// what the application concluded, and it covers one case the provider never speaks to: there was
/// no refresh token at all. A GitHub OAuth App issues none, so when its non-expiring access token
/// stops working (the user revoked it), there is no grant to refresh and the same remedy applies.
/// <para>
/// It maps to <c>409 reauthorization_required</c> rather than a 401, because the local session is
/// perfectly valid — it's the <em>provider</em> link that is broken, and a 401 would tell the SPA to
/// send the user to the wrong login screen.
/// </para>
/// </remarks>
public class ReauthorizationRequiredException(OAuthProvider provider, string reason, Exception? inner = null)
    : Exception($"The {provider} link needs a fresh authorization: {reason}", inner)
{
    public OAuthProvider Provider { get; } = provider;

    /// <summary>Machine-readable cause: <c>no_refresh_token</c>, <c>refresh_token_rejected</c>, or
    /// <c>token_rejected_after_refresh</c>.</summary>
    public string Reason { get; } = reason;
}

/// <summary>
/// The user has no link to this provider at all, so there is no token to refresh or spend.
/// Distinct from a broken link: the remedy is "connect it", not "reconnect it".
/// </summary>
public class ProviderNotLinkedException(OAuthProvider provider)
    : Exception($"No {provider} account is linked to this user.")
{
    public OAuthProvider Provider { get; } = provider;
}
