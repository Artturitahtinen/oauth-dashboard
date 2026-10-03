namespace OAuthDashboard.Infrastructure.Auth;

/// <summary>
/// The normalized outcome of a token exchange, so persistence doesn't have to care which provider's
/// JSON shape it came from. Produced by both the authorization-code exchange and the refresh grant —
/// they answer with the same fields, which is why one type covers both.
/// </summary>
/// <param name="AccessToken">The bearer token used to call the provider's API.</param>
/// <param name="RefreshToken">
/// Null when the provider didn't issue one. A GitHub OAuth App hands out a non-expiring access
/// token and no refresh token at all; Google only issues one when explicitly asked (M4). Null on a
/// <em>refresh</em> response means "keep the one you have" rather than "you now have none" — see
/// <c>LinkedAccountService.UpdateAfterRefreshAsync</c>.
/// </param>
/// <param name="Scopes">What the provider actually granted, which may be narrower than requested.</param>
/// <param name="ExpiresAtUtc">
/// Null means the provider advertised no expiry — distinct from "expired". M3's refresh logic keys
/// off exactly this difference, so it must not be flattened to <c>DateTimeOffset.MinValue</c>.
/// </param>
/// <param name="RefreshTokenExpiresAtUtc">
/// Refresh tokens expire too, and on a much longer clock (GitHub Apps: ~6 months). Tracking it is
/// what lets the dashboard say "you will have to re-link on this date" instead of discovering it as
/// a surprise failure. Null means no expiry was advertised for the refresh token either.
/// </param>
public record OAuthTokenResult(
    string AccessToken,
    string? RefreshToken,
    string? Scopes,
    DateTimeOffset? ExpiresAtUtc,
    DateTimeOffset? RefreshTokenExpiresAtUtc = null);
