namespace OAuthDashboard.Infrastructure.Auth;

/// <summary>
/// The normalized outcome of a token exchange, so persistence doesn't have to care which provider's
/// JSON shape it came from.
/// </summary>
/// <param name="AccessToken">The bearer token used to call the provider's API.</param>
/// <param name="RefreshToken">
/// Null when the provider didn't issue one. A GitHub OAuth App hands out a non-expiring access
/// token and no refresh token at all; Google only issues one when explicitly asked (M4).
/// </param>
/// <param name="Scopes">What the provider actually granted, which may be narrower than requested.</param>
/// <param name="ExpiresAtUtc">
/// Null means the provider advertised no expiry — distinct from "expired". M3's refresh logic keys
/// off exactly this difference, so it must not be flattened to <c>DateTimeOffset.MinValue</c>.
/// </param>
public record OAuthTokenResult(
    string AccessToken,
    string? RefreshToken,
    string? Scopes,
    DateTimeOffset? ExpiresAtUtc);
