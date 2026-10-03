namespace OAuthDashboard.Infrastructure.Auth;

public class GoogleOAuthOptions
{
    public required string ClientId { get; init; }
    public required string ClientSecret { get; init; }
    public required string RedirectUri { get; init; }

    /// <summary>
    /// The OIDC <em>issuer</em>, not an endpoint. Every URL Google's flow uses — authorize, token,
    /// userinfo, JWKS — is read from the discovery document published under this authority rather
    /// than hardcoded, which is the difference between OAuth2 (where you look the endpoints up in
    /// the provider's documentation) and OIDC (where the provider publishes them in a machine-
    /// readable form and can move them).
    /// </summary>
    /// <remarks>
    /// It doubles as the value the <c>iss</c> claim of every <c>id_token</c> must equal, so a typo
    /// here fails closed at validation rather than silently trusting the wrong identity provider.
    /// </remarks>
    public string Authority { get; init; } = "https://accounts.google.com";
}
