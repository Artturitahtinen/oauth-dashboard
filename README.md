# OAuth Dashboard — Backend

ASP.NET Core Web API backend for a personal dashboard that aggregates your own GitHub and Google data. Built as a learning project: the OAuth2.0/OIDC token exchange is hand-rolled against raw `HttpClient` calls (no `Microsoft.AspNetCore.Authentication.Google`/`...OAuth` middleware), so the authorization code flow, PKCE, state parameter, and refresh token flow are all implemented and understood directly rather than hidden behind a framework abstraction.

Frontend lives in the sibling repo `frontend-oauth-dashboard` (React + TypeScript + Vite).

## Architecture

Backend-for-Frontend (BFF) pattern: the React SPA authenticates only against this backend's own session cookie. This backend is the *only* thing that ever holds GitHub/Google access and refresh tokens — the SPA never sees a provider token.

```
src/OAuthDashboard.Api/             Program.cs, controllers, appsettings
src/OAuthDashboard.Core/            domain models (User, LinkedAccount), IOAuthProviderClient
src/OAuthDashboard.Infrastructure/  EF Core DbContext, GitHubOAuthClient, GoogleOAuthClient, TokenEncryptionService
tests/OAuthDashboard.Tests/
```

## Status

- [x] M0 — Solution scaffolded (Api / Core / Infrastructure / Tests projects wired together)
- [x] M0 — Register GitHub OAuth App + Google Cloud OAuth client, confirm CORS-connected hello world
- [ ] M1 — GitHub, hand-rolled, no persistence
- [ ] M2 — PKCE + encrypted persistence + local login
- [ ] M3 — Refresh token flow
- [ ] M4 — Google + OIDC
- [ ] M5 — Unified dashboard

## OAuth app registration

Both provider apps point their redirect URI at *this backend*, never at the SPA — the SPA is not
allowed to see an authorization code, let alone a token.

| Provider | Redirect URI |
| --- | --- |
| GitHub OAuth App | `https://localhost:7236/api/auth/github/callback` |
| Google OAuth client (Web application) | `https://localhost:7236/api/auth/google/callback` |

Client credentials live in `dotnet user-secrets` for `src/OAuthDashboard.Api`, under
`OAuth:GitHub:ClientId` / `ClientSecret` and `OAuth:Google:ClientId` / `ClientSecret`. The Google
consent screen stays in Testing mode with the developer's own account as a test user.

## Security learning notes

### M0 — the cross-origin boundary

- `AllowCredentials()` cannot be combined with a wildcard origin. ASP.NET Core refuses the
  combination and browsers reject `Access-Control-Allow-Origin: *` on a credentialed request, so
  the SPA origin is named explicitly through `Spa:Origin`. Startup fails fast if it is missing.
- **CORS is enforced by the browser, not the server.** A request from a disallowed origin still
  reaches the controller and still returns `200` — it just comes back without the
  `Access-Control-Allow-*` headers, so the browser refuses to hand the response to the calling
  script. CORS restricts *readers*, not *callers*; it is never a substitute for checking the
  session on the server.
- **"Same site" is compared including the scheme.** The SPA on `http://localhost:5173` and this
  API on `https://localhost:7236` are cross-site even though both are localhost — ports are
  ignored in the comparison, but `http` vs `https` is not. A default `SameSite=Lax` cookie would
  therefore never be sent back, so the session cookie needs `SameSite=None`, which is only
  accepted together with `Secure`. `/api/health` demonstrates this with a throwaway probe cookie.
- Client secrets stay in user-secrets, outside the repo and outside the SPA bundle.

Still to come: PKCE, state parameter, nonce, redirect URI allowlisting, revocation,
least-privilege scopes.

## Running locally

The dev certificate has to be trusted, otherwise the browser refuses the SPA's calls with
`ERR_CERT_AUTHORITY_INVALID` — and later refuses the provider's redirect back to
`https://localhost:7236` as well:

```
dotnet dev-certs https --trust
```

Then:

```
dotnet user-secrets init --project src/OAuthDashboard.Api
dotnet run --launch-profile https --project src/OAuthDashboard.Api
```

`GET https://localhost:7236/api/health` is the connectivity probe. Called twice from the SPA it
should report `cookieEchoed: true` on the second call.
