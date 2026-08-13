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
- [x] M1 — GitHub, hand-rolled, no persistence
- [x] M2 — PKCE + encrypted persistence + local login
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

### M1 — the authorization code flow, hand-rolled

- **`state` is single-use.** `/authorize` mints a random 256-bit value and stores it server-side
  (`OAuthStateStore`, an `IMemoryCache` entry with a 5-minute TTL); `/callback` removes it the
  moment it's checked. A captured callback URL replayed a second time fails with `invalid_state`
  because there's nothing left to consume — this is the CSRF protection on the link action, not
  an incidental detail.
- **The redirect URI is never taken from the request.** GitHub is configured (via user-secrets)
  with the exact callback URL this backend will send, and that same value is the only one this
  backend ever sends back to GitHub during the token exchange. There's no code path where a
  caller-supplied redirect target could substitute in.
- **The token exchange happens over a direct server-to-server `HttpClient` POST** to GitHub's
  token endpoint — the SPA never sees the authorization `code`, let alone the access token,
  because the entire redirect chain (`/authorize` → github.com → `/callback`) never touches the
  SPA's origin.
- **Tokens don't go in logs, even in a milestone that says "nothing hidden."** M1 logs that a
  token was obtained (scope, type, length) but deliberately not the token value — the plan's
  literal suggestion to log the token was worth deviating from, since a logging habit picked up
  now would otherwise need to be unlearned right before M2 adds real persistence.
- Scope requested is the minimum needed to prove the flow (`read:user`) — broader scopes get
  added only when a specific widget needs them (M5).

Verified by walking the real browser redirect end to end: `/authorize` → GitHub's consent screen
→ `/callback`, which returns the caller's own GitHub profile JSON. Confirmed both the happy path
and that state validation fails closed on a missing state, an unrecognized state, and a
provider-side denial (`error=access_denied`).

### M2 — PKCE, encrypted persistence, and a local identity

**PKCE (S256).** `/authorize` mints a `code_verifier` alongside the state and sends only
`code_challenge=BASE64URL(SHA256(ASCII(verifier)))` plus `code_challenge_method=S256`. The verifier
stays in `OAuthStateStore` until the server-to-server token POST, so the value that would let a
stolen code be redeemed never appears in the address bar, browser history, or GitHub's logs.

This backend is a *confidential* client — it holds a `client_secret`, so an intercepted code is
already unusable without it and PKCE is not strictly required. It's implemented anyway because it
costs almost nothing, because OAuth 2.1 makes it mandatory for all client types, and because "we
have a secret" stops being true the moment any part of this runs somewhere a secret can't be kept.
`plain` is the other method the RFC allows and is pointless: it sends the verifier *as* the
challenge, so anyone who can read the authorize URL gets both halves.

The one implementation detail worth pinning down: S256 hashes the **ASCII characters of the verifier
string**, not the random bytes it was decoded from. Getting that wrong still yields a plausible
43-character challenge and fails only later, as an opaque `invalid_grant` from the provider — so
`PkceTests` asserts the published RFC 7636 Appendix B vector rather than just checking the shape.

**State now carries who started the flow.** `OAuthStateStore` went from storing a bare marker to a
`PendingAuthorization` record, because two things have to survive the round trip and neither can
safely live in the browser: the PKCE verifier, and the id of the user who initiated. Binding the
user id means the callback can assert the flow is being *finished by the same session that started
it* — otherwise a link begun in one session could be completed in another, attaching an attacker's
GitHub account to this user's dashboard (or this user's account to an attacker's session). State
being single-use stops replay; state being *bound* stops cross-session grafting. They're different
attacks and need different checks.

**Tokens are encrypted, passwords are hashed, and the difference is deliberate.**
- Provider tokens go through `TokenProtector` (Data Protection, purpose
  `OAuthDashboard.ProviderTokens.v1`) — *reversible* encryption, because the whole point is to
  replay them to GitHub later.
- The local password goes through `PasswordHasher` (PBKDF2-HMAC-SHA256, 600k iterations, per-user
  random salt, constant-time compare) — *irreversible*, because nothing ever needs the plaintext
  back.
- Data Protection derives a distinct key per purpose string, which is what keeps the token protector
  and the session cookie's protector from being interchangeable. Sharing a purpose would let a
  cookie value be fed to the token unprotector.
- `SetApplicationName("OAuthDashboard")` is not cosmetic: without it the key-derivation
  discriminator comes from the content-root path, so moving or renaming the folder would silently
  produce a different key and every token already in SQLite would fail to decrypt.

What this buys and what it doesn't: a copied `oauthdashboard.db` is useless on its own. But in
development the keyring sits unencrypted under `%LOCALAPPDATA%\ASP.NET\DataProtection-Keys`, so an
attacker with the whole machine has both halves. This defends against a leaked database file, not
against a compromised host — a real deployment would put the keyring in a KMS.

**Local login is not OAuth, and keeping them separate matters.** `SessionController` proves *who the
local user is*; `GitHubAuthController` proves *what that user authorized this app to do at GitHub*.
Conflating "log in with GitHub" and "link GitHub" is the usual source of confusion, and the BFF
split makes the distinction concrete — you log into the dashboard, then link providers to it.
Registration is a first-run claim, open only while the users table is empty, so a personal project
doesn't ship an open sign-up endpoint or need a bootstrap password sitting in plaintext config.

**Failed logins are indistinguishable.** "No such user" and "wrong password" both return
`401 invalid_credentials`, and the unknown-user path still runs a full PBKDF2 verification against a
dummy hash so it takes comparable time. Returning early there would leak the same information
through latency that the shared error message was hiding. The log line is equally vague — a failed
attempt is no reason to write an attacker-supplied guess into a log file.

**The callback redirects instead of returning JSON.** A provider callback lands in a top-level
browser navigation, so its response is a *page the user sees*; it must not be a page containing
token material. It now 302s to `{Spa:Origin}/connections?linked=github`, with failures becoming
`?error=<code>`. The target is built from configuration — a caller-supplied `?next=` here would be
an open redirect hanging off an authenticated endpoint.

**Cookie flags, and why `SameSite=None` is required rather than sloppy.** The session cookie is
`HttpOnly` (script can't read it, so an XSS bug can't exfiltrate the session), `Secure`, and
`SameSite=None` — necessary because the SPA (`http://localhost:5173`) and this API
(`https://localhost:7236`) differ in *scheme* and are therefore cross-site, not merely
cross-origin. See the M0 note. Cookie auth's default 302-to-login-page is replaced: fetch callers
get a `401` they can branch on, real browser navigations get redirected into the SPA's login route.

**Unlink is still local-only.** `DELETE /api/connections/{provider}` deletes the row; GitHub still
considers the grant live. That's called out in the code as an M5 gap rather than left to look
finished — deleting a local row is not revocation.

**`GET /api/connections/{provider}/check` exists because M2's central claim was otherwise
unfalsifiable.** Every field on the connections response comes from an *unencrypted* column, so a
completely broken protector would still render a healthy-looking "Linked" card. This endpoint
decrypts the stored token and spends it on a real GitHub call, reporting only whether it worked. It's
also the seed of M3 — "use the stored token, notice it was rejected" is the signal the refresh flow
hangs off.

### Verifying M2

38 tests green, covering the RFC 7636 Appendix B vector, single-use and session-bound state, PBKDF2
round-trip and malformed-hash handling, and — the assertion that actually proves encryption at rest —
that the token column read straight out of SQLite does not contain the plaintext.

End-to-end against the running API and a real GitHub authorization:

- Anonymous `/api/connections`, `/api/connections/GitHub/check`, and `/api/auth/github/authorize` all
  return `401`. The same authorize URL with `Accept: text/html` redirects to the SPA login instead.
- An authenticated `/authorize` returns a `302` to GitHub carrying `code_challenge` and
  `code_challenge_method=S256`.
- A second `/register` returns `409`; wrong password and unknown username both return an identical
  `401 invalid_credentials`.
- Walking the real consent flow in the browser links the account, and `?linked=github` is the only
  thing that comes back to the SPA origin.
- **Inspecting the raw database file:** the token columns contain Data Protection ciphertext
  (`CfDJ8…`), the password is a `pbkdf2-sha256$600000$…` hash, and neither the GitHub token pattern
  (`gh[opusr]_…`) nor the account password appears anywhere in the file.
- **Across a process restart** (the token was written by an earlier process): logging in fresh
  succeeds against the stored hash, and `/check` decrypts the stored token and GitHub accepts it,
  answering with the linked account. Both halves of the encryption story survive the restart.
- Unlinking flips the card back to "Not linked"; re-linking updates the single existing row rather
  than adding a second.

Still to come: refresh flow (M3), nonce and `id_token` validation (M4), real revocation and
least-privilege scope expansion per widget (M5).

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

The SQLite schema is applied on startup (`Database.MigrateAsync()`), so there's no separate
`dotnet ef database update` step — the app owns its schema, which keeps the M2 verification
("restart the process; are the tokens still readable?") a one-command exercise. `dotnet-ef` is
pinned as a repo-local tool for *creating* migrations:

```
dotnet dotnet-ef migrations add <Name> --project src/OAuthDashboard.Infrastructure --startup-project src/OAuthDashboard.Api --output-dir Persistence/Migrations
```

On first run the SPA's login screen offers to claim the single local account; after that it asks for
those credentials. To start over, delete `src/OAuthDashboard.Api/oauthdashboard.db` (gitignored — it
holds encrypted provider tokens).
