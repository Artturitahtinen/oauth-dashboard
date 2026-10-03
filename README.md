# OAuth Dashboard — Backend

ASP.NET Core Web API backend for a personal dashboard that aggregates your own GitHub and Google data. Built as a learning project: the OAuth2.0/OIDC token exchange is hand-rolled against raw `HttpClient` calls (no `Microsoft.AspNetCore.Authentication.Google`/`...OAuth` middleware), so the authorization code flow, PKCE, state parameter, and refresh token flow are all implemented and understood directly rather than hidden behind a framework abstraction.

Frontend lives in `frontend/` (React + TypeScript + Vite).

## Architecture

Backend-for-Frontend (BFF) pattern: the React SPA authenticates only against this backend's own session cookie. This backend is the *only* thing that ever holds GitHub/Google access and refresh tokens — the SPA never sees a provider token.

```
backend/src/OAuthDashboard.Api/             Program.cs, controllers, appsettings
backend/src/OAuthDashboard.Core/            domain models (User, LinkedAccount), IOAuthProviderClient
backend/src/OAuthDashboard.Infrastructure/  EF Core DbContext, GitHubOAuthClient, GoogleOAuthClient, TokenProtector,
                                    ProviderTokenService, DashboardService, ProviderRevocationService
tests/OAuthDashboard.Tests/
```

## Status

- [x] M0 — Solution scaffolded (Api / Core / Infrastructure / Tests projects wired together)
- [x] M0 — Register GitHub OAuth App + Google Cloud OAuth client, confirm CORS-connected hello world
- [x] M1 — GitHub, hand-rolled, no persistence
- [x] M2 — PKCE + encrypted persistence + local login
- [x] M3 — Refresh token flow
- [x] M4 — Google + OIDC
- [x] M5 — Unified dashboard, real revocation, per-widget scopes

## OAuth app registration

Both provider apps point their redirect URI at *this backend*, never at the SPA — the SPA is not
allowed to see an authorization code, let alone a token.

| Provider | Redirect URI |
| --- | --- |
| GitHub OAuth App | `https://localhost:7236/api/auth/github/callback` |
| Google OAuth client (Web application) | `https://localhost:7236/api/auth/google/callback` |

Client credentials live in `dotnet user-secrets` for `backend/src/OAuthDashboard.Api`, under
`OAuth:GitHub:ClientId` / `ClientSecret` and `OAuth:Google:ClientId` / `ClientSecret`. The Google
consent screen stays in Testing mode with the developer's own account as a test user.

Two more steps in the Google Cloud project, needed by M5's calendar widget rather than by the link
itself: **enable the Google Calendar API** (APIs & Services → Library), and add
`https://www.googleapis.com/auth/calendar.events.readonly` to the consent screen's scope list. Without
the first, the widget reports `permission_denied` / `accessNotConfigured` — deliberately distinguished
from a missing scope, because re-consenting cannot fix it. Without the second, the incremental
authorization itself is refused with `invalid_scope`. Everything else on the dashboard works either way.

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

### M3 — the refresh flow

The point of the milestone is that the rest of the application stops thinking about token lifetime.
A caller asks for a GitHub access token; whether that involves a refresh POST, a retry, or nothing at
all is decided in one place (`ProviderTokenService`), and every path that spends a token goes through
it.

**Two triggers, because either one alone is broken.** The *proactive* trigger refreshes a token whose
recorded expiry is within two minutes. The *reactive* trigger refreshes when the provider answers
`401` to a token the database believed was fine. Neither is redundant:

- Proactive-only misses everything the stored metadata can't know. A user who revokes the grant from
  their GitHub settings page leaves `ExpiresAtUtc` looking perfectly healthy, and a provider is free
  to enforce an expiry it never advertised.
- Reactive-only wastes a request every time, and turns an ordinary expiry into a user-visible
  failure whenever the retry itself is the thing that fails.

The two-minute leeway isn't clock-drift paranoia so much as arithmetic: a token with eight seconds
left passes a naive `ExpiresAtUtc > UtcNow` check and then expires *in flight*. `expires_in` was also
measured at the provider, and the network time between there and here is real.

**`null` expiry is not `expired`, and this is where a refresh implementation usually goes wrong.** A
standard GitHub OAuth App issues a non-expiring access token and *no refresh token at all*. If "no
expiry recorded" were treated as "expired", every one of those links would be sent down a refresh
path with nothing to refresh with, and a perfectly working connection would start demanding
re-consent. The null survives from `GitHubOAuthClient` through the column to the comparison.

**Refresh tokens rotate, which makes concurrent refresh a correctness bug rather than waste.** GitHub
answers a refresh with a *new* refresh token and retires the one just used. So if two requests both
notice the expired token and both POST the same refresh token, the second one presents a credential
the provider has already retired — and presenting a used refresh token is precisely the signal OAuth
implementations use to detect a stolen one, answered by revoking the entire grant. Two widgets
loading at once could therefore log the user out of a provider nobody attacked. `RefreshLockRegistry`
holds one mutex per `(user, provider)`, and the refresh path *re-reads the row after acquiring it* —
whoever waited discovers the work is already done and uses the result instead of repeating it. The
lock is per-process, which is the right size for this app and explicitly not enough behind more than
one instance; that case needs the database row itself to be the lock.

For the same reason the rotated refresh token is **persisted before the new access token is handed
out**. GitHub has already retired the old one by the time the response arrives, so a crash between
the POST and the write leaves the database holding a credential the provider will refuse.

**"Rejected" and "failed" are different outcomes and get different types.** A `503`, a DNS failure or
a timeout means *try again later*; `bad_refresh_token` means *this grant is over and no number of
retries will change that*. `RefreshTokenRejectedException` reports what the provider said,
`ReauthorizationRequiredException` reports what the app concluded — and the second covers a case the
provider never speaks to, namely that there was no refresh token in the first place. Collapsing them
would make the dashboard demand a re-link every time GitHub had a bad minute.

Once a grant is known dead the link is **latched** (`ReauthorizationRequiredAtUtc`) and not retried.
Rediscovering the same rejection on every page load spends rate limit to learn nothing, and each
attempt is one more thing that looks like credential stuffing from the provider's side. Only a
completed consent clears the latch — not a restart, not a lucky call. The dead tokens are left in the
row rather than nulled out: they're useless but encrypted, and keeping the row whole means a broken
link stays distinguishable from a link that never existed, which has a different remedy.

**Exactly one retry, and sometimes none.** After a reactive refresh the call is retried once; a token
minted seconds ago and refused immediately is not going to start working on the third attempt, and a
refresh loop against a provider's rate limiter is its own outage. If the token was *already* replaced
by the proactive path and the provider rejected it anyway, there is no retry at all — the grant
behind it is dead, and refreshing again would only spend another rotation to obtain another token
from the same dead grant.

**The refresh grant has no `state`, no PKCE and no redirect — and that is not an oversight.** Those
protect a flow that travels through the user agent, and this one never leaves the server: no browser,
no address bar, no user present. What authenticates the caller here is the client secret plus
possession of the refresh token. Which also makes the refresh token the more valuable of the two
secrets — an access token is worth eight hours, a refresh token is worth six months — so it goes
through the same `TokenProtector` and is subject to the same rule about never appearing in a log
line.

**A broken provider link answers `409`, not `401`.** The local session is entirely valid; it's the
GitHub connection that's broken. Returning `401` would tell the SPA the user is logged out and send
them to the wrong screen. The body carries a specific reason — `no_refresh_token`,
`refresh_token_rejected`, `token_rejected_after_refresh` — so "reconnect" can be offered with the
right explanation. `/api/connections` gained `reauthorizationRequired` and `canRefresh` for the same
purpose: both are facts *about* the connection, derived from the token columns without exposing them.

**The catch with GitHub specifically, stated plainly.** A standard GitHub **OAuth App** — which is
what this project registered in M0 — never issues a refresh token. Its access token doesn't expire,
so there is nothing to refresh, and the only M3 path it can actually reach is the dead end: revoke
the token upstream, the next call gets `401`, there's no refresh token to recover with, and the link
latches as needing re-authorization. That *is* the correct behaviour and it is worth seeing, but it
means the happy path can't be exercised against this provider as registered. Reaching it needs either
a GitHub **App** with expiring user tokens enabled, or Google in M4 — which is the more instructive
one anyway, since Google only issues a refresh token when explicitly asked
(`access_type=offline&prompt=consent`) and expires it after 7 days while the consent screen is in
Testing mode.

**Forcing the failure modes: `POST /api/dev/connections/{provider}/…`.** Verifying M3 by waiting out
a token lifetime isn't verification, it's an afternoon, and the interesting paths can't be reproduced
at all without clicking around in GitHub's settings. Four Development-only endpoints put a link into
each state on demand: `expire-access-token` (backdates the recorded expiry → proactive trigger),
`revoke-access-token` (replaces the token with a worthless one while *leaving the expiry alone* →
reactive trigger), `break-refresh-token` (→ dead-grant path), and `clear-reauthorization-latch` (to
re-run any of the above). They only ever damage the caller's own link — nothing there mints a token,
widens a scope, or reads one out — and every action returns `404` outside Development, checked inside
the action rather than at route registration, because a conditionally-mapped controller is one
refactor away from being unconditionally mapped. The sabotaged values are still written as real
ciphertext: raw junk in the column would fail at `Unprotect` with a crypto error, which is a
different failure than the one being simulated.

### Verifying M3

62 tests green (38 from M2, 24 new). The ones that carry the milestone:

- **The wire format of the refresh grant** — that it sends `grant_type=refresh_token` with the client
  credentials and *not* `code`/`code_verifier`, that `expires_in` and `refresh_token_expires_in` are
  converted from relative lifetimes to absolute instants at the moment the response arrives, and that
  a rotated `refresh_token` comes back out. Tested by stubbing the `HttpMessageHandler` rather than
  faking the client, because the details most likely to be wrong are exactly the ones a hand-written
  fake would assume correct.
- **That a failed refresh arrives as HTTP `200`** with an error in the body — a successful HTTP
  transaction reporting an unsuccessful OAuth one. `bad_refresh_token`, `invalid_grant` and
  `unauthorized_client` become a rejection; `server_error` deliberately does not.
- **Both triggers**, separately: a token inside the leeway refreshes before any request goes out, and
  a token the database calls valid but GitHub answers `401` to refreshes on the way back and retries.
- **That a token with no advertised expiry is never refreshed**, which is the GitHub OAuth App case.
- **The dead ends** — refresh token rejected, no refresh token to begin with, and a freshly refreshed
  token rejected anyway — each latching the link and each reporting its own reason; a latched link
  then stops calling the provider entirely, and the last of the three costs exactly one refresh POST
  rather than two.
- **That a `503` doesn't break the link**, so "unreachable" can't be mistaken for "revoked".
- **The rotation race**: five concurrent requests against one expired link produce exactly one refresh
  POST and all receive the same new token. Confirmed to be a real test by removing the shared lock and
  watching it fail.
- **That `ObtainedAtUtc` survives a refresh** while `RefreshedAtUtc` moves — "this grant is 30 days
  old but the token in it is four minutes old" is the state M3 exists to produce, and one timestamp
  can't express it.
- **That the BFF boundary held** across the four new columns: the serialized connection summary
  contains no `gho_`/`ghr_` material.

To walk it by hand against the running API (`?refreshed` in the response is the observable — a
transparent refresh leaves no other trace):

```
POST /api/dev/connections/GitHub/expire-access-token   # proactive trigger
POST /api/dev/connections/GitHub/revoke-access-token   # reactive trigger (expiry left looking healthy)
POST /api/dev/connections/GitHub/break-refresh-token   # dead-grant path
GET  /api/connections/GitHub/check                     # the observable, after any of the above
GET  /api/connections                                  # reauthorizationRequired / canRefresh
POST /api/dev/connections/GitHub/clear-reauthorization-latch
```

What `/check` answers depends on which provider registration is linked, and the difference is the
whole caveat above:

- **A link that has a refresh token** (a GitHub App with expiring user tokens, or Google from M4):
  the first two both answer `200 {"ok":true,"refreshed":true}` — the refresh happened and the user
  never saw it. Only `break-refresh-token` reaches `409`, with `reason: refresh_token_rejected`.
- **A stock GitHub OAuth App**, which has no refresh token at all: the first two answer
  `409 {"reason":"no_refresh_token"}` and `/api/connections` then reports
  `reauthorizationRequired: true`, `canRefresh: false`. Re-linking through the real consent flow
  clears it. (`break-refresh-token` only means anything on a link that has one to break.)

The happy path this registration can't produce is the one the automated tests cover — and, from M4
onwards, the one Google can be walked through by hand.

### M4 — Google, and what OIDC adds on top of OAuth2

M3 ended on a caveat: GitHub as registered can't demonstrate a working refresh. Google can, and
that's the smaller half of this milestone. The larger half is the distinction Google forces:
**OAuth2 answers "what may this app do", OpenID Connect answers "who is this"**, and the second is a
different kind of claim with a different kind of proof.

An access token is *opaque*. It says nothing; it is only spent, and the answer comes from the
provider. An `id_token` is a *signed assertion* that arrives in this app's own hands and is read
locally — which means it is worth exactly as much as the checks performed on it, and a JWT's payload
is base64, not ciphertext. An unvalidated `id_token` is a claim the sender wrote down about
themselves.

**The endpoints are discovered, not configured.** Everything Google's flow touches — authorize,
token, userinfo, JWKS, and the revocation endpoint M5 will need — comes out of
`https://accounts.google.com/.well-known/openid-configuration`, cached for a day. The one thing that
*is* configured is the authority, and that matters: OIDC Discovery §4.3 requires the `issuer` inside
the document to equal the authority it was served from, and this app enforces it. Skipping that check
is subtler than it looks, because the same document supplies the expected issuer that `id_token`
validation later compares against — a document naming a different issuer would **validate its own
tokens perfectly**. Issuer checking would run and check the wrong thing. The comparison has to be
against the value an attacker can't supply.

**Every `id_token` check, and the specific attack behind it.**

| Check | What it stops |
| --- | --- |
| Signature against the published JWKS | Without it, the token is a suggestion |
| Algorithm pinned to `RS256` | `alg: none`, and RS256→HS256 confusion |
| `iss` equals the discovered issuer | Any provider asserting any user; `sub` is per-issuer |
| `aud` equals this app's client id | A token Google minted for a *different* app becoming a login here |
| `exp`, with 30s skew | A short-lived assertion honoured long after it stopped being short-lived |
| `nonce` equals the one minted for this request | An `id_token` from another flow being replayed into this one |

Two of those are worth expanding. **The audience check is the one that looks redundant and isn't.** A
token from another Google client is genuinely Google's, genuinely signed, genuinely about this user —
it just wasn't issued to this application, and anyone with a Google client id can obtain one. And
**pinning the algorithm is a single line that closes both classic JWT breaks**, because both are the
same bug: letting the token's own header tell the verifier how to verify it. `alg: none` says "no
signature needed". HS256 confusion signs with HMAC using the provider's *public* key as the shared
secret — which is published, by design — so a verifier that looks up "the key for `kid` X" and uses
it however the header says finds an RSA public key and happily treats it as an HMAC secret.

**Nonce, state and PKCE are three different proofs and none substitutes for another.** `state` proves
*this callback answers a request we made*. `code_verifier` proves *this code is being redeemed by
whoever asked for it*. `nonce` proves *this id_token was minted for that same request*. All three are
now issued together in `OAuthStateStore` — the nonce as a separate random draw from the state, not a
copy of it, since the state is public by construction the moment it reaches the address bar.

Honest scoping on the nonce, in the same spirit as the PKCE note in M2: in the authorization **code**
flow it adds less than it looks. The token arrives over a server-to-server POST, bound to a
single-use code, itself bound to a verifier only this process holds. The nonce is what carries that
guarantee in the *implicit* and *hybrid* flows, where the token lands in the browser and none of the
above applies. It is implemented because the argument for skipping it depends on properties of the
current deployment, and those stop holding quietly.

**The one thing in this project that is deliberately not hand-rolled.** RSA signature verification and
JWKS parsing use `Microsoft.IdentityModel.JsonWebTokens`. Everything else — discovery, the nonce, the
issuer and audience comparisons, the token POSTs — is still written out against raw `HttpClient`. The
line is drawn there because the failure mode of a subtly wrong signature implementation is *accepts
forged tokens*, it is invisible in testing, and re-deriving PKCS#1 teaches nothing this project is
about.

**Signing keys rotate, and the refetch that handles it is a lever an attacker can pull.** Google
publishes several keys and rotates them regularly, so a token can legitimately arrive bearing a `kid`
the cached key set has never seen. The right response is to refetch — otherwise every rotation is an
outage until the cache happens to expire. But "unknown kid, go ask Google again" is an outbound
request this app performs on the say-so of an unauthenticated token, and an attacker can mint junk
headers all day. So the refetch has a five-minute floor, matching what `Microsoft.IdentityModel`'s own
`ConfigurationManager` defaults to. The cost is stated rather than hidden: a rotation within five
minutes of a cache fill is not picked up until the floor passes. That's safe in practice because
providers publish a new key well before signing with it, and the alternative is a request amplifier.

One thing worth knowing rather than assuming: **the `kid` is a hint, not a gate.** When it doesn't
match, the library tries every published key, and what rejects a forgery is the signature failing
against all of them. A test asserting "unknown kid is rejected" passes for the wrong reason.

**Google's conventions differ from GitHub's in ways that break a copied client.**

- **A rejected grant is HTTP `400`, not `200`.** GitHub reports OAuth failures as a successful HTTP
  transaction with an error in the body; Google uses the status code. A client that calls
  `EnsureSuccessStatusCode` first turns "your refresh token is dead" — permanent, actionable — into a
  generic transport exception, which `ProviderTokenService` quite correctly treats as transient and
  never latches on. So the body is parsed first, and the status code is consulted only for failures
  the body couldn't explain (a load balancer's HTML 5xx page, which must stay a transport failure).
- **The refresh token has to be asked for.** `access_type=offline` is what makes Google issue one at
  all; `prompt=consent` is what makes it issue one *again* on a repeat authorization. Without the
  second, a re-link returns an access token and no refresh token, the stored one is correctly kept,
  and the problem only surfaces whenever that older token finally dies.
- **The refresh token does not rotate.** Google returns no `refresh_token` on a refresh and expects
  the stored one to keep working — the mirror image of GitHub, which retires the old one every time.
  Both are covered by the rule M2 already established: write what the provider sent, keep what it
  didn't. (This makes M3's concurrency gate less load-bearing for Google, not wrong.)
- **`invalid_grant` covers everything.** Revoked, expired, invalidated by a password change — all one
  code, and the remedy is the same regardless. `invalid_client` is deliberately *not* treated as a
  dead grant: that means this app's own credentials are wrong, and telling the user to reconnect
  would be advice that can't work.
- **No refresh-token lifetime is advertised.** There is one (7 days while the consent screen is in
  Testing mode, otherwise until revoked or six months unused), but Google never states it, so
  `RefreshTokenExpiresAtUtc` stays null rather than putting a guessed date on the connections card.

**The link is keyed on `sub`, never on email.** Google is explicit that an address can be reassigned
and that a user can change theirs. `email_verified` is carried for display and because an *unverified*
address from any provider is a self-asserted string — matching accounts on one is the classic
takeover path — but neither is what the row is matched on.

**The identity comes from the assertion, not from an API call.** `GoogleAuthController` establishes
the link from the validated `id_token`; the userinfo endpoint exists only so
`/api/connections/Google/check` has a real call to spend the stored token on. A signed statement beats
a response that merely arrived over TLS, and the check endpoint needs the *token* exercised, not the
identity re-fetched.

**Nothing is persisted when validation fails.** The exchange returns a `GoogleAuthorizationResult`
carrying a `ValidatedIdToken` — a type only the validator can construct — or it throws. There is no
overload that hands back an unchecked assertion, so "the token part looked fine, store it anyway" is
not an available mistake. The callback maps that to `?error=id_token_invalid`.

**What did *not* have to change.** `ProviderTokenService` gained one line in a switch. The refresh
decision, the two triggers, the single retry, the failure taxonomy and the rotation gate are all
provider-agnostic and stayed exactly as M3 left them — which is the structural claim the milestone
makes, and the Google cases in `TokenRefreshTests` are there to hold it to that.

Also folded in, since M4 is the milestone where a second set of client credentials makes it matter:
startup now fails with a named message when either provider's `ClientId`/`ClientSecret`/`RedirectUri`
is missing. `required` members don't cover this — the configuration binder constructs the options
object without enforcing them — and the alternative is an opaque `invalid_client` from the provider,
three redirects later, with nothing pointing at user-secrets.

Still open: this is "link Google", not "log in with Google". Google now hands this app a verified
identity, so building a login on it would be a short step — and a separate decision, with its own
account-linking and takeover questions. The BFF split from M2 stands.

### Verifying M4

102 tests green (62 from M3, 40 new). The fake Google signs with a real 2048-bit RSA key it publishes
in a real JWKS, because a test asserting "a forged signature is rejected" is worthless against a stub
that only pretends to sign. The ones that carry the milestone:

- **Every `id_token` check, broken one at a time.** A signature from an unpublished key, a payload
  edited after signing, `alg: none`, an HS256 token signed with the provider's public key as the
  secret, the wrong issuer, an audience belonging to another application, an expired token, a nonce
  from a different flow, and a token with no nonce when one was requested — each rejected, each for
  its own reason. Written this way because a validator with signature checking quietly disabled passes
  every happy-path test ever written against it; only the negative cases can tell.
- **That a missing nonce is accepted only on the refresh path**, where no authorization request
  happened — and that the parameter has no default value, so skipping the check has to be deliberate.
- **Key rotation**, with new key material and a new `kid`: one refetch, then validation succeeds. And
  its counterpart — five forged tokens with unknown `kid`s produce **zero** extra requests to Google,
  because the floor holds.
- **Discovery**: the endpoints come from the document; a document naming a different issuer is
  rejected; one missing an endpoint this app needs is rejected; an empty key set is rejected; eight
  concurrent cold-start requests produce one fetch.
- **The wire format**: `access_type=offline` and `prompt=consent` present, the nonce alongside `state`
  and the S256 challenge, `expires_in` converted to an absolute instant, and the refresh grant sending
  no `code`, `code_verifier` or `redirect_uri`.
- **That Google's `400 invalid_grant` reaches the same latch as GitHub's `200 bad_refresh_token`**,
  while `invalid_client` does not, and an HTML `503` stays a transport failure.
- **That the stored refresh token survives repeated refreshes**, since Google never returns a new one.
- **That the BFF boundary holds for a second token vocabulary** — no `ya29.` or `1//` material in the
  serialized connection summary.

Verified against the real provider metadata as well: the discovery document at
`accounts.google.com` parses through this code with every required endpoint present, and its JWKS
resolves to four usable RS256 signing keys.

To walk it by hand, once the SPA and API are both running and you are logged in locally:

```
GET  /api/auth/google/authorize      # 302 to Google, carrying nonce + access_type + prompt
                                     # → consent → /api/auth/google/callback → SPA ?linked=google
GET  /api/connections                # Google alongside GitHub, canRefresh: true
GET  /api/connections/Google/check   # spends the stored token on userinfo
POST /api/dev/connections/Google/expire-access-token   # then /check → {"ok":true,"refreshed":true}
POST /api/dev/connections/Google/break-refresh-token   # then /check → 409 refresh_token_rejected
POST /api/dev/connections/Google/clear-reauthorization-latch
```

**This is where M3's happy path finally becomes observable against a real provider.** The GitHub OAuth
App could only ever reach the dead end; Google, having actually issued a refresh token, answers
`{"ok":true,"refreshed":true}` — a token replaced mid-request, with the user never sent near a consent
screen.

To watch validation fail closed rather than trusting it runs, the automated tests are the real
answer — each breaks exactly one check. By hand, the observable is the log: a successful link writes

```
Validated an id_token from https://accounts.google.com (sub: …, email_verified: True, nonce checked: True)
```

*before* anything is persisted. Temporarily change `ValidAudience` in `IdTokenValidator` to any other
string and re-link: Google still returns real tokens, that line never appears, nothing reaches the
database, and the SPA gets `?error=id_token_invalid`.

### M5 — one dashboard, real revocation, and scopes asked for one at a time

The first four milestones acquired tokens, protected them, and kept them alive. M5 is the one that
finally *spends* them for something the user asked for — and spending them turns three arguments into
code: what happens when several requests need the same token at once, what "unlink" is supposed to
mean, and whether "least privilege" is a claim or a check.

**`GET /api/dashboard` is one request, and that is the BFF's job description.** The alternative
architecture — the SPA calling GitHub and Google itself — requires the browser to hold provider
tokens, which is the one thing this project has spent five milestones not doing. So the fan-out happens
here, and what crosses to the browser is a normalized list of rows with no credential of any kind in it.

**Normalizing is the BFF earning its name twice.** Once for simplicity: one renderer instead of one per
provider. And once for exposure — a GitHub repository object has well over a hundred fields and a
calendar event carries attendee addresses, so a backend that forwards either verbatim has put all of it
in the browser's memory, its network log, and the reach of any script on the page. Five fields go out
because five fields get drawn. What the SPA never receives, an XSS bug on the SPA cannot read.

**`Task.WhenAll` is why per-widget failure isolation has to be deliberate.** It surfaces the *first*
exception its branches threw and discards the rest — so an aggregator whose branches are allowed to
throw doesn't merely fail, it fails while hiding what every other provider said. Every branch converts
its own failure into a result instead, which is what makes "GitHub is down, the calendar still renders"
true rather than aspirational. Each widget also gets its own timeout budget rather than the request
having one, so a slow provider costs its own card and not the page.

| Widget status | What it means | Remedy |
| --- | --- | --- |
| `ok` | Loaded | — |
| `not_linked` | No link row | Connect |
| `reauthorization_required` | M3's latch: broken past what a refresh can fix | Re-consent |
| `scope_required` | Healthy link, this permission never granted | Opt in to one scope |
| `permission_denied` | Token accepted, request refused | Depends — see below |
| `unavailable` | Provider unreachable, or answered unusably | Wait |
| `timed_out` | Provider too slow; the page didn't wait | Wait |

**Every one of those is a `200`.** The status code describes the aggregation, not the providers: the
request succeeded, and here is what each provider said. Mapping the worst widget onto the HTTP status
would make a dashboard where four cards work look broken — and a SPA that branches on 401 would go to
the login screen because GitHub had a bad minute.

**Three of those states are decided locally, before any request goes out.** Not linked, latched, and
missing-scope are all answerable from the link row, so they are answered there. Spending a provider
request to be told something the database already knew costs rate limit to learn nothing, and in the
scope case the provider's answer arrives as a 403 that looks like several other problems.

**Each branch runs in its own DI scope, and that is a correctness fix rather than a style choice.**
`DbContext` is not thread-safe, and everything on the token path — `LinkedAccountService`,
`ProviderTokenService` — is scoped to the request. Five widgets sharing one context is five concurrent
operations on it, which EF Core refuses outright ("a second operation was started on this context"). So
each widget gets a child scope with a context of its own. `RefreshLockRegistry` stays the singleton
every one of them shares, which is exactly what keeps the next paragraph true.

**The fan-out is the scenario M3's rotation gate was built for, and M5 is the code that causes it.**
Three GitHub widgets loading against a link whose access token expired five minutes ago is three
concurrent requests all noticing the same expiry. Without the per-(user, provider) gate, all three POST
the same refresh token; GitHub rotates it, so two of them present a credential GitHub has already
retired — which is precisely the signal a provider is entitled to read as a stolen refresh token and
answer by killing the grant. **The dashboard would log the user out of a provider nobody attacked.**
With the gate, one branch refreshes and the other two re-read the row and use its result. M3 argued
this case in the abstract; here it is a test that counts refresh POSTs and expects one.

**The fan-out holds a deliberate catch-all `Exception`, and that is rare here for a reason.** The other
broad catches in this codebase immediately narrow — `IdTokenValidator` and
`OpenIdConnectDiscoveryCache` rethrow as typed failures. Only two convert an unexpected failure into a
reported outcome, and both are M5's: this one, and the unreadable-credentials path in revocation. Here
it earns it — a provider that changes a field's type, a null where the shape promised a string,
anything unhandled in one widget's parsing must cost that widget and not the page. It logs at `Error`
precisely because it also catches genuine bugs, and a bug that only ever shows up as a grey card is a
bug nobody fixes.

#### Unlinking that the provider is told about

Before M5, `DELETE /api/connections/{provider}` deleted a row. That was never an unlink. **A token this
app discards keeps working**: GitHub still lists the authorization in the user's settings, Google still
counts the grant, and any leaked copy (a log line, a backup, the SQLite file from M2's threat model)
stays live for its full lifetime — while this app could mint a fresh token through `/authorize` **with no
consent screen shown**, because the user consented once and never took it back. Only the provider can
make a credential stop working.

**The two providers express "drop the grant" differently, and neither difference is cosmetic.**

- **GitHub revokes by application.** `DELETE /applications/{client_id}/grant`, *not* `…/token` — the
  token endpoint retires one access token and leaves the authorization standing, so it would remove a
  credential while leaving the permission that produces credentials. And the call is authenticated with
  **Basic `client_id:client_secret`**: the client secret proves the caller is the application whose
  grant is being dropped, while the access token travels in the *body* as the subject of the request.
  Sending it as a bearer token — the obvious guess — gets a 404, because the endpoint isn't addressed to
  the user. `404`/`422` are mapped to "already invalid": revoking a grant the user already removed from
  their settings page reaches the desired end state, and calling that a failure would leave a local row
  that can never be deleted.
- **Google revokes by token** (RFC 7009), at the `revocation_endpoint` from the discovery document —
  optional in the spec, so its absence is a real answer rather than a licence to guess a URL. **The
  refresh token is the one to send.** Revoking a refresh token takes the whole grant with it, derived
  access tokens included; revoking an access token retires one string and leaves the refresh token able
  to mint another, which is an unlink that undoes itself the next time anything asks for a token. RFC
  7009 says revoking an already-invalid token is a success; Google answers `400 invalid_token`, so that
  case is read out of the body rather than mistaken for an outage.

**This path deliberately does not go through `ProviderTokenService`,** which is otherwise the rule for
anything that spends a token. Refreshing in order to revoke mints a brand-new credential for the sole
purpose of destroying it — and with GitHub's rotation it spends the stored refresh token to do so, so a
revocation that then failed at the transport level would leave the row holding a rotated-away credential
that can never be revoked. Worse, a link already latched as needing re-authorization would raise
`ReauthorizationRequiredException` and turn "this link is broken" into "you may not remove it", which is
backwards. Revocation reads what is stored, sends it, and reports.

**Revocation is best-effort; the local delete is not.** The order is forced — after the delete there is
no credential left to present, so the grant could never be revoked afterwards. The "delete anyway" is a
judgement call, made explicit in the response: a provider outage must not be able to trap a user in a
link they asked to remove, and continuing to hold a token this app was told to discard is the worse of
the two failures. So the endpoint answers `200` with a body instead of `204`, because a no-content
response can only say "done", and "done" is not always the whole story:

```json
{ "provider": "Google", "deleted": true, "revoked": false,
  "revocationOutcome": "Unreachable", "detail": "provider_unreachable" }
```

`Revoked`, `AlreadyInvalid`, `NothingToRevoke`, `Unsupported`, `Unreachable` — five outcomes rather than
a bool, because "the provider had nothing left to revoke" and "the provider could not be reached" are
both *not revoked by us* and mean opposite things to a user. Only `Unreachable` leaves a live credential
in someone else's hands, and it is the one worth telling the user about, along with the honest remedy:
the provider's own settings page.

#### Least privilege, made checkable

A link starts with the scopes it cannot exist without — GitHub's `read:user` to put a name on the
connection card, Google's `openid email profile` to get an `id_token` at all. Everything past that
belongs to a widget and is asked for when that widget is switched on, via
`/api/auth/{provider}/authorize?grant=<key>`. The alternative — front-loading every scope the dashboard
might one day want into the first consent screen — is how users learn that a consent screen is a button
you click past.

**The request names a key, never a scope string, and that is the security property.** This is an
authenticated endpoint that redirects the user's browser to a consent screen. `?scope=repo,admin:org`
honoured verbatim would let anyone who can get this user to follow a link choose what the consent screen
asks for — and the provider would cheerfully honour it — whereas `?grant=organizations` can only resolve
to a scope this code already decided it wanted. An unrecognized key is a `400`, not a silent fallback to
base scope: falling back would send the user through a consent screen, come back looking successful, and
leave the widget still reporting that it needs a permission, with nothing anywhere saying why.

**Incremental authorization works differently at each provider.** GitHub unions new scopes into the
existing authorization, so a token minted now carries everything previously granted. Google does not:
without `include_granted_scopes=true`, a token minted for this request carries *only* the scopes this
request named, so adding the calendar widget would hand back a token that reads events and can no longer
read the profile the connection card is drawn from. (Both re-send the base set for the same reason.)

**Neither provider lets a grant be narrowed by re-authorizing** — GitHub never removes a scope from an
authorization, Google keeps every scope the user has ever approved for the client. So the only way back
down is revocation, which is why the two halves of this milestone are not a coincidence: *"ask for less
later" is only a real option if "give it all back" exists.*

**What is deliberately not on offer: GitHub's `repo`.** It is not a read-only upgrade — it is full read
*and write* on every private repository the user can reach, with no narrower alternative available to an
OAuth App. Asking for write access to everything in order to render a five-row list is the exact trade
least privilege exists to refuse, so the repositories widget is public-only and the limitation is stated
on the card rather than bought out with a scope. The request sends `visibility=public` anyway, even
though `read:user` could not return a private repository: if this app ever holds a token with `repo` on
it for some unrelated reason, the call must not quietly start putting private repository names on a card
that says "public repositories". A request that only behaves correctly because of a scope it doesn't
control is one scope change away from being wrong.

On the Google side the same instinct picks `calendar.events.readonly` over the more familiar
`calendar.readonly`: the widget reads events, and the narrower scope excludes the calendar metadata and
sharing rules it has no business seeing. Each optional scope is stored next to a **purpose** sentence,
because "we asked for calendar access" and "we asked for calendar access in order to list your next five
events" are different requests to a user — and only one of them can be checked against what the code
actually does.

**The scope-delimiter trap is worth writing down.** RFC 6749 makes a scope *request* space-delimited and
Google's responses follow suit, but GitHub answers with a **comma**-separated list
(`"read:user,read:org"`). Splitting on space alone finds one scope named `read:user,read:org`, matches
nothing, and the widget then reports that a permission the user actually granted is missing. Both
separators are accepted; the comparison itself is **ordinal**, because scope strings are opaque
identifiers and reporting a permission as granted on the strength of a near miss is the wrong direction
to be loose in.

**Google Calendar is a *resource* server, not the authorization server** — which is why it is a separate
client with a hardcoded URL. OIDC Discovery describes identity endpoints and says nothing about APIs, so
there was never going to be a `calendar_endpoint` in that document. Its `403` has two causes that must
not be flattened together: `insufficientPermissions` means the token lacks the scope and re-consenting
fixes it, while `accessNotConfigured` means the Calendar API is not enabled on this app's Google Cloud
project — and telling a user to re-consent for that is worse than telling them nothing. GitHub's `403`
needs the same care for a different reason: it spends that status on both a depleted rate limit and a
missing scope, and only `x-ratelimit-remaining: 0` separates them.

**What M5 does not buy.** Widget data isn't cached, so every dashboard load spends real provider
requests — fine for one user, and the first thing a rate limit would force a change to. Revocation
covers this app's own grant only; a token exfiltrated between the leak and the unlink already did
whatever it did. And a `scope_required` card is an invitation, not enforcement: it reports what the
*provider* said it granted, which is the only authority on the question — a provider that misreported its
own grant string would be believed.

### Verifying M5

152 tests green (102 from M4, 50 new), across the fan-out, revocation and the scope allowlist. The ones
that carry the milestone:

- **Exactly one refresh POST for three GitHub widgets on an expired link.** The refresh endpoint is held
  for 250 ms in the stub so the other two branches are genuinely queued on the gate rather than arriving
  after the first one finished. Confirmed to bite by re-registering `RefreshLockRegistry` as scoped,
  which makes it three POSTs — the assertion is worthless without knowing it can fail.
- **One widget's failure costs one card.** Asserted for a provider outage, separately for a widget whose
  *parsing* throws (the catch-all path), and for a widget that hangs past its timeout while the others
  still render.
- **Nothing is asked of a provider when the answer is already local**: nothing linked, a latched link, or
  a scope never granted all produce zero outbound requests.
- **A missing scope is distinguished from a depleted rate limit** — both GitHub `403` — and a dead grant
  arrives with M3's own vocabulary rather than a new one.
- **The reactive trigger through the fan-out**: a stored expiry that looks healthy, a provider answering
  `401`, and a widget that still renders — which only works because the catalog holds a re-runnable fetch
  delegate rather than a value.
- **No token vocabulary in the serialized dashboard** — no `gho_`, `ghr_`, `ya29.` or `1//` material
  anywhere in the response, and no `CfDJ8` either, since ciphertext is not an acceptable answer here
  either. The same boundary test M2 established, now applied to the endpoint that actually carries
  provider data.
- **Revocation targets the grant, not a token**: GitHub's call goes to `/grant` authenticated with the
  application's own credentials; Google's sends the **refresh** token, and falls back to the access token
  only when there is no refresh token to send. A `400 invalid_token` is read as already-revoked while any
  other `400` is not, and a provider outage reports `Unreachable` rather than claiming success.
- **Revocation does not refresh first** even when the stored token expired an hour ago, and **is still
  attempted for a link already latched as broken** — the two ways routing this through
  `ProviderTokenService` would have gone wrong.
- **The local row is deleted even when revocation could not be completed**, with the response saying so.
- **The allowlist refuses everything that is not a registered key**: `repo`, `admin:org`, a smuggled
  `read:org extra:thing`, a Gmail scope URL, the empty string — and keys don't leak across providers.
  These negative cases are the whole test: a registry that hands out whatever it is asked for passes
  every happy-path test there is, and the only thing wrong with it is where the request came from.
- **Every optional scope on offer is read-only and carries a purpose sentence**, asserted rather than
  assumed, because that is the kind of claim a README makes and a later commit quietly breaks.
- **Google's authorize URL always sends `include_granted_scopes=true`**, and both providers' URLs carry
  the base set plus exactly one grant.

Not covered by tests, and worth stating: the repositories and organizations calls are exercised against
the stub's shapes, not GitHub's real payloads — the field selection is verified by hand below.

To walk it by hand, logged in locally with the SPA and API running:

```
GET    /api/dashboard                                   # every widget, one response
GET    /api/auth/github/authorize?grant=organizations   # incremental consent → the organizations card fills in
GET    /api/auth/github/authorize?grant=nonsense        # 400 unknown_grant
POST   /api/dev/connections/GitHub/expire-access-token
GET    /api/dashboard                                   # one GitHub card reports "refreshed": true, all three render
POST   /api/dev/connections/GitHub/break-refresh-token
GET    /api/dashboard                                   # GitHub cards: reauthorization_required / refresh_token_rejected
                                                        # Google's cards unaffected — the isolation claim, visible
DELETE /api/connections/GitHub                          # {"deleted":true,"revoked":true,"revocationOutcome":"Revoked"}
```

**The revocation evidence is at the provider, not in this app's response.** After the `DELETE`, GitHub's
[authorized OAuth Apps](https://github.com/settings/applications) page no longer lists the app — and the
sharper check is to re-link immediately: **the consent screen appears again**. Before M5 it would not
have, because the authorization was still standing. For Google the equivalent is
[permissions](https://myaccount.google.com/permissions), where the app's entry disappears.

#### The Google Cloud console step the calendar widget needs

The calendar widget is complete in code and **reports `permission_denied` with reason
`accessNotConfigured` until two things are done in the Google Cloud project** — which is exactly the
distinction `GoogleCalendarClient` draws, and the reason it draws it: no amount of re-consenting fixes
this one.

1. **Enable the Google Calendar API** for the project (APIs & Services → Library → Google Calendar API →
   Enable). `accessNotConfigured` is the symptom of this step being missing.
2. **Add `https://www.googleapis.com/auth/calendar.events.readonly`** to the OAuth consent screen's
   scope list. Without it Google refuses the authorization request itself rather than the API call, so
   the symptom is an `invalid_scope` error on the redirect instead of a `403` on the widget.

Then `GET /api/auth/google/authorize?grant=calendar` shows a consent screen that names calendar access
specifically — the observable for the whole least-privilege half of this milestone: the *first* Google
link asked for identity only, and the calendar permission arrived on its own, later, when a widget needed
it. This is a sensitive scope, so with the consent screen in Testing mode it works for the project's own
test users and would need Google's verification to go further.

Still to come: nothing in the milestone plan. What the code invites next is caching for the fan-out and a
login built on the verified Google identity M4 produced — both separate decisions.

## Running locally

The dev certificate has to be trusted, otherwise the browser refuses the SPA's calls with
`ERR_CERT_AUTHORITY_INVALID` — and later refuses the provider's redirect back to
`https://localhost:7236` as well:

```
dotnet dev-certs https --trust
```

Then:

```
dotnet user-secrets init --project backend/src/OAuthDashboard.Api
dotnet run --launch-profile https --project backend/src/OAuthDashboard.Api
```

`GET https://localhost:7236/api/health` is the connectivity probe. Called twice from the SPA it
should report `cookieEchoed: true` on the second call.

The SQLite schema is applied on startup (`Database.MigrateAsync()`), so there's no separate
`dotnet ef database update` step — the app owns its schema, which keeps the M2 verification
("restart the process; are the tokens still readable?") a one-command exercise. `dotnet-ef` is
pinned as a repo-local tool for *creating* migrations:

```
dotnet dotnet-ef migrations add <Name> --project backend/src/OAuthDashboard.Infrastructure --startup-project backend/src/OAuthDashboard.Api --output-dir Persistence/Migrations
```

On first run the SPA's login screen offers to claim the single local account; after that it asks for
those credentials. To start over, delete `backend/src/OAuthDashboard.Api/oauthdashboard.db` (gitignored — it
holds encrypted provider tokens).
