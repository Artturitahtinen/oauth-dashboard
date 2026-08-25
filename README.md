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
- [x] M3 — Refresh token flow
- [x] M4 — Google + OIDC
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

Still to come: real revocation on unlink and least-privilege scope expansion per widget (M5).

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
