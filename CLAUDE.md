# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

A deliberately hand-rolled OAuth2/OIDC learning project: the authorization code flow, PKCE, state
handling and the refresh grant are implemented against raw `HttpClient` rather than
`Microsoft.AspNetCore.Authentication.OAuth`/`...Google` middleware. **Do not replace the hand-rolled
flow with provider middleware** — the explicit implementation is the point of the project.

The React SPA lives in the sibling repo `frontend-oauth-dashboard`.

## Commands

```bash
dotnet build                                     # whole solution (net10.0)
dotnet test                                      # all tests (xUnit, currently 152)
dotnet test --filter "FullyQualifiedName~TokenRefreshTests"          # one class
dotnet test --filter "FullyQualifiedName~GetAccessTokenAsync_DoesNotRefreshATokenWithNoAdvertisedExpiry"  # one test

dotnet dev-certs https --trust                   # once; otherwise the SPA and the provider redirect both fail
dotnet run --launch-profile https --project src/OAuthDashboard.Api    # https://localhost:7236
```

Secrets live in `dotnet user-secrets` for `src/OAuthDashboard.Api` under `OAuth:GitHub:ClientId` /
`ClientSecret` and `OAuth:Google:ClientId` / `ClientSecret`. Non-secret config — `Spa:Origin`,
`ConnectionStrings:Dashboard`, `OAuth:{GitHub,Google}:RedirectUri`, `OAuth:Google:Authority` — is in
`appsettings.Development.json`. Startup throws if `Spa:Origin`, the connection string, or either
provider's ClientId/ClientSecret/RedirectUri is missing.

Two provider-side prerequisites live outside the repo and can't be fixed in code: the Google Cloud
project needs the **Calendar API enabled** and
`https://www.googleapis.com/auth/calendar.events.readonly` **listed on the consent screen**. Without
the first, `google.calendar` reports `permission_denied` / `accessNotConfigured`; without the second,
`?grant=calendar` is refused as `invalid_scope` at the redirect. Nothing else on the dashboard depends
on them — don't "fix" that widget in code.

Migrations (`dotnet-ef` is pinned as a repo-local tool in `dotnet-tools.json`):

```bash
dotnet dotnet-ef migrations add <Name> --project src/OAuthDashboard.Infrastructure \
  --startup-project src/OAuthDashboard.Api --output-dir Persistence/Migrations
```

There is no `database update` step — `Program.cs` calls `Database.MigrateAsync()` on startup. To
reset state, delete `src/OAuthDashboard.Api/oauthdashboard.db` (gitignored).

## Architecture

Backend-for-Frontend. The SPA authenticates only against this backend's own cookie session
(`oauthdash.session`); this backend is the only thing that ever holds a provider token.

- `OAuthDashboard.Core` — entities only (`User`, `LinkedAccount`, `OAuthProvider`). No dependencies.
- `OAuthDashboard.Infrastructure` — EF Core/SQLite, `GitHubOAuthClient`, `GoogleOAuthClient`,
  `GoogleCalendarClient`, `OpenIdConnectDiscoveryCache`, `IdTokenValidator`, `OAuthStateStore`,
  `TokenProtector`, `PasswordHasher`, `ProviderTokenService`, `RefreshLockRegistry`,
  `ProviderRevocationService`, `ProviderScopes`, and `Dashboard/` (`DashboardService`,
  `DashboardWidgets`, `DashboardContracts`).
- `OAuthDashboard.Api` — controllers, `Program.cs` (all DI and pipeline config; no extension-method
  indirection), `ClaimsPrincipalExtensions.GetUserId()`.

Two distinct identity concepts that must not be conflated: `SessionController` proves *who the local
user is* (username + PBKDF2 password, first-run registration only while the users table is empty);
`GitHubAuthController` / `GoogleAuthController` prove *what that user authorized this app to do at
that provider*. You log into the dashboard, then link providers to it. There is no "log in with
GitHub" — and although M4's `id_token` now gives Google a verified identity that a login could be
built on, that stays a separate decision.

`DashboardController` is the SPA's one data endpoint (M5): it fans out to every linked provider and
returns one normalized response. The template's `WeatherForecastController`/`WeatherForecast.cs` were
deleted in M5.

## Invariants worth knowing before editing

**Token material never reaches a response.** `LinkedAccountService` is the only route tokens take in
or out of the database, so encryption can't be forgotten at a call site. Its two return types encode
the boundary: `LinkedAccountSummary` (metadata only — this is what serializes to the SPA) versus
`StoredProviderTokens` (plaintext credentials, server-side only). Keep them separate; don't add
token fields to the summary, and don't return `StoredProviderTokens` from a controller. Not even
ciphertext goes to the browser.

**Provider payloads are cut down, never forwarded.** A widget maps into `DashboardItem`'s five fields
by hand. A GitHub repository object has 100+ fields and a calendar event carries attendee addresses,
so forwarding either verbatim re-creates in the browser the exposure the BFF exists to prevent — what
the SPA never receives, an XSS bug on the SPA cannot read. Don't add a passthrough field.

**Anything that spends a provider token goes through `ProviderTokenService`** (`GetAccessTokenAsync`
for the raw token, `CallAsync` when the call itself may need retrying after a reactive refresh).
`LinkedAccountService.GetAccessTokenAsync` answers "what is in the database" and does *not* refresh —
it exists for tests, not for call sites. **`ProviderRevocationService` is the one deliberate
exception**, and it must stay one: refreshing in order to revoke mints a credential to destroy it and
spends a rotating refresh token doing so, and a latched link would be refused outright — turning "this
link is broken" into "you may not remove it". Two tests hold that line.

**`ExpiresAtUtc == null` means "no expiry advertised", not "expired".** A stock GitHub OAuth App
issues a non-expiring access token and no refresh token; treating null as expired would send every
such link into a refresh path with nothing to refresh with. Guarded in
`ProviderTokenService.IsExpiringSoon` and asserted by tests.

**Refresh tokens rotate, so concurrent refresh is a correctness bug, not waste.** `RefreshLockRegistry`
is registered as a **singleton** (scoped would give every request its own mutex and protect nothing),
the refresh path re-reads the row after acquiring the gate, and the rotated refresh token is
persisted *before* the new access token is handed out.

**Failure taxonomy is load-bearing.** `RefreshTokenRejectedException` = the provider said this grant
is dead. `ReauthorizationRequiredException` = the app concluded the link can't self-heal (reasons:
`no_refresh_token`, `refresh_token_rejected`, `token_rejected_after_refresh`) → HTTP **409**, never
401: the local session is fine, and 401 would send the SPA to the login screen.
`ProviderNotLinkedException` → 404. Transport failures (`HttpRequestException`, 503, DNS) must never
break a link.

**The re-authorization latch (`ReauthorizationRequiredAtUtc`) is cleared only by a completed
consent** (`LinkedAccountService.UpsertAsync`) or a successful refresh — not by a restart, not by a
lucky call. Dead tokens are left in the row rather than nulled, so a broken link stays
distinguishable from one that never existed.

**Data Protection identifiers are effectively schema.** Changing the purpose string
`OAuthDashboard.ProviderTokens.v1`, or removing `SetApplicationName("OAuthDashboard")` in
`Program.cs`, makes every token already in SQLite undecryptable. The purpose string also keeps the
token protector and the cookie protector from being interchangeable.

**OAuth state is single-use *and* session-bound.** `OAuthStateStore.TryConsume` removes the entry
(stops replay); the callback additionally checks `pending.UserId == User.GetUserId()` (stops
cross-session account grafting). Both checks are needed — they defend different attacks. The `nonce`
in the same record is a *third* proof, not a substitute: state proves the callback answers a request
we made, the verifier proves the code is redeemed by whoever asked for it, the nonce proves the
`id_token` was minted for that same request.

**Redirect targets come from configuration, never from the request.** `redirect_uri` at the token
exchange and the post-callback SPA redirect are both built from config; a caller-supplied `?next=`
would be an open redirect on an authenticated endpoint.

**Token values never go in logs** — log scope, type, length, expiry, rotation flags instead. Failed
logins log nothing attacker-supplied and return an identical `401 invalid_credentials` for both
unknown user and wrong password (the unknown-user path still runs a full PBKDF2 verify against a
dummy hash, so timing matches).

**Cookie flags are forced by the topology.** SPA on `http://localhost:5173`, API on
`https://localhost:7236` differ in scheme, so they are cross-*site*: the session cookie needs
`SameSite=None` (+ `Secure`, + `HttpOnly`), and CORS must name the origin explicitly because
`AllowCredentials` is illegal with a wildcard.

**A dashboard branch never throws and never shares a `DbContext`.** `Task.WhenAll` surfaces only the
first exception and discards the rest, so a branch that throws doesn't just fail — it hides what every
other provider said. Every failure becomes a `DashboardWidgetResult`, including via a deliberate
catch-all `Exception` — one of only two here that convert an unexpected failure into a reported outcome
instead of rethrowing it typed (the other is revocation's unreadable-credentials path). Keep it last,
and keep it logging at `Error`: it also catches real bugs. Each branch runs in a **child DI scope**
because `DbContext` is not thread-safe; `RefreshLockRegistry` stays the singleton they all share,
which is what makes three widgets on one expired link produce **one** refresh POST rather than three
presentations of a rotated-away token.

**The dashboard answers 200 for everything except a bad local session.** Widget states (`not_linked`,
`reauthorization_required`, `scope_required`, `permission_denied`, `unavailable`, `timed_out`) are
facts in the body. Mapping the worst widget onto the HTTP status would make four working cards look
broken and, on a 401, send the SPA to the login screen because a provider had a bad minute. The three
locally-decidable states (not linked, latched, scope never granted) must stay answered from the link
row without a provider call.

**Unlink means revoke-then-delete, and the delete happens either way.** Revoke first, because after
the delete there is no credential left to present. Delete regardless, because a provider outage must
not trap a user in a link they asked to remove — the response reports which half happened, which is
why it is `200` with a body and not `204`. GitHub's **grant** endpoint (`/applications/{id}/grant`,
Basic client_id:client_secret, token in the body), not its token endpoint: the latter leaves the
authorization standing, so the app could mint a new token with no consent screen. Google's RFC 7009
endpoint from discovery, sent the **refresh** token: revoking an access token leaves the grant able to
mint another.

**A scope is named by allowlist key, never by scope string.** `/api/auth/{provider}/authorize?grant=`
resolves through `ProviderScopes.TryResolve`; an unknown key is a `400`, not a silent base-scope
fallback. A caller-chosen `scope` on an authenticated redirect endpoint is a privilege-escalation
primitive, and the provider would honour it. New scopes go in `ProviderScopes.Optional` with a purpose
sentence, read-only, and as narrow as the provider offers (`calendar.events.readonly`, not
`calendar.readonly`; **never** GitHub's `repo` — read *and* write on everything). Google needs
`include_granted_scopes=true` or an incremental authorization drops earlier grants from the new token.

**Granted-scope strings have two delimiters.** GitHub answers with commas, Google with spaces
(`ProviderScopes.IsGranted` accepts both, and compares **ordinally** — a near miss must not read as
granted). Splitting on space alone silently reports granted permissions as missing.

**`ProviderPermissionException` (403) is not part of the M3 taxonomy.** A 401 means "this credential
is no good" and a refresh may fix it; a 403 means "this credential is fine and may not do that", which
no refresh fixes and which must not latch the link. Its `Reason` is load-bearing:
`insufficientPermissions` is fixable by re-consenting, `accessNotConfigured` (Calendar API not enabled
on the Cloud project) is not — and GitHub spends 403 on rate limits too, separated only by
`x-ratelimit-remaining: 0`.

## Adding a provider

The refresh *decision* is provider-agnostic and stays in `ProviderTokenService`. The seams to touch:
the `OAuthProvider` enum, a new client + options class + `AddHttpClient` registration in
`Program.cs`, the `RefreshWithProviderAsync` switch, the `identityCall` switch in
`ConnectionsController.Check`, `ProviderScopes.BaseFor`, the `RevokeWithProviderAsync` switch in
`ProviderRevocationService`, and a `{provider}AuthController`. Google (M4) is the worked example.

## Adding a dashboard widget

Add an entry to `DashboardWidgets.All` and nothing else — the fan-out, per-widget failure isolation,
the scope check and refresh handling are all generic over that list. Three rules the catalog encodes:
resolve clients out of the `IServiceProvider` the widget is **handed** (that is the branch's child
scope; closing over an injected client puts every branch back on one `DbContext`); the `Fetch`
delegate may run **twice**, since `CallAsync` retries after a reactive refresh, so it must be safe to
repeat — reads are, side effects are not; and if the widget needs a permission the base link doesn't
have, give it a `RequiredGrant` from `ProviderScopes.Optional` rather than widening the base scope.

## OIDC specifics (M4, Google)

**`id_token` validation is the milestone, and every check is load-bearing.** `IdTokenValidator`
enforces signature (against the discovered JWKS), `ValidAlgorithms = [RS256]` (this one line closes
both `alg: none` and RS256→HS256 confusion — never let the header pick the algorithm), issuer,
audience (a token Google minted for *another* app is genuinely valid and must still be refused), a
30-second lifetime skew, and the nonce. `ValidatedIdToken` can only be produced by the validator, so
no call site can read claims out of an unverified JWT. Nothing is persisted if validation fails.

**`expectedNonce` has no default value on purpose** — `null` means "the refresh path, where no
authorization request happened", and a check skippable by forgetting an argument will be skipped.

**Endpoints come from the discovery document**, never hardcoded; only the authority is configured.
`OpenIdConnectDiscoveryCache` enforces OIDC Discovery §4.3 (the document's `issuer` must equal the
authority it was fetched from) — without it a substituted document would supply *both* the tokens and
the expected issuer they're checked against. It is a **singleton**; the on-demand JWKS refetch for an
unknown `kid` is rate-limited to once per five minutes because that fetch is attacker-triggerable.

**Google's conventions differ from GitHub's** in four ways a copied client gets wrong: a rejected
grant is HTTP `400` (parse the body *before* `EnsureSuccessStatusCode`, or a dead grant becomes an
un-latched transport error); the refresh token does not rotate and is absent from refresh responses;
`access_type=offline&prompt=consent` are required to get one at all; `invalid_grant` is a dead grant
but `invalid_client` is not (that's this app's own credentials). The "write what the provider sent,
keep what it didn't" rule in `LinkedAccountService` covers both providers' opposite behaviours.

**Links are keyed on `sub`, never email**, and the identity at link time comes from the signed
`id_token`, not from userinfo. Userinfo exists so `/check` has a real call to spend the token on.

## Development-only sabotage endpoints

`TokenLabController` (`POST /api/dev/connections/{provider}/…`) forces each M3 state on demand:
`expire-access-token` (proactive trigger), `revoke-access-token` (reactive trigger),
`break-refresh-token` (dead-grant path), `clear-reauthorization-latch`. Two rules if you extend it:
the Development check happens **inside every action** (not at route registration) and returns 404;
and sabotaged values are written as real `TokenProtector` ciphertext, since raw junk would fail at
`Unprotect` with a crypto error — a different failure than the one being simulated.

`GET /api/connections/{provider}/check` is the observable for both encryption-at-rest and transparent
refresh (`"refreshed": true`); every other field on the connections response comes from an
unencrypted column and would look healthy even with a broken protector. Since M4 it works for Google
too — and Google is the only registration here that can reach the *happy* refresh path, because a
stock GitHub OAuth App has no refresh token to spend.

`GET /api/dashboard` is the second observable, and the sabotage endpoints drive it too:
`break-refresh-token` on GitHub should leave every GitHub card `reauthorization_required` with
Google's cards untouched (the isolation claim, visible), while `expire-access-token` should produce
`"refreshed": true` on a card with the others still rendering.

## Testing conventions

- Provider behaviour is tested by substituting the **`HttpMessageHandler`** (`StubGitHubHandler`),
  not by faking `GitHubOAuthClient` — the wire details (which form fields the refresh grant sends,
  that a *failed* exchange arrives as HTTP 200 with an error in the body, that `expires_in` is
  relative) are exactly what a hand-written fake would assume correct.
- `TokenRefreshTests` uses a **file-backed** temp SQLite database with a fresh `DashboardDbContext`
  per simulated request; the concurrency test is meaningless with a shared in-memory connection.
  It calls `SqliteConnection.ClearAllPools()` before deleting the file (Windows keeps handles open).
- Use one `TokenProtector` over an `EphemeralDataProtectionProvider` across contexts — separate
  provider instances hold separate keys.
- Assert published vectors where they exist (`PkceTests` uses RFC 7636 Appendix B): a wrong S256
  implementation still produces a plausible 43-character challenge and only fails later as an opaque
  `invalid_grant`.
- `FakeGoogle` serves discovery, JWKS, token and userinfo from one handler and signs with a **real**
  RSA key pair it really publishes — a test asserting "a forged signature is rejected" proves nothing
  against a stub that only pretends to sign. Its `CreateIdToken` defaults every parameter to the value
  that *passes*, so each test names only the thing it is breaking.
- `id_token` checks are tested by breaking exactly one at a time. A validator with signature checking
  quietly disabled passes every happy-path test ever written against it.
- `FakeGitHub` is shared (its own file, not nested in `TokenRefreshTests`) and both stub handlers
  support an **awaited** per-request delay. A stub that blocks its thread also blocks the branch about
  to start, and a fan-out under test then never actually overlaps — the concurrency assertion passes
  for the wrong reason.
- Concurrency claims are checked by counting provider requests, and confirmed to bite by breaking the
  thing they protect: `Build_RefreshesExactlyOnceForAllOfOneProvidersWidgets` was verified by
  re-registering `RefreshLockRegistry` as scoped, which makes it three POSTs.
- The scope allowlist is tested through its **negative** cases (`repo`, `admin:org`, a smuggled
  `read:org extra:thing`, a Gmail URL, empty). A registry that hands out whatever it is asked for
  passes every happy-path test there is; the only thing wrong with it is where the request came from.
  Same reason `Optional_OffersOnlyReadOnlyScopes` exists: "we only ask for read access" is the kind of
  claim a README makes and a later commit quietly breaks.

## Documentation conventions

`README.md` is the project's real artifact: a per-milestone log of *why* each security decision was
made, plus the evidence each milestone was verified with. When you complete a milestone or change a
security-relevant behaviour, update the matching README section — including what the change does
*not* buy. Code comments follow the same style: they explain the reasoning and the failure mode
avoided, not what the line does. Match that when adding code.
