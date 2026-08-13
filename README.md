# OAuth Dashboard — Frontend

React + TypeScript (Vite) frontend for a personal dashboard that aggregates your own GitHub and Google data. Talks only to the sibling backend repo `backend-oauth-dashboard` (ASP.NET Core) — never directly to GitHub/Google.

## Architecture

Backend-for-Frontend (BFF): this SPA authenticates only against the backend's own session cookie (`credentials: 'include'` on every API call) and never receives a GitHub/Google access or refresh token itself. "Connect GitHub/Google" buttons do a full `window.location.href` navigation to the backend's `/api/auth/{provider}/authorize` endpoint — a real browser redirect, not a fetch — since the provider redirect_uri points at the backend, not this SPA.

## Stack

- `react-router-dom` for routing
- `@tanstack/react-query` for data fetching against the backend's `/api/dashboard` endpoint

## Status

M2 complete: local login, a route guard, and the Connections screen where providers get linked.
`src/api/client.ts` centralises the BFF invariant — every call goes to the backend base URL with
`credentials: 'include'`.

```
src/api/         client (BFF invariant + ApiError), session, connections
src/auth/        useSession hook, RequireAuth guard
src/components/  AppLayout (nav + sign out)
src/routes/      Login, Dashboard, Connections
```

The M0 `/api/health` connectivity panel is gone — `RequireAuth` now surfaces an unreachable backend
with the same dev-certificate guidance, so the standalone probe UI no longer earned its place. The
endpoint still exists on the backend.

Remaining widgets land alongside their backend milestone — see `backend-oauth-dashboard/README.md`
for the full plan.

## Notes from M2

**There is no `/oauth/callback` route here, deliberately.** Provider redirect URIs point at the
backend, which holds the client secret and does the exchange. This SPA is never handed an
authorization code. The backend redirects to `/connections?linked=github` (or `?error=<code>`) when
it's done, and that marker is the *only* thing that crosses back into this origin.

**Auth state is not stored client-side.** The session lives in an HttpOnly cookie this code cannot
read, so "am I signed in?" is a question only the backend can answer — that's what `useSession` is
for. There's no token in `localStorage`, no expiry to track, and no client-side auth state to drift
out of sync. An XSS bug on this page has nothing to steal.

**`RequireAuth` is a usability guard, not a security boundary.** It decides which screen to render
and nothing more. Every endpoint behind it is independently protected by `[Authorize]` on the server,
because anyone can edit the JavaScript that runs here.

**`Connection` has no token field, and won't get one.** Not even an encrypted one — putting
ciphertext in the browser's memory and network log buys nothing. That type *is* the BFF boundary: if
a token ever needs to appear in it to make a feature work, the feature belongs on the backend.

**"Check token" is the only control that proves a link works.** Every other field on the card comes
from an unencrypted column, so a card can read "Linked" while the token behind it is undecryptable
or revoked. That button asks the backend to decrypt the stored token and actually spend it on a
provider call.

**Local sign-in is not "Sign in with GitHub".** This form establishes who the local user is; linking
GitHub grants this app permission to read that user's GitHub data. Separate acts — collapsing them
would make the dashboard unusable the moment you unlink the provider you logged in with.

**Login failures stay vague on purpose.** The backend won't say whether a username exists;
`describeError` doesn't rewrite `invalid_credentials` into "no such user", which would give away
exactly what the backend withheld.

## Dev

The backend must be running on `https://localhost:7236` with a **trusted** dev certificate
(`dotnet dev-certs https --trust` in the backend repo), otherwise every call fails with a bare
`Failed to fetch` / `ERR_CERT_AUTHORITY_INVALID`.

```
npm install
npm run dev
```

Vite must be on port **5173** — that exact origin is what the backend's `Spa:Origin` allows and
redirects back to. If 5173 is already taken Vite silently picks 5174 and every call fails CORS, so
free the port rather than letting it fall through.

On first run the login screen offers to claim the single local account; after that it asks for those
credentials. To start over, delete `oauthdashboard.db` in the backend's API project.

Override the backend base URL with `VITE_API_BASE_URL` if the backend runs elsewhere; the origin
must also be allowed by the backend's `Spa:Origin` setting, since credentialed CORS forbids
wildcard origins.

Note: `react-router` 8.x (the CSRF-patched line for GHSA-qwww-vcr4-c8h2) requires Node ≥22.22.0; this project pins `react-router-dom@7.18.2` instead. That advisory only affects the unstable RSC APIs, which this SPA does not use, so the flagged version is safe here.
