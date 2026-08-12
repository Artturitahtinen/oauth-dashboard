# OAuth Dashboard — Frontend

React + TypeScript (Vite) frontend for a personal dashboard that aggregates your own GitHub and Google data. Talks only to the sibling backend repo `backend-oauth-dashboard` (ASP.NET Core) — never directly to GitHub/Google.

## Architecture

Backend-for-Frontend (BFF): this SPA authenticates only against the backend's own session cookie (`credentials: 'include'` on every API call) and never receives a GitHub/Google access or refresh token itself. "Connect GitHub/Google" buttons do a full `window.location.href` navigation to the backend's `/api/auth/{provider}/authorize` endpoint — a real browser redirect, not a fetch — since the provider redirect_uri points at the backend, not this SPA.

## Stack

- `react-router-dom` for routing
- `@tanstack/react-query` for data fetching against the backend's `/api/dashboard` endpoint

## Status

M0 complete. `src/api/client.ts` centralises the BFF invariant — every call goes to the backend
base URL with `credentials: 'include'` — and `App.tsx` renders a connectivity panel against
`/api/health` that also proves a backend-set cookie survives the cross-origin round trip.

Routes/widgets land alongside the corresponding backend milestone — see
`backend-oauth-dashboard/README.md` for the full milestone plan.

## Dev

The backend must be running on `https://localhost:7236` with a **trusted** dev certificate
(`dotnet dev-certs https --trust` in the backend repo), otherwise every call fails with a bare
`Failed to fetch` / `ERR_CERT_AUTHORITY_INVALID`.

```
npm install
npm run dev
```

Override the backend base URL with `VITE_API_BASE_URL` if the backend runs elsewhere; the origin
must also be allowed by the backend's `Spa:Origin` setting, since credentialed CORS forbids
wildcard origins.

Note: `react-router` 8.x (the CSRF-patched line for GHSA-qwww-vcr4-c8h2) requires Node ≥22.22.0; this project pins `react-router-dom@7.18.2` instead. That advisory only affects the unstable RSC APIs, which this SPA does not use, so the flagged version is safe here.
