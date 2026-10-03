import { apiDelete, apiGet, navigateToApi } from './client'

/**
 * Everything the SPA is allowed to know about a provider link.
 *
 * There is no token field, and there deliberately never will be — not even an encrypted one. This
 * type *is* the BFF boundary: if a token ever needs to appear here to make a feature work, that
 * feature belongs on the backend instead.
 */
export interface Connection {
  provider: string
  accountName: string | null
  scopes: string | null
  expiresAtUtc: string | null
  obtainedAtUtc: string
}

export interface ProviderDescriptor {
  /** Matches the backend's `OAuthProvider` enum name, which is what the routes bind to. */
  id: string
  label: string
  /** What linking this account will let the dashboard read, in plain language. */
  grants: string
}

/** Google arrives in M4; listing it now would render a button that 404s. */
export const PROVIDERS: ProviderDescriptor[] = [
  { id: 'GitHub', label: 'GitHub', grants: 'your public profile (read:user)' },
]

export function fetchConnections(): Promise<Connection[]> {
  return apiGet<Connection[]>('/api/connections')
}

/**
 * Starts the authorization code flow by handing the browser to the backend.
 *
 * A full navigation, not a fetch — the backend responds with a 302 to GitHub's consent screen, and
 * the user has to land on it to grant anything. Note the SPA never sees the authorization code or
 * the token: the whole redirect chain runs between the browser, GitHub, and the backend, and the
 * only thing that comes back to this origin is the final `?linked=` / `?error=` marker.
 */
export function startLink(provider: ProviderDescriptor): void {
  navigateToApi(`/api/auth/${provider.id.toLowerCase()}/authorize`)
}

/**
 * Drops the local link. Still local-only in M2 — the backend deletes its stored tokens but GitHub
 * continues to list the authorization until real revocation lands in M5.
 */
export function unlink(provider: string): Promise<void> {
  return apiDelete(`/api/connections/${provider}`)
}

export interface ConnectionCheck {
  provider: string
  ok: boolean
  accountName: string | null
  reason: string | null
}

/**
 * Asks the backend to decrypt the stored token and actually spend it on a provider call.
 *
 * This is the only way to tell a working link from a broken one: every other field on `Connection`
 * comes from an unencrypted column, so a card can read "Linked" while the token behind it is
 * undecryptable or revoked. The answer that comes back is the provider's, never the token.
 */
export function checkConnection(provider: string): Promise<ConnectionCheck> {
  return apiGet<ConnectionCheck>(`/api/connections/${provider}/check`)
}
