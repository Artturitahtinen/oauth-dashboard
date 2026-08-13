import { apiGet, apiPost } from './client'

export interface Session {
  authenticated: boolean
  username: string | null
  /** True while nobody has claimed the single local account yet, which unlocks registration. */
  needsSetup: boolean
}

export interface Credentials {
  username: string
  password: string
}

/**
 * The one call that drives the login screen and the auth guard.
 *
 * Note what is *not* here: no token, no expiry, nothing to store. The session lives entirely in an
 * HttpOnly cookie this code cannot read, so "am I logged in?" is a question only the backend can
 * answer — which is the point. There's no client-side auth state to get out of sync, and an XSS bug
 * has nothing to steal.
 */
export function fetchSession(): Promise<Session> {
  return apiGet<Session>('/api/auth/session')
}

export function login(credentials: Credentials): Promise<Session> {
  return apiPost<Session>('/api/auth/login', credentials)
}

/** First-run claim of the single local account. The backend refuses once one exists. */
export function register(credentials: Credentials): Promise<Session> {
  return apiPost<Session>('/api/auth/register', credentials)
}

/**
 * Ends the local session. Deliberately does not touch linked providers — logging out of the
 * dashboard is not the same act as revoking GitHub's grant.
 */
export function logout(): Promise<void> {
  return apiPost<void>('/api/auth/logout')
}

/** Mirrors the backend's minimum; enforced there too, since this check is only a courtesy. */
export const MINIMUM_PASSWORD_LENGTH = 12
