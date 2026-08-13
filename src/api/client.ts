// The BFF is the only host this app talks to. GitHub and Google are never called from here —
// the backend is the sole holder of provider tokens, and this SPA's only credential is the
// backend's own session cookie.
export const API_BASE_URL: string =
  import.meta.env.VITE_API_BASE_URL ?? 'https://localhost:7236'

/**
 * A failed API call, carrying the backend's own `error` code alongside the HTTP status.
 *
 * The status alone isn't enough to react well: a 401 from `/api/auth/login` means "wrong
 * credentials" and belongs next to the password field, while a 401 from any other endpoint means
 * the session lapsed and the whole app should fall back to the login screen.
 */
export class ApiError extends Error {
  readonly status: number
  /** The backend's machine-readable `error` field, when it sent one. */
  readonly code: string | null

  constructor(status: number, code: string | null, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }

  get isUnauthorized(): boolean {
    return this.status === 401
  }
}

async function request(path: string, init?: RequestInit): Promise<Response> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    // The session cookie belongs to the backend's origin, so it only rides along when the
    // request opts in. Without this every call would arrive anonymous.
    credentials: 'include',
  })

  if (!response.ok) {
    throw new ApiError(
      response.status,
      await readErrorCode(response),
      `${response.status} ${response.statusText}`,
    )
  }

  return response
}

/** Pulls the backend's `{ error: "..." }` code out of a failure body, tolerating an empty one. */
async function readErrorCode(response: Response): Promise<string | null> {
  try {
    const body: unknown = await response.json()
    if (body && typeof body === 'object' && 'error' in body) {
      const code = (body as { error: unknown }).error
      return typeof code === 'string' ? code : null
    }
  } catch {
    // A non-JSON error body (an HTML error page, or nothing at all) is not itself an error.
  }

  return null
}

export async function apiGet<T>(path: string): Promise<T> {
  return (await (await request(path)).json()) as T
}

export async function apiPost<T>(path: string, body?: unknown): Promise<T> {
  const response = await request(path, {
    method: 'POST',
    headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })

  // 204 is a success with nothing to parse (logout), so this can't unconditionally call .json().
  return (response.status === 204 ? undefined : await response.json()) as T
}

export async function apiDelete(path: string): Promise<void> {
  await request(path, { method: 'DELETE' })
}

/**
 * Hands the browser over to a backend endpoint as a real top-level navigation.
 *
 * This has to be a navigation and not a fetch: the endpoint answers with a 302 to the provider's
 * consent screen, and the user needs to actually *arrive* there and see what they're authorizing.
 * A fetch would follow the redirect invisibly and hand back GitHub's HTML, which is useless.
 */
export function navigateToApi(path: string): void {
  window.location.href = `${API_BASE_URL}${path}`
}
