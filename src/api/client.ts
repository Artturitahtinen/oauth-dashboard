// The BFF is the only host this app talks to. GitHub and Google are never called from here —
// the backend is the sole holder of provider tokens, and this SPA's only credential is the
// backend's own session cookie.
export const API_BASE_URL: string =
  import.meta.env.VITE_API_BASE_URL ?? 'https://localhost:7236'

export async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    // The session cookie belongs to the backend's origin, so it only rides along when the
    // request opts in. Without this every call would arrive anonymous.
    credentials: 'include',
  })

  if (!response.ok) {
    throw new Error(`${response.status} ${response.statusText}`)
  }

  return (await response.json()) as T
}
