import { useMutation, useQuery, useQueryClient, type UseQueryResult } from '@tanstack/react-query'
import { ApiError } from '../api/client'
import { fetchSession, login, logout, register, type Credentials, type Session } from '../api/session'

export const sessionQueryKey = ['session'] as const

/**
 * The app's single source of truth for "who am I", asked of the backend rather than remembered here.
 *
 * `retry: false` matters: an unauthenticated caller still gets a successful 200 with
 * `authenticated: false`, so a failure from this endpoint means the backend is actually unreachable
 * — retrying it three times would just delay the error screen.
 */
export function useSession(): UseQueryResult<Session, Error> {
  return useQuery({
    queryKey: sessionQueryKey,
    queryFn: fetchSession,
    retry: false,
    // The cookie can lapse or be cleared out from under us, so this is re-checked when the tab
    // regains focus rather than trusted for the lifetime of the page.
    refetchOnWindowFocus: true,
  })
}

/**
 * Signs in (or claims the account on first run) and replaces the cached session with the result, so
 * the guard re-evaluates immediately instead of waiting for a refetch.
 */
export function useLogin(mode: 'login' | 'register') {
  const queryClient = useQueryClient()

  return useMutation<Session, ApiError, Credentials>({
    mutationFn: (credentials) => (mode === 'register' ? register(credentials) : login(credentials)),
    onSuccess: (session) => queryClient.setQueryData(sessionQueryKey, session),
  })
}

export function useLogout() {
  const queryClient = useQueryClient()

  return useMutation<void, Error, void>({
    mutationFn: logout,
    // Everything cached was fetched as the previous user and none of it is theirs to see anymore.
    // Clearing the whole cache is the blunt-but-correct move here; selectively invalidating would
    // leave connection data sitting in memory after sign-out.
    onSuccess: () => queryClient.clear(),
  })
}
