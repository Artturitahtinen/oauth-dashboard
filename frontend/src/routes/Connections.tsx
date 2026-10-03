import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import {
  checkConnection,
  fetchConnections,
  PROVIDERS,
  startLink,
  unlink,
  type Connection,
  type ProviderDescriptor,
} from '../api/connections'

const connectionsQueryKey = ['connections'] as const

/**
 * Where provider accounts get linked — and where the callback lands.
 *
 * The backend redirects here after the OAuth round trip with `?linked=github` or `?error=<code>`,
 * which is the *only* thing that crosses back into this origin. No code, no token: the entire
 * exchange happened between the browser, GitHub, and the backend.
 */
export function Connections() {
  const [searchParams, setSearchParams] = useSearchParams()
  const queryClient = useQueryClient()

  const { data: connections, isPending, error } = useQuery({
    queryKey: connectionsQueryKey,
    queryFn: fetchConnections,
    retry: false,
  })

  const { mutate: removeLink, isPending: isUnlinking } = useMutation({
    mutationFn: unlink,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: connectionsQueryKey }),
  })

  const linked = searchParams.get('linked')
  const callbackError = searchParams.get('error')

  const dismissCallbackResult = () => {
    // Clears `?linked=`/`?error=` so a refresh or a Back navigation doesn't replay a stale banner
    // that no longer describes anything that just happened.
    setSearchParams({}, { replace: true })
  }

  return (
    <main className="shell">
      <h1>Connections</h1>
      <p className="lede">
        Linking a provider stores its tokens on the backend, encrypted. They are never sent to this
        page — the browser only ever learns <em>that</em> an account is linked.
      </p>

      {linked && (
        <div className="panel notice ok">
          <p>
            <strong>{linked}</strong> linked. The access token was exchanged server-side, encrypted,
            and written to the database.
          </p>
          <button type="button" className="action subtle" onClick={dismissCallbackResult}>
            Dismiss
          </button>
        </div>
      )}

      {callbackError && (
        <div className="panel notice bad">
          <p>{describeCallbackError(callbackError)}</p>
          <p className="hint">
            Backend error code: <code>{callbackError}</code>
          </p>
          <button type="button" className="action subtle" onClick={dismissCallbackResult}>
            Dismiss
          </button>
        </div>
      )}

      {isPending && (
        <p className="status">
          <span className="dot wait" />
          Loading connections…
        </p>
      )}

      {error && (
        <div className="panel">
          <p className="error">Could not load connections: {error.message}</p>
        </div>
      )}

      {connections && (
        <ul className="providers">
          {PROVIDERS.map((provider) => (
            <ProviderCard
              key={provider.id}
              provider={provider}
              connection={connections.find((c) => c.provider === provider.id)}
              onLink={() => startLink(provider)}
              onUnlink={() => removeLink(provider.id)}
              isBusy={isUnlinking}
            />
          ))}
        </ul>
      )}

      <p className="hint footnote">
        Unlinking currently deletes the backend&rsquo;s stored tokens but does not yet call
        GitHub&rsquo;s revoke endpoint, so the authorization stays listed in your GitHub settings.
        Real revocation lands in M5 — deleting a local row is not revocation.
      </p>
    </main>
  )
}

function ProviderCard({
  provider,
  connection,
  onLink,
  onUnlink,
  isBusy,
}: {
  provider: ProviderDescriptor
  connection: Connection | undefined
  onLink: () => void
  onUnlink: () => void
  isBusy: boolean
}) {
  const check = useMutation({ mutationFn: checkConnection })

  return (
    <li className="panel provider">
      <div className="provider-head">
        <h2>{provider.label}</h2>
        <span className={`badge ${connection ? 'ok' : ''}`}>
          {connection ? 'Linked' : 'Not linked'}
        </span>
      </div>

      {connection ? (
        <>
          <dl className="facts">
            <dt>Account</dt>
            <dd>{connection.accountName ?? 'unknown'}</dd>
            <dt>Granted scopes</dt>
            <dd>{connection.scopes || 'none reported'}</dd>
            <dt>Linked at</dt>
            <dd>{new Date(connection.obtainedAtUtc).toLocaleString()}</dd>
            <dt>Token expires</dt>
            {/* Null means the provider advertised no expiry, which is different from "expired" —
                a GitHub OAuth App token simply doesn't expire. M3 leans on that distinction. */}
            <dd>
              {connection.expiresAtUtc
                ? new Date(connection.expiresAtUtc).toLocaleString()
                : 'no expiry advertised'}
            </dd>
          </dl>

          {check.data && (
            <p className="status check">
              <span className={`dot ${check.data.ok ? 'ok' : 'bad'}`} />
              {check.data.ok
                ? `Stored token decrypted and accepted by the provider as ${check.data.accountName}.`
                : `Stored token was rejected (${check.data.reason}).`}
            </p>
          )}

          {check.error && <p className="error">Check failed: {check.error.message}</p>}

          <div className="row">
            {/* The only control that proves the link actually works: everything above it is
                metadata from unencrypted columns and would render identically if the token were
                undecryptable. */}
            <button
              type="button"
              className="action subtle"
              onClick={() => check.mutate(connection.provider)}
              disabled={check.isPending}
            >
              {check.isPending ? 'Checking…' : 'Check token'}
            </button>
            <button type="button" className="action subtle" onClick={onUnlink} disabled={isBusy}>
              Unlink
            </button>
          </div>
        </>
      ) : (
        <>
          <p className="hint">Grants read access to {provider.grants}.</p>
          <button type="button" className="action" onClick={onLink}>
            Connect {provider.label}
          </button>
        </>
      )}
    </li>
  )
}

/** Maps the codes `GitHubAuthController` redirects back with onto something a human can act on. */
function describeCallbackError(code: string): string {
  switch (code) {
    case 'access_denied':
      return 'You declined the authorization at GitHub, so nothing was linked.'
    case 'invalid_state':
      return 'That callback could not be matched to a link you started — it may have expired, already been used, or the backend restarted mid-flow. Try connecting again.'
    case 'state_session_mismatch':
      return 'That authorization was started by a different session and was refused. Try connecting again from this tab.'
    case 'missing_code':
      return 'GitHub returned no authorization code, so there was nothing to exchange.'
    case 'exchange_failed':
      return 'GitHub rejected the token exchange. Check the backend log for the reason it gave.'
    case 'provider_unreachable':
      return 'The backend could not reach GitHub to exchange the code. Check your connection and try again.'
    default:
      return 'Linking failed. Check the backend log for details.'
  }
}
