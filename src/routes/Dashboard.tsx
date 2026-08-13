import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { fetchConnections, PROVIDERS } from '../api/connections'
import { useSession } from '../auth/useSession'

/**
 * The dashboard proper is M5's job — the aggregated `/api/dashboard` endpoint and the per-provider
 * widgets don't exist yet. Until then this shows the state M2 actually established: a local
 * identity, and which providers have tokens sitting encrypted behind the BFF.
 */
export function Dashboard() {
  const { data: session } = useSession()

  const { data: connections } = useQuery({
    queryKey: ['connections'],
    queryFn: fetchConnections,
    retry: false,
  })

  const linkedCount = connections?.length ?? 0

  return (
    <main className="shell">
      <h1>Dashboard</h1>

      <p className="lede">
        Signed in as <strong>{session?.username}</strong>. Your provider tokens live on the backend,
        encrypted at rest — this page has never held one.
      </p>

      <section className="panel">
        <h2>Milestone 2</h2>
        <p className="hint">
          PKCE, encrypted persistence, and local login are in place. The aggregated GitHub and
          Calendar widgets arrive with <code>/api/dashboard</code> in M5.
        </p>

        <dl className="facts">
          <dt>Local account</dt>
          <dd>{session?.username}</dd>
          <dt>Providers linked</dt>
          <dd>
            {linkedCount} of {PROVIDERS.length}
          </dd>
          <dt>Tokens visible here</dt>
          <dd>none, by design</dd>
        </dl>

        {linkedCount === 0 && (
          <p className="hint">
            Nothing linked yet — <Link to="/connections">connect GitHub</Link> to store your first
            encrypted token.
          </p>
        )}
      </section>
    </main>
  )
}
