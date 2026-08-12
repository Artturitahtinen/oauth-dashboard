import { useQuery } from '@tanstack/react-query'
import { API_BASE_URL } from './api/client'
import { fetchHealth } from './api/health'
import './App.css'

function App() {
  const { data, error, isPending, isFetching, refetch } = useQuery({
    queryKey: ['health'],
    queryFn: fetchHealth,
    retry: false,
  })

  return (
    <main className="shell">
      <h1>OAuth Dashboard</h1>
      <p className="lede">
        Milestone 0 — confirming this SPA can reach the backend at{' '}
        <code>{API_BASE_URL}</code> cross-origin, with cookies.
      </p>

      <section className="panel">
        {isPending && (
          <p className="status">
            <span className="dot wait" />
            Contacting backend…
          </p>
        )}

        {error && (
          <>
            <p className="status">
              <span className="dot bad" />
              Backend unreachable
            </p>
            <p className="error">{error.message}</p>
            <p className="hint">
              A bare <code>Failed to fetch</code> usually means the ASP.NET dev certificate
              isn’t trusted yet, or the backend isn’t running. Start it with{' '}
              <code>dotnet run --launch-profile https</code>.
            </p>
          </>
        )}

        {data && (
          <>
            <p className="status">
              <span className="dot ok" />
              Backend reachable
            </p>
            <dl className="facts">
              <dt>Status</dt>
              <dd>{data.status}</dd>
              <dt>Environment</dt>
              <dd>{data.environment}</dd>
              <dt>Cookie echoed</dt>
              <dd>{data.cookieEchoed ? 'yes' : 'not yet'}</dd>
            </dl>
            {!data.cookieEchoed && (
              <p className="hint">
                The backend just set a probe cookie. Check again — if credentialed CORS is
                wired up correctly, the browser sends it back and this flips to{' '}
                <code>yes</code>.
              </p>
            )}
          </>
        )}

        <button
          type="button"
          className="action"
          onClick={() => void refetch()}
          disabled={isFetching}
        >
          {isFetching ? 'Checking…' : 'Check again'}
        </button>
      </section>
    </main>
  )
}

export default App
