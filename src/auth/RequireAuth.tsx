import type { ReactNode } from 'react'
import { Navigate, useLocation } from 'react-router-dom'
import { useSession } from './useSession'

/**
 * Gates the authenticated routes behind the backend's answer to "is this cookie valid?".
 *
 * Worth being honest about what this is: a *usability* guard, not a security boundary. It decides
 * which screen to render, and nothing more. Every endpoint behind it is independently protected by
 * `[Authorize]` on the server, because anyone can edit the JavaScript that runs here. A client-side
 * route guard that was the only thing standing between a caller and the data would be no protection
 * at all.
 */
export function RequireAuth({ children }: { children: ReactNode }) {
  const { data: session, isPending, error } = useSession()
  const location = useLocation()

  if (isPending) {
    return (
      <main className="shell">
        <p className="status">
          <span className="dot wait" />
          Checking your session…
        </p>
      </main>
    )
  }

  if (error) {
    return (
      <main className="shell">
        <h1>Backend unreachable</h1>
        <div className="panel">
          <p className="error">{error.message}</p>
          <p className="hint">
            Start the API with <code>dotnet run --launch-profile https</code>, and make sure the dev
            certificate is trusted (<code>dotnet dev-certs https --trust</code>).
          </p>
        </div>
      </main>
    )
  }

  if (!session?.authenticated) {
    // `replace` keeps the bounced-from URL out of history, so Back doesn't land the user on a page
    // that will immediately bounce them again. The attempted path rides along in state so the login
    // screen can return them where they were headed.
    return <Navigate to="/login" replace state={{ from: location.pathname }} />
  }

  return children
}
