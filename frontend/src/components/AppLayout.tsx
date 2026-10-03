import { NavLink, Outlet } from 'react-router-dom'
import { useLogout, useSession } from '../auth/useSession'

/** Chrome shared by the authenticated routes: where you are, who you are, and the way out. */
export function AppLayout() {
  const { data: session } = useSession()
  const { mutate: signOut, isPending: isSigningOut } = useLogout()

  return (
    <>
      <header className="topbar">
        <nav className="tabs">
          <NavLink to="/" end>
            Dashboard
          </NavLink>
          <NavLink to="/connections">Connections</NavLink>
        </nav>

        <div className="whoami">
          {session?.username && <span className="username">{session.username}</span>}
          <button
            type="button"
            className="action subtle"
            onClick={() => signOut()}
            disabled={isSigningOut}
          >
            {isSigningOut ? 'Signing out…' : 'Sign out'}
          </button>
        </div>
      </header>

      <Outlet />
    </>
  )
}
