import { useState, type FormEvent } from 'react'
import { Navigate, useLocation, useSearchParams } from 'react-router-dom'
import { MINIMUM_PASSWORD_LENGTH } from '../api/session'
import { useLogin, useSession } from '../auth/useSession'

/**
 * Local sign-in — deliberately *not* "Sign in with GitHub".
 *
 * The distinction is the one worth internalizing from this milestone: this form establishes who the
 * local user is, and linking GitHub (on Connections) grants this app permission to read that user's
 * data at GitHub. They're separate acts. Collapsing them into "log in with GitHub" would make the
 * dashboard unusable the moment you unlink the provider you logged in with.
 */
export function Login() {
  const { data: session, isPending } = useSession()
  const location = useLocation()
  const [searchParams] = useSearchParams()

  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')

  const needsSetup = session?.needsSetup === true
  const mode = needsSetup ? 'register' : 'login'
  const { mutate: submit, isPending: isSubmitting, error } = useLogin(mode)

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

  if (session?.authenticated) {
    const from = (location.state as { from?: string } | null)?.from
    return <Navigate to={from && from !== '/login' ? from : '/'} replace />
  }

  const handleSubmit = (event: FormEvent) => {
    event.preventDefault()
    submit({ username, password })
  }

  const passwordTooShort = mode === 'register' && password.length > 0 && password.length < MINIMUM_PASSWORD_LENGTH

  return (
    <main className="shell">
      <h1>{needsSetup ? 'Claim your dashboard' : 'Sign in'}</h1>

      <p className="lede">
        {needsSetup ? (
          <>
            Nobody has claimed this dashboard yet, so this first sign-up creates the single local
            account. Registration closes as soon as it exists.
          </>
        ) : (
          <>
            This is the dashboard&rsquo;s own local login. Connecting GitHub comes afterwards — it
            grants access to your data, it isn&rsquo;t how you sign in.
          </>
        )}
      </p>

      {searchParams.get('reason') === 'session_expired' && (
        <div className="panel notice">
          <p>Your session expired, so that action was cancelled. Sign in and try again.</p>
        </div>
      )}

      <form className="panel form" onSubmit={handleSubmit}>
        <label className="field">
          <span>Username</span>
          <input
            name="username"
            autoComplete="username"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            required
            maxLength={64}
          />
        </label>

        <label className="field">
          <span>Password</span>
          <input
            name="password"
            type="password"
            // Tells the password manager which of the two this is, so it offers to generate a new
            // one on first run instead of trying to autofill a credential that doesn't exist yet.
            autoComplete={mode === 'register' ? 'new-password' : 'current-password'}
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            required
            minLength={mode === 'register' ? MINIMUM_PASSWORD_LENGTH : undefined}
          />
          {mode === 'register' && (
            <small className="hint">
              At least {MINIMUM_PASSWORD_LENGTH} characters. Length is the only rule — it&rsquo;s
              hashed with PBKDF2 and never stored in a recoverable form.
            </small>
          )}
        </label>

        {passwordTooShort && (
          <p className="error">Needs at least {MINIMUM_PASSWORD_LENGTH} characters.</p>
        )}

        {error && <p className="error">{describeError(error.code, mode)}</p>}

        <button className="action" type="submit" disabled={isSubmitting || passwordTooShort}>
          {isSubmitting
            ? needsSetup
              ? 'Creating account…'
              : 'Signing in…'
            : needsSetup
              ? 'Create account'
              : 'Sign in'}
        </button>
      </form>
    </main>
  )
}

/**
 * Turns the backend's error code into something readable.
 *
 * `invalid_credentials` stays vague on purpose — the backend won't say whether the username exists,
 * and rewording it here into "no such user" would give away exactly what it withheld.
 */
function describeError(code: string | null, mode: 'login' | 'register'): string {
  switch (code) {
    case 'invalid_credentials':
      return 'That username and password combination is not recognized.'
    case 'already_registered':
      return 'This dashboard has already been claimed. Reload the page to sign in instead.'
    case 'password_too_short':
      return `Password must be at least ${MINIMUM_PASSWORD_LENGTH} characters.`
    case 'invalid_username':
      return 'That username is not usable. Keep it under 64 characters.'
    case 'missing_credentials':
      return 'Both a username and a password are required.'
    default:
      return mode === 'register'
        ? 'Could not create the account. Is the backend running?'
        : 'Could not sign in. Is the backend running?'
  }
}
