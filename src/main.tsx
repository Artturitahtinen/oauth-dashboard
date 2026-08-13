import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom'
import { RequireAuth } from './auth/RequireAuth'
import { AppLayout } from './components/AppLayout'
import { Connections } from './routes/Connections'
import { Dashboard } from './routes/Dashboard'
import { Login } from './routes/Login'
import './index.css'
import './App.css'

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      // A 401 means the cookie lapsed; retrying an unauthenticated call cannot make it succeed and
      // only delays the redirect to the login screen.
      retry: false,
    },
  },
})

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />

          {/*
            There is deliberately no /oauth/callback route here. Provider redirect_uris point at the
            backend, which holds the client_secret and performs the exchange; the SPA is never handed
            an authorization code. The backend redirects to /connections?linked=… when it's done.
          */}
          <Route
            element={
              <RequireAuth>
                <AppLayout />
              </RequireAuth>
            }
          >
            <Route path="/" element={<Dashboard />} />
            <Route path="/connections" element={<Connections />} />
          </Route>

          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
)
