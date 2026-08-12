import { apiFetch } from './client'

export interface HealthResponse {
  status: string
  environment: string
  /** True once the probe cookie set by a previous call came back with this one. */
  cookieEchoed: boolean
}

export function fetchHealth(): Promise<HealthResponse> {
  return apiFetch<HealthResponse>('/api/health')
}
