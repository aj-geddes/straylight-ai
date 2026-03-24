export interface HealthResponse {
  status: 'ok' | 'starting' | 'degraded';
  openbao?: 'unsealed' | 'sealed' | 'unavailable';
  services_count: number;
  uptime_seconds: number;
  version: string;
}
