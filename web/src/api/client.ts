import type { HealthResponse } from '../types/health';
import type {
  Service,
  ServiceTemplate,
  CreateServiceRequest,
  UpdateServiceRequest,
  CredentialStatus,
  AddServiceRequest,
} from '../types/service';

const HEALTH_ENDPOINT = '/api/v1/health';
const SERVICES_ENDPOINT = '/api/v1/services';
const TEMPLATES_ENDPOINT = '/api/v1/templates';
const STATS_ENDPOINT = '/api/v1/stats';

// ---------------------------------------------------------------------------
// Stats / activity types
// ---------------------------------------------------------------------------

export interface ActivityEntry {
  timestamp: string;
  service: string;
  tool: string;
  method?: string;
  path?: string;
  status: number;
}

export interface StatsResponse {
  total_services: number;
  total_api_calls: number;
  total_exec_calls: number;
  uptime_seconds: number;
  recent_activity: ActivityEntry[];
}

const DEGRADED_RESPONSE: HealthResponse = {
  status: 'degraded',
  services_count: 0,
  uptime_seconds: 0,
  version: 'unknown',
};

/**
 * Fetches the backend health status.
 * Returns a degraded response on any network or HTTP error.
 */
export async function getHealth(): Promise<HealthResponse> {
  try {
    const response = await fetch(HEALTH_ENDPOINT);
    if (!response.ok) {
      return { ...DEGRADED_RESPONSE };
    }
    const data: HealthResponse = await response.json();
    return data;
  } catch {
    return { ...DEGRADED_RESPONSE };
  }
}

/**
 * Returns the list of configured services.
 */
export async function getServices(): Promise<Service[]> {
  const response = await fetch(SERVICES_ENDPOINT);
  if (!response.ok) {
    const body = await response.json();
    throw new Error(typeof body?.error === 'string' ? body.error : body?.error?.message ?? `HTTP ${response.status}`);
  }
  const data: { services: Service[] } = await response.json();
  return data.services;
}

/**
 * Returns a single service by name.
 */
export async function getService(name: string): Promise<Service> {
  const response = await fetch(`${SERVICES_ENDPOINT}/${name}`);
  if (!response.ok) {
    const body = await response.json();
    throw new Error(typeof body?.error === 'string' ? body.error : body?.error?.message ?? `HTTP ${response.status}`);
  }
  return response.json();
}

/**
 * Creates a new service with the given configuration and credential.
 * Supports both legacy single-credential format and new multi-field + auth_method format.
 */
export async function createService(data: CreateServiceRequest): Promise<Service> {
  const response = await fetch(SERVICES_ENDPOINT, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const body = await response.json();
    throw new Error(typeof body?.error === 'string' ? body.error : body?.error?.message ?? `HTTP ${response.status}`);
  }
  return response.json();
}

/**
 * Creates a service using the new template-based wizard format.
 * Translates AddServiceRequest into CreateServiceRequest.
 */
export async function addServiceFromTemplate(data: AddServiceRequest): Promise<Service> {
  const request: CreateServiceRequest = {
    name: data.name ?? data.template,
    template: data.template,
    auth_method: data.auth_method,
    credentials: data.credentials,
  };
  return createService(request);
}

/**
 * Updates an existing service's configuration or credential.
 */
export async function updateService(
  name: string,
  data: UpdateServiceRequest
): Promise<Service> {
  const response = await fetch(`${SERVICES_ENDPOINT}/${name}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const body = await response.json();
    throw new Error(typeof body?.error === 'string' ? body.error : body?.error?.message ?? `HTTP ${response.status}`);
  }
  return response.json();
}

/**
 * Deletes a service and its stored credential.
 */
export async function deleteService(name: string): Promise<void> {
  const response = await fetch(`${SERVICES_ENDPOINT}/${name}`, {
    method: 'DELETE',
  });
  if (!response.ok) {
    const body = await response.json();
    throw new Error(typeof body?.error === 'string' ? body.error : body?.error?.message ?? `HTTP ${response.status}`);
  }
}

/**
 * Checks the credential status for a service.
 */
export async function checkCredential(name: string): Promise<CredentialStatus> {
  const response = await fetch(`${SERVICES_ENDPOINT}/${name}/check`);
  if (!response.ok) {
    const body = await response.json();
    throw new Error(typeof body?.error === 'string' ? body.error : body?.error?.message ?? `HTTP ${response.status}`);
  }
  return response.json();
}

/**
 * Returns the list of available service templates with auth methods.
 */
export async function getTemplates(): Promise<ServiceTemplate[]> {
  const response = await fetch(TEMPLATES_ENDPOINT);
  if (!response.ok) {
    const body = await response.json();
    throw new Error(typeof body?.error === 'string' ? body.error : body?.error?.message ?? `HTTP ${response.status}`);
  }
  const data: { templates: ServiceTemplate[] } = await response.json();
  return data.templates;
}

/**
 * Returns activity stats: total API/exec call counts, uptime, and recent activity.
 */
export async function getStats(): Promise<StatsResponse> {
  try {
    const response = await fetch(STATS_ENDPOINT);
    if (!response.ok) {
      return {
        total_services: 0,
        total_api_calls: 0,
        total_exec_calls: 0,
        uptime_seconds: 0,
        recent_activity: [],
      };
    }
    return response.json();
  } catch {
    return {
      total_services: 0,
      total_api_calls: 0,
      total_exec_calls: 0,
      uptime_seconds: 0,
      recent_activity: [],
    };
  }
}

// ---------------------------------------------------------------------------
// OAuth App credential management
// ---------------------------------------------------------------------------

/**
 * Returns whether OAuth App credentials are configured for the given provider.
 * The client_secret is never returned by the backend.
 */
export async function getOAuthConfig(
  provider: string
): Promise<{ provider: string; configured: boolean; client_id?: string }> {
  const response = await fetch(`/api/v1/oauth/${provider}/config`);
  if (!response.ok) {
    const body = await response.json();
    throw new Error(typeof body?.error === 'string' ? body.error : body?.error?.message ?? `HTTP ${response.status}`);
  }
  return response.json();
}

/**
 * Saves the OAuth App client_id and client_secret for the given provider.
 * These are application-level credentials obtained by registering an OAuth App
 * with the provider — they are not the user's personal tokens.
 */
export async function saveOAuthConfig(
  provider: string,
  clientId: string,
  clientSecret: string
): Promise<void> {
  const response = await fetch(`/api/v1/oauth/${provider}/config`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ client_id: clientId, client_secret: clientSecret }),
  });
  if (!response.ok) {
    const body = await response.json();
    throw new Error(typeof body?.error === 'string' ? body.error : body?.error?.message ?? `HTTP ${response.status}`);
  }
}

/**
 * Removes the stored OAuth App credentials for the given provider.
 */
export async function deleteOAuthConfig(provider: string): Promise<void> {
  const response = await fetch(`/api/v1/oauth/${provider}/config`, {
    method: 'DELETE',
  });
  if (!response.ok) {
    const body = await response.json();
    throw new Error(typeof body?.error === 'string' ? body.error : body?.error?.message ?? `HTTP ${response.status}`);
  }
}

// ---------------------------------------------------------------------------
// Device Authorization Flow (RFC 8628)
// ---------------------------------------------------------------------------

/** Response from POST /api/v1/oauth/{provider}/device/start */
export interface DeviceCodeResponse {
  device_code: string;
  user_code: string;
  verification_uri: string;
  expires_in: number;
  interval: number;
}

/** Response from POST /api/v1/oauth/{provider}/device/poll */
export interface DeviceFlowStatus {
  status: 'pending' | 'complete' | 'expired';
}

/**
 * Initiates the GitHub Device Authorization Flow.
 * Returns the user code and verification URI to display to the user.
 * The caller should then poll pollDeviceFlow every `interval` seconds.
 */
export async function startDeviceFlow(
  provider: string,
  serviceName: string
): Promise<DeviceCodeResponse> {
  const response = await fetch(`/api/v1/oauth/${provider}/device/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ service_name: serviceName }),
  });
  if (!response.ok) {
    const body = await response.json();
    throw new Error(typeof body?.error === 'string' ? body.error : body?.error?.message ?? `HTTP ${response.status}`);
  }
  return response.json();
}

/**
 * Polls the device authorization status.
 * Call this every `interval` seconds after startDeviceFlow.
 * Returns "pending" while the user has not yet authorized,
 * "complete" when the token has been stored, or "expired" when the code expires.
 */
export async function pollDeviceFlow(
  provider: string,
  deviceCode: string,
  serviceName: string
): Promise<DeviceFlowStatus> {
  const response = await fetch(`/api/v1/oauth/${provider}/device/poll`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ device_code: deviceCode, service_name: serviceName }),
  });
  if (!response.ok) {
    const body = await response.json();
    throw new Error(typeof body?.error === 'string' ? body.error : body?.error?.message ?? `HTTP ${response.status}`);
  }
  return response.json();
}
