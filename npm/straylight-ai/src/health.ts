/** Response shape from the health endpoint */
export interface HealthResponse {
  status: string;
  version?: string;
  [key: string]: unknown;
}

/** Interval between health-check attempts in milliseconds */
const POLL_INTERVAL_MS = 1_000;

/**
 * Perform a single health check against the given URL.
 * Throws if the endpoint is unreachable or returns a non-ok HTTP status.
 */
export async function checkHealth(url: string): Promise<HealthResponse> {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`Health check failed with HTTP ${response.status}`);
  }
  return (await response.json()) as HealthResponse;
}

/**
 * Poll the health endpoint until it returns a successful response or the
 * timeout elapses.
 *
 * @param url       Full URL of the health endpoint.
 * @param timeoutMs Maximum time to wait in milliseconds.
 * @returns The first successful HealthResponse.
 * @throws  Error when the timeout is reached without a successful response.
 */
export async function waitForHealth(
  url: string,
  timeoutMs: number
): Promise<HealthResponse> {
  const deadline = Date.now() + timeoutMs;

  while (Date.now() < deadline) {
    try {
      return await checkHealth(url);
    } catch {
      // Not ready yet — wait before retrying
      await sleep(POLL_INTERVAL_MS);
    }
  }

  throw new Error(
    `Health check timed out after ${timeoutMs}ms. ` +
      `Is the container running at ${url}?`
  );
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
