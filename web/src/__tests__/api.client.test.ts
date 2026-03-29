import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { getHealth, getServices } from '../api/client';
import type { HealthResponse } from '../types/health';

describe('API client - getHealth', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('returns health response on success', async () => {
    const mockResponse: HealthResponse = {
      status: 'ok',
      openbao: 'unsealed',
      services_count: 2,
      uptime_seconds: 120,
      version: '1.0.1',
    };

    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => mockResponse,
    } as Response);

    const result = await getHealth();
    expect(result).toEqual(mockResponse);
    expect(fetch).toHaveBeenCalledWith('/api/v1/health');
  });

  it('returns degraded status on non-200 response', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: false,
      status: 503,
      json: async () => ({ error: 'service unavailable' }),
    } as Response);

    const result = await getHealth();
    expect(result.status).toBe('degraded');
  });

  it('returns degraded status on network error', async () => {
    vi.mocked(fetch).mockRejectedValueOnce(new Error('Network failure'));

    const result = await getHealth();
    expect(result.status).toBe('degraded');
  });

  it('returns starting status when backend returns starting', async () => {
    const mockResponse: HealthResponse = {
      status: 'starting',
      services_count: 0,
      uptime_seconds: 5,
      version: '1.0.1',
    };

    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => mockResponse,
    } as Response);

    const result = await getHealth();
    expect(result.status).toBe('starting');
  });
});

describe('API client - getServices', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('returns empty array when backend returns empty list', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ services: [] }),
    } as Response);

    const result = await getServices();
    expect(result).toEqual([]);
    expect(Array.isArray(result)).toBe(true);
  });

  it('makes a network call to /api/v1/services', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ services: [] }),
    } as Response);

    await getServices();
    expect(fetch).toHaveBeenCalledWith('/api/v1/services');
  });
});
