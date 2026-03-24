import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  getServices,
  getService,
  createService,
  updateService,
  deleteService,
  checkCredential,
  getTemplates,
} from '../api/client';
import type { Service, ServiceTemplate, CredentialStatus } from '../types/service';

const MOCK_SERVICE: Service = {
  name: 'stripe',
  type: 'http_proxy',
  target: 'https://api.stripe.com',
  inject: 'header',
  header_template: 'Bearer {{.secret}}',
  status: 'available',
  created_at: '2026-03-22T00:00:00Z',
  updated_at: '2026-03-22T00:00:00Z',
};

const MOCK_TEMPLATE: ServiceTemplate = {
  id: 'stripe',
  display_name: 'Stripe',
  target: 'https://api.stripe.com',
  description: 'Stripe payment API',
  auth_methods: [
    {
      id: 'stripe_api_key',
      name: 'API Key',
      description: 'Stripe secret key',
      fields: [{ key: 'token', label: 'API Key', type: 'password', required: true }],
      injection: { type: 'bearer_header' },
    },
  ],
};

describe('API client - getServices', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('fetches services from /api/v1/services', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ services: [MOCK_SERVICE] }),
    } as Response);

    const result = await getServices();

    expect(fetch).toHaveBeenCalledWith('/api/v1/services');
    expect(result).toEqual([MOCK_SERVICE]);
  });

  it('returns empty array when response has empty services list', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ services: [] }),
    } as Response);

    const result = await getServices();
    expect(result).toEqual([]);
  });

  it('throws on HTTP error response', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: false,
      status: 500,
      json: async () => ({ error: { code: 'server_error', message: 'Internal error' } }),
    } as Response);

    await expect(getServices()).rejects.toThrow();
  });
});

describe('API client - getService', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('fetches a single service by name', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => MOCK_SERVICE,
    } as Response);

    const result = await getService('stripe');

    expect(fetch).toHaveBeenCalledWith('/api/v1/services/stripe');
    expect(result).toEqual(MOCK_SERVICE);
  });

  it('throws on 404 not found', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: false,
      status: 404,
      json: async () => ({ error: { code: 'service_not_found', message: 'Not found' } }),
    } as Response);

    await expect(getService('nonexistent')).rejects.toThrow();
  });
});

describe('API client - createService', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('posts to /api/v1/services with JSON body (legacy format)', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      status: 201,
      json: async () => MOCK_SERVICE,
    } as Response);

    const request = {
      name: 'stripe',
      type: 'http_proxy',
      target: 'https://api.stripe.com',
      inject: 'header',
      credential: 'sk_live_test',
      header_template: 'Bearer {{.secret}}',
    };

    const result = await createService(request);

    expect(fetch).toHaveBeenCalledWith('/api/v1/services', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    });
    expect(result).toEqual(MOCK_SERVICE);
  });

  it('posts to /api/v1/services with new auth_method + credentials format', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      status: 201,
      json: async () => MOCK_SERVICE,
    } as Response);

    const request = {
      name: 'github',
      type: 'http_proxy',
      target: 'https://api.github.com',
      auth_method: 'github_pat_classic',
      credentials: { token: 'ghp_xxx' },
    };

    await createService(request);

    expect(fetch).toHaveBeenCalledWith('/api/v1/services', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    });
  });

  it('throws on 409 conflict (service already exists)', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: false,
      status: 409,
      json: async () => ({ error: { code: 'conflict', message: 'Already exists' } }),
    } as Response);

    await expect(
      createService({ name: 'stripe', type: 'http_proxy', target: 'https://api.stripe.com' })
    ).rejects.toThrow();
  });

  it('throws on 400 validation error', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: false,
      status: 400,
      json: async () => ({ error: { code: 'validation_error', message: 'Invalid name' } }),
    } as Response);

    await expect(
      createService({ name: '', type: 'http_proxy', target: 'https://api.stripe.com' })
    ).rejects.toThrow();
  });
});

describe('API client - updateService', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('puts to /api/v1/services/:name with JSON body', async () => {
    const updated = { ...MOCK_SERVICE, status: 'available' as const };
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => updated,
    } as Response);

    const request = { credential: 'new_key' };
    const result = await updateService('stripe', request);

    expect(fetch).toHaveBeenCalledWith('/api/v1/services/stripe', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    });
    expect(result).toEqual(updated);
  });

  it('throws on 404 not found', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: false,
      status: 404,
      json: async () => ({ error: { code: 'service_not_found', message: 'Not found' } }),
    } as Response);

    await expect(updateService('nonexistent', {})).rejects.toThrow();
  });
});

describe('API client - deleteService', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('sends DELETE to /api/v1/services/:name', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      status: 204,
    } as Response);

    await deleteService('stripe');

    expect(fetch).toHaveBeenCalledWith('/api/v1/services/stripe', {
      method: 'DELETE',
    });
  });

  it('throws on 404 not found', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: false,
      status: 404,
      json: async () => ({ error: { code: 'service_not_found', message: 'Not found' } }),
    } as Response);

    await expect(deleteService('nonexistent')).rejects.toThrow();
  });

  it('resolves void on success', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      status: 204,
    } as Response);

    const result = await deleteService('stripe');
    expect(result).toBeUndefined();
  });
});

describe('API client - checkCredential', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('fetches credential status from /api/v1/services/:name/check', async () => {
    const mockStatus: CredentialStatus = {
      service: 'stripe',
      status: 'available',
    };

    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => mockStatus,
    } as Response);

    const result = await checkCredential('stripe');

    expect(fetch).toHaveBeenCalledWith('/api/v1/services/stripe/check');
    expect(result).toEqual(mockStatus);
  });

  it('returns status for expired credential', async () => {
    const mockStatus: CredentialStatus = {
      service: 'github',
      status: 'expired',
    };

    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => mockStatus,
    } as Response);

    const result = await checkCredential('github');
    expect(result.status).toBe('expired');
  });
});

describe('API client - getTemplates', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('fetches templates from /api/v1/templates', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ templates: [MOCK_TEMPLATE] }),
    } as Response);

    const result = await getTemplates();

    expect(fetch).toHaveBeenCalledWith('/api/v1/templates');
    expect(result).toEqual([MOCK_TEMPLATE]);
  });

  it('returns empty array when no templates', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ templates: [] }),
    } as Response);

    const result = await getTemplates();
    expect(result).toEqual([]);
  });
});
