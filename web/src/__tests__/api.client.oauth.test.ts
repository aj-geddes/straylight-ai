import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { getOAuthConfig, saveOAuthConfig, deleteOAuthConfig } from '../api/client';

describe('API client - getOAuthConfig', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('fetches oauth config from /api/v1/oauth/{provider}/config', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ provider: 'github', configured: true, client_id: 'my-cid' }),
    } as Response);

    const result = await getOAuthConfig('github');

    expect(fetch).toHaveBeenCalledWith('/api/v1/oauth/github/config');
    expect(result.provider).toBe('github');
    expect(result.configured).toBe(true);
    expect(result.client_id).toBe('my-cid');
  });

  it('returns configured=false when not set', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ provider: 'github', configured: false }),
    } as Response);

    const result = await getOAuthConfig('github');
    expect(result.configured).toBe(false);
    expect(result.client_id).toBeUndefined();
  });

  it('throws on HTTP error', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: false,
      status: 400,
      json: async () => ({ error: 'unknown provider' }),
    } as Response);

    await expect(getOAuthConfig('badprovider')).rejects.toThrow();
  });
});

describe('API client - saveOAuthConfig', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('posts client_id and client_secret to /api/v1/oauth/{provider}/config', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ provider: 'github', configured: true }),
    } as Response);

    await saveOAuthConfig('github', 'my-client-id', 'my-client-secret');

    expect(fetch).toHaveBeenCalledWith('/api/v1/oauth/github/config', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ client_id: 'my-client-id', client_secret: 'my-client-secret' }),
    });
  });

  it('resolves void on success', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      status: 200,
      json: async () => ({ provider: 'github', configured: true }),
    } as Response);

    const result = await saveOAuthConfig('github', 'cid', 'cs');
    expect(result).toBeUndefined();
  });

  it('throws on HTTP error', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: false,
      status: 400,
      json: async () => ({ error: 'client_id required' }),
    } as Response);

    await expect(saveOAuthConfig('github', '', 'cs')).rejects.toThrow();
  });
});

describe('API client - deleteOAuthConfig', () => {
  beforeEach(() => {
    vi.stubGlobal('fetch', vi.fn());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it('sends DELETE to /api/v1/oauth/{provider}/config', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      status: 204,
    } as Response);

    await deleteOAuthConfig('github');

    expect(fetch).toHaveBeenCalledWith('/api/v1/oauth/github/config', {
      method: 'DELETE',
    });
  });

  it('resolves void on success', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: true,
      status: 204,
    } as Response);

    const result = await deleteOAuthConfig('github');
    expect(result).toBeUndefined();
  });

  it('throws on HTTP error', async () => {
    vi.mocked(fetch).mockResolvedValueOnce({
      ok: false,
      status: 400,
      json: async () => ({ error: 'unknown provider' }),
    } as Response);

    await expect(deleteOAuthConfig('badprovider')).rejects.toThrow();
  });
});
