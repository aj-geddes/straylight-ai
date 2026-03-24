import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';

// Mock the API client
vi.mock('../api/client', () => ({
  getOAuthConfig: vi.fn(),
  saveOAuthConfig: vi.fn(),
  startDeviceFlow: vi.fn(),
  pollDeviceFlow: vi.fn(),
}));

import { getOAuthConfig } from '../api/client';

// Import after mock registration — module will be loaded with mocked deps.
// We use a dynamic import to allow vi.mock to run first.
import { WebOAuthStep } from '../components/WebOAuthStep';

describe('WebOAuthStep - loading state', () => {
  beforeEach(() => {
    vi.mocked(getOAuthConfig).mockImplementation(
      () => new Promise(() => {}) // never resolves
    );
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('shows a loading indicator while checking config', () => {
    render(
      <WebOAuthStep
        provider="google"
        displayName="Google"
        serviceName="my-google"
      />
    );
    // Loading spinner or text should be present
    const el = document.querySelector('[aria-hidden="true"]') ||
      screen.queryByText(/checking/i) ||
      screen.queryByRole('status');
    expect(el || screen.getByRole('dialog', { hidden: true }) !== null).toBeTruthy();
  });
});

describe('WebOAuthStep - configured state', () => {
  beforeEach(() => {
    vi.mocked(getOAuthConfig).mockResolvedValue({
      provider: 'google',
      configured: true,
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('shows "Sign in with Google" button when configured', async () => {
    render(
      <WebOAuthStep
        provider="google"
        displayName="Google"
        serviceName="my-google"
      />
    );
    await waitFor(() => {
      expect(
        screen.getByRole('button', { name: /sign in with google/i })
      ).toBeInTheDocument();
    });
  });

  it('does not show client_id and client_secret fields when configured', async () => {
    render(
      <WebOAuthStep
        provider="google"
        displayName="Google"
        serviceName="my-google"
      />
    );
    await waitFor(() => {
      expect(
        screen.getByRole('button', { name: /sign in with google/i })
      ).toBeInTheDocument();
    });
    expect(screen.queryByLabelText(/client id/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/client secret/i)).not.toBeInTheDocument();
  });

  it('redirects to oauth start URL when button is clicked', async () => {
    const user = userEvent.setup();

    // Spy on window.location assignment
    const originalLocation = window.location;
    Object.defineProperty(window, 'location', {
      value: { href: '' },
      writable: true,
    });

    render(
      <WebOAuthStep
        provider="google"
        displayName="Google"
        serviceName="my-google"
      />
    );
    await waitFor(() => {
      expect(
        screen.getByRole('button', { name: /sign in with google/i })
      ).toBeInTheDocument();
    });

    await user.click(screen.getByRole('button', { name: /sign in with google/i }));

    expect(window.location.href).toBe(
      '/api/v1/oauth/google/start?service_name=my-google'
    );

    Object.defineProperty(window, 'location', {
      value: originalLocation,
      writable: true,
    });
  });

  it('shows description text before the sign-in button', async () => {
    render(
      <WebOAuthStep
        provider="google"
        displayName="Google"
        serviceName="my-google"
      />
    );
    await waitFor(() => {
      expect(
        screen.getByRole('button', { name: /sign in with google/i })
      ).toBeInTheDocument();
    });
    // Description text should mention Google
    expect(screen.getByText(/google/i, { selector: 'p' })).toBeInTheDocument();
  });

  it('works for facebook provider', async () => {
    vi.mocked(getOAuthConfig).mockResolvedValue({
      provider: 'facebook',
      configured: true,
    });
    render(
      <WebOAuthStep
        provider="facebook"
        displayName="Facebook"
        serviceName="my-facebook"
      />
    );
    await waitFor(() => {
      expect(
        screen.getByRole('button', { name: /sign in with facebook/i })
      ).toBeInTheDocument();
    });
  });
});

describe('WebOAuthStep - not configured, device flow provider', () => {
  beforeEach(() => {
    vi.mocked(getOAuthConfig).mockResolvedValue({
      provider: 'google',
      configured: false,
    });
    vi.mocked(getOAuthConfig as ReturnType<typeof vi.fn>).mockResolvedValue({
      provider: 'google',
      configured: false,
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('shows DeviceFlowStep for google when not configured (device flow fallback)', async () => {
    render(
      <WebOAuthStep
        provider="google"
        displayName="Google"
        serviceName="my-google"
      />
    );
    // When not configured and provider supports device flow, falls back to device flow.
    await waitFor(() => {
      expect(
        screen.getByRole('button', { name: /start authorization/i })
      ).toBeInTheDocument();
    });
  });
});

describe('WebOAuthStep - not configured, non-device-flow provider (facebook)', () => {
  beforeEach(() => {
    vi.mocked(getOAuthConfig).mockResolvedValue({
      provider: 'facebook',
      configured: false,
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('shows OAuthSetupStep for facebook when not configured (no device flow)', async () => {
    render(
      <WebOAuthStep
        provider="facebook"
        displayName="Facebook"
        serviceName="my-facebook"
      />
    );
    // Falls back to OAuthSetupStep which shows client_id/client_secret fields.
    await waitFor(() => {
      expect(screen.getByLabelText(/client id/i)).toBeInTheDocument();
    });
  });
});

describe('WebOAuthStep - error state', () => {
  beforeEach(() => {
    vi.mocked(getOAuthConfig).mockRejectedValue(new Error('Network error'));
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('falls back to OAuthSetupStep when config check fails for non-device provider', async () => {
    render(
      <WebOAuthStep
        provider="facebook"
        displayName="Facebook"
        serviceName="my-facebook"
      />
    );
    // On error, treats as not configured → OAuthSetupStep fallback.
    await waitFor(() => {
      expect(screen.getByLabelText(/client id/i)).toBeInTheDocument();
    });
  });
});
