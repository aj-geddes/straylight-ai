import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { OAuthSetupStep } from '../components/OAuthSetupStep';

// Mock the API client
vi.mock('../api/client', () => ({
  getOAuthConfig: vi.fn(),
  saveOAuthConfig: vi.fn(),
}));

import { getOAuthConfig, saveOAuthConfig } from '../api/client';

const _GITHUB_PROVIDER = {
  id: 'github',
  displayName: 'GitHub',
};
void _GITHUB_PROVIDER; // suppress unused warning

describe('OAuthSetupStep - configured state', () => {
  beforeEach(() => {
    vi.mocked(getOAuthConfig).mockResolvedValue({
      provider: 'github',
      configured: true,
      client_id: 'my-client-id',
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('shows Connect button when OAuth is already configured', async () => {
    render(
      <OAuthSetupStep
        provider="github"
        displayName="GitHub"
        serviceName="github"
        onStartOAuth={vi.fn()}
      />
    );

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /connect with github/i })).toBeInTheDocument();
    });
  });

  it('calls onStartOAuth when Connect button is clicked', async () => {
    const onStartOAuth = vi.fn();
    const user = userEvent.setup();

    render(
      <OAuthSetupStep
        provider="github"
        displayName="GitHub"
        serviceName="github"
        onStartOAuth={onStartOAuth}
      />
    );

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /connect with github/i })).toBeInTheDocument();
    });

    await user.click(screen.getByRole('button', { name: /connect with github/i }));
    expect(onStartOAuth).toHaveBeenCalledTimes(1);
  });
});

describe('OAuthSetupStep - not configured state', () => {
  beforeEach(() => {
    vi.mocked(getOAuthConfig).mockResolvedValue({
      provider: 'github',
      configured: false,
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it('shows setup form when OAuth is not configured', async () => {
    render(
      <OAuthSetupStep
        provider="github"
        displayName="GitHub"
        serviceName="github"
        onStartOAuth={vi.fn()}
      />
    );

    await waitFor(() => {
      expect(screen.getByLabelText(/client id/i)).toBeInTheDocument();
    });
  });

  it('shows client secret field', async () => {
    render(
      <OAuthSetupStep
        provider="github"
        displayName="GitHub"
        serviceName="github"
        onStartOAuth={vi.fn()}
      />
    );

    await waitFor(() => {
      expect(screen.getByLabelText(/client secret/i)).toBeInTheDocument();
    });
  });

  it('shows the callback URL for the user to register', async () => {
    render(
      <OAuthSetupStep
        provider="github"
        displayName="GitHub"
        serviceName="github"
        onStartOAuth={vi.fn()}
      />
    );

    await waitFor(() => {
      expect(
        screen.getByText(/http:\/\/localhost:9470\/api\/v1\/oauth\/callback/i)
      ).toBeInTheDocument();
    });
  });

  it('shows a link to the GitHub OAuth App registration page', async () => {
    render(
      <OAuthSetupStep
        provider="github"
        displayName="GitHub"
        serviceName="github"
        onStartOAuth={vi.fn()}
      />
    );

    await waitFor(() => {
      const link = screen.getByRole('link', { name: /new oauth app/i });
      expect(link).toBeInTheDocument();
      expect(link).toHaveAttribute('href', 'https://github.com/settings/developers');
    });
  });

  it('shows Save & Connect button', async () => {
    render(
      <OAuthSetupStep
        provider="github"
        displayName="GitHub"
        serviceName="github"
        onStartOAuth={vi.fn()}
      />
    );

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /save & connect/i })).toBeInTheDocument();
    });
  });

  it('calls saveOAuthConfig and then onStartOAuth on Save & Connect', async () => {
    const onStartOAuth = vi.fn();
    vi.mocked(saveOAuthConfig).mockResolvedValue(undefined);
    const user = userEvent.setup();

    render(
      <OAuthSetupStep
        provider="github"
        displayName="GitHub"
        serviceName="github"
        onStartOAuth={onStartOAuth}
      />
    );

    await waitFor(() => {
      expect(screen.getByLabelText(/client id/i)).toBeInTheDocument();
    });

    await user.type(screen.getByLabelText(/client id/i), 'test-client-id');
    await user.type(screen.getByLabelText(/client secret/i), 'test-client-secret');
    await user.click(screen.getByRole('button', { name: /save & connect/i }));

    await waitFor(() => {
      expect(saveOAuthConfig).toHaveBeenCalledWith(
        'github',
        'test-client-id',
        'test-client-secret'
      );
      expect(onStartOAuth).toHaveBeenCalledTimes(1);
    });
  });

  it('shows validation error when client_id is empty on save', async () => {
    vi.mocked(saveOAuthConfig).mockResolvedValue(undefined);
    const user = userEvent.setup();

    render(
      <OAuthSetupStep
        provider="github"
        displayName="GitHub"
        serviceName="github"
        onStartOAuth={vi.fn()}
      />
    );

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /save & connect/i })).toBeInTheDocument();
    });

    await user.click(screen.getByRole('button', { name: /save & connect/i }));

    await waitFor(() => {
      expect(screen.getByText(/client id is required/i)).toBeInTheDocument();
    });
  });

  it('shows error when saveOAuthConfig fails', async () => {
    vi.mocked(saveOAuthConfig).mockRejectedValue(new Error('Network error'));
    const user = userEvent.setup();

    render(
      <OAuthSetupStep
        provider="github"
        displayName="GitHub"
        serviceName="github"
        onStartOAuth={vi.fn()}
      />
    );

    await waitFor(() => {
      expect(screen.getByLabelText(/client id/i)).toBeInTheDocument();
    });

    await user.type(screen.getByLabelText(/client id/i), 'cid');
    await user.type(screen.getByLabelText(/client secret/i), 'cs');
    await user.click(screen.getByRole('button', { name: /save & connect/i }));

    await waitFor(() => {
      expect(screen.getByText(/network error/i)).toBeInTheDocument();
    });
  });
});

describe('OAuthSetupStep - loading state', () => {
  it('shows loading indicator while checking config', async () => {
    vi.mocked(getOAuthConfig).mockImplementation(
      () => new Promise(() => {}) // never resolves
    );

    render(
      <OAuthSetupStep
        provider="github"
        displayName="GitHub"
        serviceName="github"
        onStartOAuth={vi.fn()}
      />
    );

    // Should show loading state before config resolves
    expect(screen.getByText(/checking/i)).toBeInTheDocument();
  });
});
