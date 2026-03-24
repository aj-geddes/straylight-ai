import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AddServiceDialog } from '../components/AddServiceDialog';
import type { ServiceTemplate } from '../types/service';

// Mock the API client — getOAuthConfig returns "configured: true" so WebOAuthStep
// shows the simple "Sign in" button directly.
vi.mock('../api/client', () => ({
  getOAuthConfig: vi.fn().mockResolvedValue({ provider: 'google', configured: true }),
  saveOAuthConfig: vi.fn().mockResolvedValue(undefined),
  startDeviceFlow: vi.fn().mockResolvedValue({
    device_code: 'DEV',
    user_code: 'ABCD-1234',
    verification_uri: 'https://github.com/login/device',
    expires_in: 900,
    interval: 5,
  }),
  pollDeviceFlow: vi.fn().mockResolvedValue({ status: 'pending' }),
}));

// Google OAuth template — single OAuth method.
const GOOGLE_OAUTH_TEMPLATE: ServiceTemplate = {
  id: 'google',
  display_name: 'Google',
  description: 'Google APIs',
  target: 'https://www.googleapis.com',
  auth_methods: [
    {
      id: 'google_oauth',
      name: 'OAuth',
      description: 'Sign in with Google',
      fields: [],
      injection: { type: 'oauth' },
    },
  ],
};

// Facebook OAuth template — single OAuth method.
const FACEBOOK_OAUTH_TEMPLATE: ServiceTemplate = {
  id: 'facebook',
  display_name: 'Facebook',
  description: 'Facebook Graph API',
  target: 'https://graph.facebook.com',
  auth_methods: [
    {
      id: 'facebook_oauth',
      name: 'OAuth',
      description: 'Sign in with Facebook',
      fields: [],
      injection: { type: 'oauth' },
    },
  ],
};

describe('AddServiceDialog - web-oauth routing for Google', () => {
  it('shows WebOAuthStep (Sign in with Google) for Google OAuth method when configured', async () => {
    const user = userEvent.setup();
    render(
      <AddServiceDialog
        templates={[GOOGLE_OAUTH_TEMPLATE]}
        onSave={vi.fn()}
        onClose={vi.fn()}
      />
    );

    await user.click(screen.getByText('Google'));

    // Should show the "Sign in with Google" button from WebOAuthStep.
    await waitFor(() => {
      expect(
        screen.getByRole('button', { name: /sign in with google/i })
      ).toBeInTheDocument();
    });
  });

  it('does not show OAuthSetupStep credential form fields for Google', async () => {
    const user = userEvent.setup();
    render(
      <AddServiceDialog
        templates={[GOOGLE_OAUTH_TEMPLATE]}
        onSave={vi.fn()}
        onClose={vi.fn()}
      />
    );

    await user.click(screen.getByText('Google'));

    await waitFor(() => {
      expect(
        screen.getByRole('button', { name: /sign in with google/i })
      ).toBeInTheDocument();
    });

    expect(screen.queryByLabelText(/client id/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/client secret/i)).not.toBeInTheDocument();
  });
});

describe('AddServiceDialog - web-oauth routing for Facebook', () => {
  it('shows WebOAuthStep (Sign in with Facebook) for Facebook OAuth method when configured', async () => {
    const { getOAuthConfig } = await import('../api/client');
    vi.mocked(getOAuthConfig).mockResolvedValue({ provider: 'facebook', configured: true });

    const user = userEvent.setup();
    render(
      <AddServiceDialog
        templates={[FACEBOOK_OAUTH_TEMPLATE]}
        onSave={vi.fn()}
        onClose={vi.fn()}
      />
    );

    await user.click(screen.getByText('Facebook'));

    await waitFor(() => {
      expect(
        screen.getByRole('button', { name: /sign in with facebook/i })
      ).toBeInTheDocument();
    });
  });

  it('shows Back button in web-oauth step', async () => {
    const user = userEvent.setup();
    render(
      <AddServiceDialog
        templates={[GOOGLE_OAUTH_TEMPLATE]}
        onSave={vi.fn()}
        onClose={vi.fn()}
      />
    );

    await user.click(screen.getByText('Google'));

    await waitFor(() => {
      expect(
        screen.getByRole('button', { name: /sign in with google/i })
      ).toBeInTheDocument();
    });

    expect(screen.getByRole('button', { name: /back/i })).toBeInTheDocument();
  });
});
