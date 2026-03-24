import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AddServiceDialog } from '../components/AddServiceDialog';
import type { ServiceTemplate } from '../types/service';

// Mock the API client for device flow tests
vi.mock('../api/client', () => ({
  startDeviceFlow: vi.fn().mockResolvedValue({
    device_code: 'DEV',
    user_code: 'ABCD-1234',
    verification_uri: 'https://github.com/login/device',
    expires_in: 900,
    interval: 5,
  }),
  pollDeviceFlow: vi.fn().mockResolvedValue({ status: 'pending' }),
  getOAuthConfig: vi.fn().mockResolvedValue({ provider: 'github', configured: false }),
  saveOAuthConfig: vi.fn().mockResolvedValue(undefined),
}));

const GITHUB_TEMPLATE: ServiceTemplate = {
  id: 'github',
  display_name: 'GitHub',
  description: 'GitHub API',
  target: 'https://api.github.com',
  auth_methods: [
    {
      id: 'github_pat_classic',
      name: 'Personal Access Token (classic)',
      description: 'Use a personal access token',
      fields: [
        {
          key: 'token',
          label: 'Personal Access Token',
          type: 'password',
          placeholder: 'ghp_xxxxxxxxxxxx',
          required: true,
        },
      ],
      injection: { type: 'bearer_header' },
    },
    {
      id: 'github_fine_grained',
      name: 'Fine-grained PAT',
      description: 'Use a fine-grained token',
      fields: [
        {
          key: 'token',
          label: 'Fine-grained Token',
          type: 'password',
          placeholder: 'github_pat_xxxx',
          required: true,
        },
      ],
      injection: { type: 'bearer_header' },
    },
  ],
};

const SINGLE_AUTH_TEMPLATE: ServiceTemplate = {
  id: 'stripe',
  display_name: 'Stripe',
  description: 'Stripe payment API',
  target: 'https://api.stripe.com',
  auth_methods: [
    {
      id: 'stripe_api_key',
      name: 'API Key',
      description: 'Use a Stripe API key',
      fields: [
        {
          key: 'token',
          label: 'API Key',
          type: 'password',
          placeholder: 'sk_live_xxxxxxxxxxxx',
          required: true,
        },
      ],
      injection: { type: 'bearer_header' },
    },
  ],
};

// GitHub OAuth template: single auth method using the "oauth" injection type.
// This should route to DeviceFlowStep (not OAuthSetupStep) because GitHub
// supports Device Authorization Flow.
const GITHUB_OAUTH_TEMPLATE: ServiceTemplate = {
  id: 'github',
  display_name: 'GitHub',
  description: 'GitHub API via OAuth',
  target: 'https://api.github.com',
  auth_methods: [
    {
      id: 'github_oauth',
      name: 'OAuth (GitHub)',
      description: 'Authorize with GitHub via Device Flow',
      fields: [],
      injection: { type: 'oauth' },
    },
  ],
};

describe('AddServiceDialog - rendering', () => {
  it('renders as a dialog', () => {
    render(
      <AddServiceDialog
        templates={[GITHUB_TEMPLATE]}
        onSave={vi.fn()}
        onClose={vi.fn()}
      />
    );
    expect(screen.getByRole('dialog')).toBeInTheDocument();
  });

  it('renders a close button', () => {
    render(
      <AddServiceDialog
        templates={[GITHUB_TEMPLATE]}
        onSave={vi.fn()}
        onClose={vi.fn()}
      />
    );
    expect(screen.getByRole('button', { name: /close/i })).toBeInTheDocument();
  });

  it('shows step 1 (select service) initially', () => {
    render(
      <AddServiceDialog
        templates={[GITHUB_TEMPLATE]}
        onSave={vi.fn()}
        onClose={vi.fn()}
      />
    );
    expect(screen.getByText('GitHub')).toBeInTheDocument();
  });
});

describe('AddServiceDialog - step 1 template selection', () => {
  it('shows all template names', () => {
    render(
      <AddServiceDialog
        templates={[GITHUB_TEMPLATE, SINGLE_AUTH_TEMPLATE]}
        onSave={vi.fn()}
        onClose={vi.fn()}
      />
    );
    expect(screen.getByText('GitHub')).toBeInTheDocument();
    expect(screen.getByText('Stripe')).toBeInTheDocument();
  });

  it('advances to step 2 when template with multiple auth methods is selected', async () => {
    const user = userEvent.setup();
    render(
      <AddServiceDialog
        templates={[GITHUB_TEMPLATE]}
        onSave={vi.fn()}
        onClose={vi.fn()}
      />
    );
    await user.click(screen.getByText('GitHub'));
    await waitFor(() => {
      expect(screen.getByText('Personal Access Token (classic)')).toBeInTheDocument();
    });
  });

  it('skips step 2 for single-auth template and shows credentials form', async () => {
    const user = userEvent.setup();
    render(
      <AddServiceDialog
        templates={[SINGLE_AUTH_TEMPLATE]}
        onSave={vi.fn()}
        onClose={vi.fn()}
      />
    );
    await user.click(screen.getByText('Stripe'));
    await waitFor(() => {
      expect(screen.getByLabelText(/api key/i)).toBeInTheDocument();
    });
  });
});

describe('AddServiceDialog - step 2 auth method selection', () => {
  it('shows a Back button in step 2', async () => {
    const user = userEvent.setup();
    render(
      <AddServiceDialog
        templates={[GITHUB_TEMPLATE]}
        onSave={vi.fn()}
        onClose={vi.fn()}
      />
    );
    await user.click(screen.getByText('GitHub'));
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /back/i })).toBeInTheDocument();
    });
  });

  it('goes back to step 1 when Back is clicked', async () => {
    const user = userEvent.setup();
    render(
      <AddServiceDialog
        templates={[GITHUB_TEMPLATE]}
        onSave={vi.fn()}
        onClose={vi.fn()}
      />
    );
    await user.click(screen.getByText('GitHub'));
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /back/i })).toBeInTheDocument();
    });
    await user.click(screen.getByRole('button', { name: /back/i }));
    await waitFor(() => {
      expect(screen.getByText('GitHub')).toBeInTheDocument();
    });
  });

  it('advances to step 3 when auth method is selected and Next is clicked', async () => {
    const user = userEvent.setup();
    render(
      <AddServiceDialog
        templates={[GITHUB_TEMPLATE]}
        onSave={vi.fn()}
        onClose={vi.fn()}
      />
    );
    await user.click(screen.getByText('GitHub'));
    await waitFor(() => {
      expect(screen.getByText('Personal Access Token (classic)')).toBeInTheDocument();
    });
    await user.click(screen.getByDisplayValue('github_pat_classic'));
    await user.click(screen.getByRole('button', { name: /next/i }));
    await waitFor(() => {
      expect(screen.getByLabelText(/personal access token/i)).toBeInTheDocument();
    });
  });
});

describe('AddServiceDialog - step 3 credential entry', () => {
  async function advanceToStep3(user: ReturnType<typeof userEvent.setup>) {
    render(
      <AddServiceDialog
        templates={[GITHUB_TEMPLATE]}
        onSave={vi.fn()}
        onClose={vi.fn()}
      />
    );
    await user.click(screen.getByText('GitHub'));
    await waitFor(() => {
      expect(screen.getByText('Personal Access Token (classic)')).toBeInTheDocument();
    });
    await user.click(screen.getByDisplayValue('github_pat_classic'));
    await user.click(screen.getByRole('button', { name: /next/i }));
    await waitFor(() => {
      expect(screen.getByLabelText(/personal access token/i)).toBeInTheDocument();
    });
  }

  it('shows a Save button in step 3', async () => {
    const user = userEvent.setup();
    await advanceToStep3(user);
    expect(screen.getByRole('button', { name: /save/i })).toBeInTheDocument();
  });

  it('shows a Back button in step 3', async () => {
    const user = userEvent.setup();
    await advanceToStep3(user);
    expect(screen.getByRole('button', { name: /back/i })).toBeInTheDocument();
  });

  it('shows validation error when credential is empty on save', async () => {
    const user = userEvent.setup();
    await advanceToStep3(user);
    await user.click(screen.getByRole('button', { name: /save/i }));
    await waitFor(() => {
      expect(screen.getByText(/required/i)).toBeInTheDocument();
    });
  });
});

describe('AddServiceDialog - onSave', () => {
  it('calls onSave with template id, auth method id, and credentials', async () => {
    const user = userEvent.setup();
    const onSave = vi.fn().mockResolvedValue(undefined);

    render(
      <AddServiceDialog
        templates={[SINGLE_AUTH_TEMPLATE]}
        onSave={onSave}
        onClose={vi.fn()}
      />
    );

    await user.click(screen.getByText('Stripe'));
    await waitFor(() => {
      expect(screen.getByLabelText(/api key/i)).toBeInTheDocument();
    });

    await user.type(screen.getByLabelText(/api key/i), 'sk_live_test123');
    await user.click(screen.getByRole('button', { name: /save/i }));

    await waitFor(() => {
      expect(onSave).toHaveBeenCalledWith(
        expect.objectContaining({
          template: 'stripe',
          auth_method: 'stripe_api_key',
          credentials: { token: 'sk_live_test123' },
        })
      );
    });
  });

  it('calls onClose after successful save', async () => {
    const user = userEvent.setup();
    const onSave = vi.fn().mockResolvedValue(undefined);
    const onClose = vi.fn();

    render(
      <AddServiceDialog
        templates={[SINGLE_AUTH_TEMPLATE]}
        onSave={onSave}
        onClose={onClose}
      />
    );

    await user.click(screen.getByText('Stripe'));
    await waitFor(() => {
      expect(screen.getByLabelText(/api key/i)).toBeInTheDocument();
    });
    await user.type(screen.getByLabelText(/api key/i), 'sk_live_test123');
    await user.click(screen.getByRole('button', { name: /save/i }));

    await waitFor(() => {
      expect(onClose).toHaveBeenCalledTimes(1);
    });
  });

  it('shows error when save fails', async () => {
    const user = userEvent.setup();
    const onSave = vi.fn().mockRejectedValue(new Error('Service already exists'));

    render(
      <AddServiceDialog
        templates={[SINGLE_AUTH_TEMPLATE]}
        onSave={onSave}
        onClose={vi.fn()}
      />
    );

    await user.click(screen.getByText('Stripe'));
    await waitFor(() => {
      expect(screen.getByLabelText(/api key/i)).toBeInTheDocument();
    });
    await user.type(screen.getByLabelText(/api key/i), 'sk_live_test123');
    await user.click(screen.getByRole('button', { name: /save/i }));

    await waitFor(() => {
      expect(screen.getByText(/service already exists/i)).toBeInTheDocument();
    });
  });
});

describe('AddServiceDialog - close behavior', () => {
  it('calls onClose when close button is clicked', async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();

    render(
      <AddServiceDialog
        templates={[GITHUB_TEMPLATE]}
        onSave={vi.fn()}
        onClose={onClose}
      />
    );

    await user.click(screen.getByRole('button', { name: /close/i }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});

describe('AddServiceDialog - device flow routing for GitHub OAuth', () => {
  it('shows DeviceFlowStep (not OAuthSetupStep) for GitHub OAuth method', async () => {
    const user = userEvent.setup();
    render(
      <AddServiceDialog
        templates={[GITHUB_OAUTH_TEMPLATE]}
        onSave={vi.fn()}
        onClose={vi.fn()}
      />
    );

    await user.click(screen.getByText('GitHub'));

    // Should show DeviceFlowStep: "Start Authorization" button, NOT credential form fields.
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /start authorization/i })).toBeInTheDocument();
    });
  });

  it('does not show OAuthSetupStep credential fields for GitHub OAuth method', async () => {
    const user = userEvent.setup();
    render(
      <AddServiceDialog
        templates={[GITHUB_OAUTH_TEMPLATE]}
        onSave={vi.fn()}
        onClose={vi.fn()}
      />
    );

    await user.click(screen.getByText('GitHub'));

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /start authorization/i })).toBeInTheDocument();
    });

    // Should NOT show the OAuthSetupStep "Save & Connect" button or client_id field.
    expect(screen.queryByRole('button', { name: /save & connect/i })).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/client id/i)).not.toBeInTheDocument();
  });
});
