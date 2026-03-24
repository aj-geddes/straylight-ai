import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { AddServiceDialog } from '../components/AddServiceDialog';
import type { ServiceTemplate } from '../types/service';

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

const CUSTOM_TEMPLATE: ServiceTemplate = {
  id: 'custom',
  display_name: 'Custom Service',
  description: 'Configure a custom API service',
  target: '',
  auth_methods: [
    {
      id: 'api_key_bearer',
      name: 'API Key (Bearer)',
      description: 'Token sent as Authorization Bearer header',
      fields: [
        {
          key: 'token',
          label: 'API Key',
          type: 'password',
          required: true,
        },
      ],
      injection: { type: 'bearer_header' },
    },
  ],
};

const STRIPE_TEMPLATE: ServiceTemplate = {
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

async function advanceToCredentialStep(
  user: ReturnType<typeof userEvent.setup>,
  template: ServiceTemplate
) {
  render(
    <AddServiceDialog
      templates={[template]}
      onSave={vi.fn()}
      onClose={vi.fn()}
    />
  );
  await user.click(screen.getByText(template.display_name));
  await waitFor(() => {
    expect(screen.getByLabelText(/api key/i)).toBeInTheDocument();
  });
}

describe('AddServiceDialog - service name field', () => {
  it('shows a Service Name field in the credentials step', async () => {
    const user = userEvent.setup();
    await advanceToCredentialStep(user, CUSTOM_TEMPLATE);
    expect(screen.getByLabelText(/service name/i)).toBeInTheDocument();
  });

  it('shows Service Name field for non-custom templates too', async () => {
    const user = userEvent.setup();
    await advanceToCredentialStep(user, STRIPE_TEMPLATE);
    expect(screen.getByLabelText(/service name/i)).toBeInTheDocument();
  });

  it('Service Name field has correct placeholder for custom template', async () => {
    const user = userEvent.setup();
    await advanceToCredentialStep(user, CUSTOM_TEMPLATE);
    const nameInput = screen.getByLabelText(/service name/i);
    expect(nameInput).toHaveAttribute('placeholder', 'my-api-service');
  });

  it('requires service name for custom template — shows error when empty', async () => {
    const user = userEvent.setup();
    const onSave = vi.fn().mockResolvedValue(undefined);
    render(
      <AddServiceDialog
        templates={[CUSTOM_TEMPLATE]}
        onSave={onSave}
        onClose={vi.fn()}
      />
    );
    await user.click(screen.getByText('Custom Service'));
    await waitFor(() => {
      expect(screen.getByLabelText(/api key/i)).toBeInTheDocument();
    });
    await user.type(screen.getByLabelText(/api key/i), 'mytoken');
    // Do not fill in the service name — click Save
    await user.click(screen.getByRole('button', { name: /save/i }));
    await waitFor(() => {
      expect(screen.getByText(/service name is required/i)).toBeInTheDocument();
    });
    expect(onSave).not.toHaveBeenCalled();
  });

  it('uses user-provided name instead of template id when saving', async () => {
    const user = userEvent.setup();
    const onSave = vi.fn().mockResolvedValue(undefined);
    render(
      <AddServiceDialog
        templates={[STRIPE_TEMPLATE]}
        onSave={onSave}
        onClose={vi.fn()}
      />
    );
    await user.click(screen.getByText('Stripe'));
    await waitFor(() => {
      expect(screen.getByLabelText(/api key/i)).toBeInTheDocument();
    });
    await user.type(screen.getByLabelText(/api key/i), 'sk_live_test123');
    await user.clear(screen.getByLabelText(/service name/i));
    await user.type(screen.getByLabelText(/service name/i), 'stripe-work');
    await user.click(screen.getByRole('button', { name: /save/i }));
    await waitFor(() => {
      expect(onSave).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'stripe-work',
          template: 'stripe',
        })
      );
    });
  });

  it('falls back to template id when name is left empty for non-custom template', async () => {
    const user = userEvent.setup();
    const onSave = vi.fn().mockResolvedValue(undefined);
    render(
      <AddServiceDialog
        templates={[STRIPE_TEMPLATE]}
        onSave={onSave}
        onClose={vi.fn()}
      />
    );
    await user.click(screen.getByText('Stripe'));
    await waitFor(() => {
      expect(screen.getByLabelText(/api key/i)).toBeInTheDocument();
    });
    await user.type(screen.getByLabelText(/api key/i), 'sk_live_test123');
    // Leave name empty — should fall back to template id
    await user.click(screen.getByRole('button', { name: /save/i }));
    await waitFor(() => {
      expect(onSave).toHaveBeenCalledWith(
        expect.objectContaining({
          name: 'stripe',
          template: 'stripe',
        })
      );
    });
  });

  it('rejects invalid name format — shows pattern error', async () => {
    const user = userEvent.setup();
    const onSave = vi.fn().mockResolvedValue(undefined);
    render(
      <AddServiceDialog
        templates={[STRIPE_TEMPLATE]}
        onSave={onSave}
        onClose={vi.fn()}
      />
    );
    await user.click(screen.getByText('Stripe'));
    await waitFor(() => {
      expect(screen.getByLabelText(/api key/i)).toBeInTheDocument();
    });
    await user.type(screen.getByLabelText(/api key/i), 'sk_live_test123');
    await user.clear(screen.getByLabelText(/service name/i));
    await user.type(screen.getByLabelText(/service name/i), 'My Invalid Name!');
    await user.click(screen.getByRole('button', { name: /save/i }));
    await waitFor(() => {
      expect(screen.getByText(/service name.*invalid/i)).toBeInTheDocument();
    });
    expect(onSave).not.toHaveBeenCalled();
  });

  it('resets service name when template changes', async () => {
    const user = userEvent.setup();
    render(
      <AddServiceDialog
        templates={[STRIPE_TEMPLATE, CUSTOM_TEMPLATE]}
        onSave={vi.fn()}
        onClose={vi.fn()}
      />
    );
    // Navigate to credentials for Stripe, set a name
    await user.click(screen.getByText('Stripe'));
    await waitFor(() => {
      expect(screen.getByLabelText(/service name/i)).toBeInTheDocument();
    });
    await user.type(screen.getByLabelText(/service name/i), 'stripe-work');
    // Go back and pick Custom
    await user.click(screen.getByRole('button', { name: /back/i }));
    await waitFor(() => {
      expect(screen.getByText('Custom Service')).toBeInTheDocument();
    });
    await user.click(screen.getByText('Custom Service'));
    await waitFor(() => {
      expect(screen.getByLabelText(/service name/i)).toBeInTheDocument();
    });
    // Name should be reset (empty)
    expect(screen.getByLabelText(/service name/i)).toHaveValue('');
  });
});
