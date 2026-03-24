import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { PasteKeyDialog } from '../components/PasteKeyDialog';
import type { ServiceTemplate } from '../types/service';

const STRIPE_TEMPLATE: ServiceTemplate = {
  id: 'stripe',
  display_name: 'Stripe',
  name: 'stripe',
  type: 'http_proxy',
  target: 'https://api.stripe.com',
  inject: 'header',
  header_template: 'Bearer {{.secret}}',
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

describe('PasteKeyDialog - rendering (create from template)', () => {
  it('renders the dialog title with template name', () => {
    render(
      <PasteKeyDialog
        mode="create"
        template={STRIPE_TEMPLATE}
        onSave={vi.fn()}
        onClose={vi.fn()}
      />
    );
    expect(screen.getByText(/stripe/i)).toBeInTheDocument();
  });

  it('shows a name field pre-filled with template id', () => {
    render(
      <PasteKeyDialog
        mode="create"
        template={STRIPE_TEMPLATE}
        onSave={vi.fn()}
        onClose={vi.fn()}
      />
    );
    const nameInput = screen.getByLabelText(/service name/i);
    expect(nameInput).toHaveValue('Stripe');
  });

  it('shows a credential input of type password', () => {
    render(
      <PasteKeyDialog
        mode="create"
        template={STRIPE_TEMPLATE}
        onSave={vi.fn()}
        onClose={vi.fn()}
      />
    );
    const credInput = screen.getByLabelText(/api key/i);
    expect(credInput).toHaveAttribute('type', 'password');
  });

  it('renders a Save button', () => {
    render(
      <PasteKeyDialog
        mode="create"
        template={STRIPE_TEMPLATE}
        onSave={vi.fn()}
        onClose={vi.fn()}
      />
    );
    expect(screen.getByRole('button', { name: /save/i })).toBeInTheDocument();
  });

  it('renders a Cancel button', () => {
    render(
      <PasteKeyDialog
        mode="create"
        template={STRIPE_TEMPLATE}
        onSave={vi.fn()}
        onClose={vi.fn()}
      />
    );
    expect(screen.getByRole('button', { name: /cancel/i })).toBeInTheDocument();
  });
});

describe('PasteKeyDialog - rendering (update mode)', () => {
  it('shows update credential title', () => {
    render(
      <PasteKeyDialog
        mode="update"
        serviceName="stripe"
        onSave={vi.fn()}
        onClose={vi.fn()}
      />
    );
    expect(screen.getByText(/update credential/i)).toBeInTheDocument();
  });

  it('does not show the service name field in update mode', () => {
    render(
      <PasteKeyDialog
        mode="update"
        serviceName="stripe"
        onSave={vi.fn()}
        onClose={vi.fn()}
      />
    );
    expect(screen.queryByLabelText(/service name/i)).not.toBeInTheDocument();
  });

  it('shows credential input field', () => {
    render(
      <PasteKeyDialog
        mode="update"
        serviceName="stripe"
        onSave={vi.fn()}
        onClose={vi.fn()}
      />
    );
    // Label text is "Credential"; target by id to avoid matching aria-label on dialog
    expect(document.getElementById('credential-input')).toBeInTheDocument();
  });
});

describe('PasteKeyDialog - form submission (create mode)', () => {
  it('calls onSave with form data when submitted', async () => {
    const user = userEvent.setup();
    const onSave = vi.fn().mockResolvedValue(undefined);

    render(
      <PasteKeyDialog
        mode="create"
        template={STRIPE_TEMPLATE}
        onSave={onSave}
        onClose={vi.fn()}
      />
    );

    const credInput = screen.getByLabelText(/api key/i);
    await user.type(credInput, 'sk_live_test123');

    await user.click(screen.getByRole('button', { name: /save/i }));

    await waitFor(() => {
      expect(onSave).toHaveBeenCalledWith(
        expect.objectContaining({
          credential: 'sk_live_test123',
          type: 'http_proxy',
          target: 'https://api.stripe.com',
          inject: 'header',
        })
      );
    });
  });

  it('clears the credential field after successful save', async () => {
    const user = userEvent.setup();
    const onSave = vi.fn().mockResolvedValue(undefined);

    render(
      <PasteKeyDialog
        mode="create"
        template={STRIPE_TEMPLATE}
        onSave={onSave}
        onClose={vi.fn()}
      />
    );

    const credInput = screen.getByLabelText(/api key/i);
    await user.type(credInput, 'sk_live_test123');
    await user.click(screen.getByRole('button', { name: /save/i }));

    await waitFor(() => {
      expect(credInput).toHaveValue('');
    });
  });

  it('shows validation error when name is empty', async () => {
    const user = userEvent.setup();

    render(
      <PasteKeyDialog
        mode="create"
        template={STRIPE_TEMPLATE}
        onSave={vi.fn()}
        onClose={vi.fn()}
      />
    );

    const nameInput = screen.getByLabelText(/service name/i);
    await user.clear(nameInput);

    await user.click(screen.getByRole('button', { name: /save/i }));

    await waitFor(() => {
      expect(screen.getByText(/name is required/i)).toBeInTheDocument();
    });
  });

  it('shows validation error when credential is empty', async () => {
    const user = userEvent.setup();

    render(
      <PasteKeyDialog
        mode="create"
        template={STRIPE_TEMPLATE}
        onSave={vi.fn()}
        onClose={vi.fn()}
      />
    );

    await user.click(screen.getByRole('button', { name: /save/i }));

    await waitFor(() => {
      expect(screen.getByText(/credential is required/i)).toBeInTheDocument();
    });
  });

  it('shows loading state while saving', async () => {
    const user = userEvent.setup();
    let resolveSave!: () => void;
    const onSave = vi.fn().mockReturnValue(new Promise<void>((res) => { resolveSave = res; }));

    render(
      <PasteKeyDialog
        mode="create"
        template={STRIPE_TEMPLATE}
        onSave={onSave}
        onClose={vi.fn()}
      />
    );

    const credInput = screen.getByLabelText(/api key/i);
    await user.type(credInput, 'sk_live_test123');
    await user.click(screen.getByRole('button', { name: /save/i }));

    expect(screen.getByRole('button', { name: /saving/i })).toBeInTheDocument();

    resolveSave();
  });

  it('shows error message when save fails', async () => {
    const user = userEvent.setup();
    const onSave = vi.fn().mockRejectedValue(new Error('Failed to save service'));

    render(
      <PasteKeyDialog
        mode="create"
        template={STRIPE_TEMPLATE}
        onSave={onSave}
        onClose={vi.fn()}
      />
    );

    const credInput = screen.getByLabelText(/api key/i);
    await user.type(credInput, 'sk_live_test123');
    await user.click(screen.getByRole('button', { name: /save/i }));

    await waitFor(() => {
      expect(screen.getByText(/failed to save service/i)).toBeInTheDocument();
    });
  });
});

describe('PasteKeyDialog - form submission (update mode)', () => {
  it('calls onSave with credential only in update mode', async () => {
    const user = userEvent.setup();
    const onSave = vi.fn().mockResolvedValue(undefined);

    render(
      <PasteKeyDialog
        mode="update"
        serviceName="stripe"
        onSave={onSave}
        onClose={vi.fn()}
      />
    );

    const credInput = document.getElementById('credential-input') as HTMLInputElement;
    await user.type(credInput, 'new_secret_key');
    await user.click(screen.getByRole('button', { name: /save/i }));

    await waitFor(() => {
      expect(onSave).toHaveBeenCalledWith(
        expect.objectContaining({ credential: 'new_secret_key' })
      );
    });
  });
});

describe('PasteKeyDialog - close behavior', () => {
  it('calls onClose when Cancel button is clicked', async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();

    render(
      <PasteKeyDialog
        mode="create"
        template={STRIPE_TEMPLATE}
        onSave={vi.fn()}
        onClose={onClose}
      />
    );

    await user.click(screen.getByRole('button', { name: /cancel/i }));
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
