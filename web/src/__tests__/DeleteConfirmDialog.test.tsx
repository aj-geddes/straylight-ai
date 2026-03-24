import { describe, it, expect, vi } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { DeleteConfirmDialog } from '../components/DeleteConfirmDialog';

describe('DeleteConfirmDialog - rendering', () => {
  it('displays the service name in the confirmation message', () => {
    render(
      <DeleteConfirmDialog
        serviceName="stripe"
        onConfirm={vi.fn()}
        onCancel={vi.fn()}
      />
    );
    expect(screen.getAllByText(/stripe/i).length).toBeGreaterThan(0);
  });

  it('shows a warning about permanent removal', () => {
    render(
      <DeleteConfirmDialog
        serviceName="stripe"
        onConfirm={vi.fn()}
        onCancel={vi.fn()}
      />
    );
    expect(screen.getByText(/permanently remove/i)).toBeInTheDocument();
  });

  it('renders a Delete/Confirm button', () => {
    render(
      <DeleteConfirmDialog
        serviceName="stripe"
        onConfirm={vi.fn()}
        onCancel={vi.fn()}
      />
    );
    expect(screen.getByRole('button', { name: /delete/i })).toBeInTheDocument();
  });

  it('renders a Cancel button', () => {
    render(
      <DeleteConfirmDialog
        serviceName="stripe"
        onConfirm={vi.fn()}
        onCancel={vi.fn()}
      />
    );
    expect(screen.getByRole('button', { name: /cancel/i })).toBeInTheDocument();
  });
});

describe('DeleteConfirmDialog - interaction', () => {
  it('calls onConfirm when Delete button is clicked', async () => {
    const user = userEvent.setup();
    const onConfirm = vi.fn().mockResolvedValue(undefined);

    render(
      <DeleteConfirmDialog
        serviceName="stripe"
        onConfirm={onConfirm}
        onCancel={vi.fn()}
      />
    );

    await user.click(screen.getByRole('button', { name: /delete/i }));
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });

  it('calls onCancel when Cancel button is clicked', async () => {
    const user = userEvent.setup();
    const onCancel = vi.fn();

    render(
      <DeleteConfirmDialog
        serviceName="stripe"
        onConfirm={vi.fn()}
        onCancel={onCancel}
      />
    );

    await user.click(screen.getByRole('button', { name: /cancel/i }));
    expect(onCancel).toHaveBeenCalledTimes(1);
  });

  it('shows loading state while deleting', async () => {
    const user = userEvent.setup();
    let resolveDelete!: () => void;
    const onConfirm = vi.fn().mockReturnValue(
      new Promise<void>((res) => { resolveDelete = res; })
    );

    render(
      <DeleteConfirmDialog
        serviceName="stripe"
        onConfirm={onConfirm}
        onCancel={vi.fn()}
      />
    );

    await user.click(screen.getByRole('button', { name: /delete/i }));
    expect(screen.getByRole('button', { name: /deleting/i })).toBeInTheDocument();

    resolveDelete();
  });

  it('shows error message when delete fails', async () => {
    const user = userEvent.setup();
    const onConfirm = vi.fn().mockRejectedValue(new Error('Delete failed'));

    render(
      <DeleteConfirmDialog
        serviceName="stripe"
        onConfirm={onConfirm}
        onCancel={vi.fn()}
      />
    );

    await user.click(screen.getByRole('button', { name: /delete/i }));

    await waitFor(() => {
      expect(screen.getByText(/delete failed/i)).toBeInTheDocument();
    });
  });
});
