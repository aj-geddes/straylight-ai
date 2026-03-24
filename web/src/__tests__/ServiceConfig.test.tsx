import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { ServiceConfig } from '../pages/ServiceConfig';
import type { Service } from '../types/service';

vi.mock('../api/client', () => ({
  getService: vi.fn(),
  updateService: vi.fn(),
  deleteService: vi.fn(),
  checkCredential: vi.fn(),
}));

import { getService, updateService, deleteService } from '../api/client';

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

describe('ServiceConfig - rendering', () => {
  beforeEach(() => {
    vi.mocked(getService).mockResolvedValue(MOCK_SERVICE);
  });

  it('displays the service name as a heading', async () => {
    render(<ServiceConfig name="stripe" onBack={vi.fn()} />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /stripe/i })).toBeInTheDocument();
    });
  });

  it('displays the service type', async () => {
    render(<ServiceConfig name="stripe" onBack={vi.fn()} />);
    await waitFor(() => {
      expect(screen.getByText(/http_proxy/i)).toBeInTheDocument();
    });
  });

  it('displays the target URL', async () => {
    render(<ServiceConfig name="stripe" onBack={vi.fn()} />);
    await waitFor(() => {
      expect(screen.getByText('https://api.stripe.com')).toBeInTheDocument();
    });
  });

  it('displays the inject method', async () => {
    render(<ServiceConfig name="stripe" onBack={vi.fn()} />);
    await waitFor(() => {
      expect(screen.getByText(/injection method/i)).toBeInTheDocument();
    });
  });

  it('does NOT display a credential value field', async () => {
    render(<ServiceConfig name="stripe" onBack={vi.fn()} />);
    await waitFor(() => {
      expect(screen.queryByLabelText(/credential value/i)).not.toBeInTheDocument();
    });
  });

  it('renders an Update Credential button', async () => {
    render(<ServiceConfig name="stripe" onBack={vi.fn()} />);
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /update credential/i })).toBeInTheDocument();
    });
  });

  it('renders a Delete button', async () => {
    render(<ServiceConfig name="stripe" onBack={vi.fn()} />);
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /delete/i })).toBeInTheDocument();
    });
  });

  it('renders a Back button', async () => {
    render(<ServiceConfig name="stripe" onBack={vi.fn()} />);
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /back/i })).toBeInTheDocument();
    });
  });
});

describe('ServiceConfig - interaction', () => {
  beforeEach(() => {
    vi.mocked(getService).mockResolvedValue(MOCK_SERVICE);
  });

  it('calls onBack when Back button is clicked', async () => {
    const onBack = vi.fn();
    render(<ServiceConfig name="stripe" onBack={onBack} />);
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /back/i })).toBeInTheDocument();
    });
    fireEvent.click(screen.getByRole('button', { name: /back/i }));
    expect(onBack).toHaveBeenCalledTimes(1);
  });

  it('opens PasteKeyDialog in update mode when Update Credential is clicked', async () => {
    render(<ServiceConfig name="stripe" onBack={vi.fn()} />);
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /update credential/i })).toBeInTheDocument();
    });
    fireEvent.click(screen.getByRole('button', { name: /update credential/i }));
    await waitFor(() => {
      // PasteKeyDialog in update mode renders a dialog role element
      expect(screen.getByRole('dialog', { name: /update credential/i })).toBeInTheDocument();
    });
  });

  it('opens DeleteConfirmDialog when Delete is clicked', async () => {
    render(<ServiceConfig name="stripe" onBack={vi.fn()} />);
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /delete/i })).toBeInTheDocument();
    });
    fireEvent.click(screen.getByRole('button', { name: /delete/i }));
    await waitFor(() => {
      expect(screen.getByText(/permanently remove/i)).toBeInTheDocument();
    });
  });
});

describe('ServiceConfig - loading state', () => {
  it('shows loading state while fetching service', () => {
    vi.mocked(getService).mockReturnValue(new Promise(() => {}));
    render(<ServiceConfig name="stripe" onBack={vi.fn()} />);
    expect(screen.getByText(/loading/i)).toBeInTheDocument();
  });
});

describe('ServiceConfig - error state', () => {
  it('shows error when service fails to load', async () => {
    vi.mocked(getService).mockRejectedValue(new Error('Service not found'));
    render(<ServiceConfig name="stripe" onBack={vi.fn()} />);
    await waitFor(() => {
      expect(screen.getByText(/service not found/i)).toBeInTheDocument();
    });
  });

  it('shows go back link on error', async () => {
    vi.mocked(getService).mockRejectedValue(new Error('Service not found'));
    render(<ServiceConfig name="stripe" onBack={vi.fn()} />);
    await waitFor(() => {
      expect(screen.getByText(/go back/i)).toBeInTheDocument();
    });
  });
});

describe('ServiceConfig - update credential flow', () => {
  beforeEach(() => {
    vi.mocked(getService).mockResolvedValue(MOCK_SERVICE);
  });

  it('calls updateService and closes dialog on successful credential update', async () => {
    const updatedService = { ...MOCK_SERVICE, status: 'available' as const };
    vi.mocked(updateService).mockResolvedValue(updatedService);

    render(<ServiceConfig name="stripe" onBack={vi.fn()} />);

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /update credential/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /update credential/i }));

    await waitFor(() => {
      expect(screen.getByRole('dialog')).toBeInTheDocument();
    });

    const credInput = document.getElementById('credential-input') as HTMLInputElement;
    fireEvent.change(credInput, { target: { value: 'new_secret' } });
    fireEvent.click(screen.getByRole('button', { name: /save/i }));

    await waitFor(() => {
      expect(updateService).toHaveBeenCalledWith('stripe', { credential: 'new_secret' });
    });
  });
});

describe('ServiceConfig - account info section', () => {
  it('shows account info section when account_info is present', async () => {
    const serviceWithAccountInfo = {
      ...MOCK_SERVICE,
      account_info: {
        display_name: 'AJ Geddes',
        username: 'aj-geddes',
        avatar_url: 'https://avatars.githubusercontent.com/u/123',
        url: 'https://github.com/aj-geddes',
        plan: 'pro',
        extra: {
          public_repos: '26',
          followers: '10',
        },
      },
    };
    vi.mocked(getService).mockResolvedValue(serviceWithAccountInfo);
    render(<ServiceConfig name="stripe" onBack={vi.fn()} />);
    await waitFor(() => {
      expect(screen.getByText(/account/i)).toBeInTheDocument();
    });
  });

  it('displays display_name in account section', async () => {
    const serviceWithAccountInfo = {
      ...MOCK_SERVICE,
      account_info: {
        display_name: 'AJ Geddes',
        username: 'aj-geddes',
      },
    };
    vi.mocked(getService).mockResolvedValue(serviceWithAccountInfo);
    render(<ServiceConfig name="stripe" onBack={vi.fn()} />);
    await waitFor(() => {
      expect(screen.getByText('AJ Geddes')).toBeInTheDocument();
    });
  });

  it('displays username in account section', async () => {
    const serviceWithAccountInfo = {
      ...MOCK_SERVICE,
      account_info: {
        display_name: 'AJ Geddes',
        username: 'aj-geddes',
      },
    };
    vi.mocked(getService).mockResolvedValue(serviceWithAccountInfo);
    render(<ServiceConfig name="stripe" onBack={vi.fn()} />);
    await waitFor(() => {
      expect(screen.getByText('aj-geddes')).toBeInTheDocument();
    });
  });

  it('renders profile link when url is present', async () => {
    const serviceWithAccountInfo = {
      ...MOCK_SERVICE,
      account_info: {
        display_name: 'AJ Geddes',
        url: 'https://github.com/aj-geddes',
      },
    };
    vi.mocked(getService).mockResolvedValue(serviceWithAccountInfo);
    render(<ServiceConfig name="stripe" onBack={vi.fn()} />);
    await waitFor(() => {
      const link = screen.getByRole('link', { name: /profile/i });
      expect(link).toHaveAttribute('href', 'https://github.com/aj-geddes');
    });
  });

  it('shows plan badge when plan is present', async () => {
    const serviceWithAccountInfo = {
      ...MOCK_SERVICE,
      account_info: {
        display_name: 'AJ Geddes',
        plan: 'pro',
      },
    };
    vi.mocked(getService).mockResolvedValue(serviceWithAccountInfo);
    render(<ServiceConfig name="stripe" onBack={vi.fn()} />);
    await waitFor(() => {
      // Plan badge renders the exact plan text in a <span>
      expect(screen.getByText((content) => content === 'pro')).toBeInTheDocument();
    });
  });

  it('shows extra stats in account section', async () => {
    const serviceWithAccountInfo = {
      ...MOCK_SERVICE,
      account_info: {
        display_name: 'AJ Geddes',
        extra: {
          public_repos: '26',
          followers: '10',
        },
      },
    };
    vi.mocked(getService).mockResolvedValue(serviceWithAccountInfo);
    render(<ServiceConfig name="stripe" onBack={vi.fn()} />);
    await waitFor(() => {
      expect(screen.getByText('public_repos')).toBeInTheDocument();
      expect(screen.getByText('26')).toBeInTheDocument();
    });
  });

  it('does not show account section when account_info is absent', async () => {
    vi.mocked(getService).mockResolvedValue(MOCK_SERVICE);
    render(<ServiceConfig name="stripe" onBack={vi.fn()} />);
    await waitFor(() => {
      // Service card should render without an "Account" heading
      expect(screen.queryByRole('heading', { name: /^account$/i })).not.toBeInTheDocument();
    });
  });
});

describe('ServiceConfig - delete flow', () => {
  beforeEach(() => {
    vi.mocked(getService).mockResolvedValue(MOCK_SERVICE);
  });

  it('calls deleteService and invokes onBack after confirmation', async () => {
    vi.mocked(deleteService).mockResolvedValue(undefined);
    const onBack = vi.fn();

    render(<ServiceConfig name="stripe" onBack={onBack} />);

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /delete/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /delete/i }));

    await waitFor(() => {
      expect(screen.getByText(/permanently remove/i)).toBeInTheDocument();
    });

    // Both ServiceConfig Delete button and dialog Delete button are visible;
    // click the last "Delete" button (inside the confirmation dialog)
    const deleteButtons = screen.getAllByRole('button', { name: /^delete$/i });
    fireEvent.click(deleteButtons[deleteButtons.length - 1]);

    await waitFor(() => {
      expect(deleteService).toHaveBeenCalledWith('stripe');
      expect(onBack).toHaveBeenCalledTimes(1);
    });
  });

  it('closes DeleteConfirmDialog on Cancel', async () => {
    render(<ServiceConfig name="stripe" onBack={vi.fn()} />);

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /delete/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /delete/i }));

    await waitFor(() => {
      expect(screen.getByText(/permanently remove/i)).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /cancel/i }));

    await waitFor(() => {
      expect(screen.queryByText(/permanently remove/i)).not.toBeInTheDocument();
    });
  });
});
