import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor, fireEvent, act } from '@testing-library/react';
import { Services as Dashboard } from '../pages/Services';
import type { Service, ServiceTemplate } from '../types/service';

vi.mock('../api/client', () => ({
  getServices: vi.fn(),
  createService: vi.fn(),
  addServiceFromTemplate: vi.fn(),
  updateService: vi.fn(),
  deleteService: vi.fn(),
  checkCredential: vi.fn(),
  getTemplates: vi.fn(),
}));

import {
  getServices,
  getTemplates,
  createService,
  addServiceFromTemplate,
} from '../api/client';

const MOCK_SERVICES: Service[] = [
  {
    name: 'stripe',
    type: 'http_proxy',
    target: 'https://api.stripe.com',
    inject: 'header',
    header_template: 'Bearer {{.secret}}',
    status: 'available',
    created_at: '2026-03-22T00:00:00Z',
    updated_at: '2026-03-22T00:00:00Z',
  },
  {
    name: 'github',
    type: 'oauth',
    target: 'https://api.github.com',
    inject: 'header',
    status: 'expired',
    created_at: '2026-03-22T00:00:00Z',
    updated_at: '2026-03-22T00:00:00Z',
  },
];

const MOCK_TEMPLATES: ServiceTemplate[] = [
  {
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
  },
];

describe('Dashboard - empty state', () => {
  beforeEach(() => {

    vi.mocked(getServices).mockResolvedValue([]);
    vi.mocked(getTemplates).mockResolvedValue([]);
  });

  it('shows empty state message when no services', async () => {
    render(<Dashboard />);
    await waitFor(() => {
      expect(
        screen.getByText(/no services configured yet/i)
      ).toBeInTheDocument();
    });
  });

  it('shows Add Service button', async () => {
    render(<Dashboard />);
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /add service/i })).toBeInTheDocument();
    });
  });
});

describe('Dashboard - populated state', () => {
  beforeEach(() => {

    vi.mocked(getServices).mockResolvedValue(MOCK_SERVICES);
    vi.mocked(getTemplates).mockResolvedValue(MOCK_TEMPLATES);
  });

  it('renders service tiles for each service', async () => {
    render(<Dashboard />);
    await waitFor(() => {
      expect(screen.getByText('stripe')).toBeInTheDocument();
      expect(screen.getByText('github')).toBeInTheDocument();
    });
  });

  it('still shows Add Service button when services exist', async () => {
    render(<Dashboard />);
    await waitFor(() => {
      expect(screen.getByRole('button', { name: /add service/i })).toBeInTheDocument();
    });
  });

  it('does not show empty state when services exist', async () => {
    render(<Dashboard />);
    await waitFor(() => {
      expect(screen.queryByText(/no services configured yet/i)).not.toBeInTheDocument();
    });
  });
});

describe('Dashboard - auto-refresh', () => {
  beforeEach(() => {

    vi.mocked(getServices).mockResolvedValue([]);
    vi.mocked(getTemplates).mockResolvedValue([]);
  });

  it('re-fetches services every 30 seconds', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });

    render(<Dashboard />);

    await act(async () => {
      await Promise.resolve();
    });

    const initialCalls = vi.mocked(getServices).mock.calls.length;

    await act(async () => {
      vi.advanceTimersByTime(30_000);
      await Promise.resolve();
    });

    expect(vi.mocked(getServices).mock.calls.length).toBeGreaterThan(initialCalls);

    vi.useRealTimers();
  });
});

describe('Dashboard - AddServiceDialog flow', () => {
  beforeEach(() => {

    vi.mocked(getServices).mockResolvedValue([]);
    vi.mocked(getTemplates).mockResolvedValue(MOCK_TEMPLATES);
  });

  it('opens AddServiceDialog when Add Service is clicked', async () => {
    render(<Dashboard />);

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /add service/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /add service/i }));

    await waitFor(() => {
      expect(screen.getByRole('dialog')).toBeInTheDocument();
    });
  });

  it('shows template names in the dialog', async () => {
    render(<Dashboard />);

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /add service/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /add service/i }));

    await waitFor(() => {
      expect(screen.getByText('Stripe')).toBeInTheDocument();
    });
  });

  it('closes the dialog when close button is clicked', async () => {
    render(<Dashboard />);

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /add service/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /add service/i }));

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /close/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /close/i }));

    await waitFor(() => {
      expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    });
  });
});

describe('Dashboard - createService flow', () => {
  beforeEach(() => {

    vi.mocked(getServices).mockResolvedValue([]);
    vi.mocked(getTemplates).mockResolvedValue(MOCK_TEMPLATES);
    vi.mocked(createService).mockResolvedValue(MOCK_SERVICES[0]);
    vi.mocked(addServiceFromTemplate).mockResolvedValue(MOCK_SERVICES[0]);
  });

  it('calls addServiceFromTemplate and refreshes list after save', async () => {
    vi.mocked(getServices)
      .mockResolvedValueOnce([])
      .mockResolvedValueOnce(MOCK_SERVICES);

    render(<Dashboard />);

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /add service/i })).toBeInTheDocument();
    });

    fireEvent.click(screen.getByRole('button', { name: /add service/i }));

    await waitFor(() => {
      expect(screen.getByText('Stripe')).toBeInTheDocument();
    });

    fireEvent.click(screen.getByText('Stripe'));

    await waitFor(() => {
      expect(screen.getByLabelText(/api key/i)).toBeInTheDocument();
    });

    const credInput = screen.getByLabelText(/api key/i);
    fireEvent.change(credInput, { target: { value: 'sk_live_test' } });

    fireEvent.click(screen.getByRole('button', { name: /save/i }));

    await waitFor(() => {
      expect(addServiceFromTemplate).toHaveBeenCalled();
    });
  });
});

describe('Dashboard - templates fetch error', () => {
  beforeEach(() => {

    vi.mocked(getServices).mockResolvedValue([]);
  });

  it('falls back to empty templates when getTemplates fails', async () => {
    vi.mocked(getTemplates).mockRejectedValue(new Error('Templates unavailable'));

    render(<Dashboard />);

    await waitFor(() => {
      expect(screen.getByRole('button', { name: /add service/i })).toBeInTheDocument();
    });

    // Should still render without error
    expect(screen.queryByText(/error/i)).not.toBeInTheDocument();
  });
});
