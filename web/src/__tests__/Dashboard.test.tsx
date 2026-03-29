import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { Dashboard } from '../pages/Dashboard';
import type { HealthResponse } from '../types/health';

vi.mock('../api/client', () => ({
  getHealth: vi.fn(),
  getServices: vi.fn(),
  getTemplates: vi.fn(),
  createService: vi.fn(),
  updateService: vi.fn(),
  deleteService: vi.fn(),
  checkCredential: vi.fn(),
}));

import { getHealth, getServices, getTemplates } from '../api/client';

describe('Dashboard', () => {
  beforeEach(() => {
    vi.mocked(getServices).mockResolvedValue([]);
    vi.mocked(getTemplates).mockResolvedValue([]);
    vi.mocked(getHealth).mockResolvedValue({
      status: 'ok',
      services_count: 0,
      uptime_seconds: 10,
      version: '0.5.0',
    } as HealthResponse);
  });

  it('renders the services section heading', async () => {
    render(<Dashboard />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /services/i })).toBeInTheDocument();
    });
  });

  it('renders empty state message when no services configured', async () => {
    render(<Dashboard />);
    await waitFor(() => {
      expect(
        screen.getByText(/no services configured yet/i)
      ).toBeInTheDocument();
    });
  });

  it('renders the add service button', async () => {
    render(<Dashboard />);
    await waitFor(() => {
      expect(
        screen.getByRole('button', { name: /add service/i })
      ).toBeInTheDocument();
    });
  });
});
