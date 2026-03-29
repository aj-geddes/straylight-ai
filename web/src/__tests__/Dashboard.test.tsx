import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { Dashboard } from '../pages/Dashboard';

vi.mock('../api/client', () => ({
  getHealth: vi.fn(),
  getServices: vi.fn(),
  getStats: vi.fn(),
  getAuditStats: vi.fn(),
  getAuditEvents: vi.fn(),
}));

import { getHealth, getServices, getStats, getAuditStats, getAuditEvents } from '../api/client';

describe('Dashboard', () => {
  beforeEach(() => {
    vi.mocked(getHealth).mockResolvedValue({
      status: 'ok',
      services_count: 0,
      uptime_seconds: 120,
      version: '1.0.1',
      openbao: 'unsealed',
    });
    vi.mocked(getServices).mockResolvedValue([]);
    vi.mocked(getStats).mockResolvedValue({
      total_services: 0,
      total_api_calls: 5,
      total_exec_calls: 2,
      uptime_seconds: 120,
      recent_activity: [],
    });
    vi.mocked(getAuditStats).mockResolvedValue({
      by_type: {},
      by_service: {},
      total: 0,
    });
    vi.mocked(getAuditEvents).mockResolvedValue({
      events: [],
      total: 0,
    });
  });

  it('renders the Dashboard heading', async () => {
    render(<Dashboard />);
    await waitFor(() => {
      expect(screen.getByRole('heading', { name: /dashboard/i })).toBeInTheDocument();
    });
  });

  it('renders metric cards', async () => {
    render(<Dashboard />);
    await waitFor(() => {
      expect(screen.getByText('Healthy')).toBeInTheDocument();
      expect(screen.getByText('Unsealed')).toBeInTheDocument();
    });
  });

  it('renders service status section', async () => {
    render(<Dashboard />);
    await waitFor(() => {
      expect(screen.getByText(/service status/i)).toBeInTheDocument();
    });
  });
});
