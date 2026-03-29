import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { Dashboard } from '../pages/Dashboard';
import type { StatsResponse } from '../api/client';

vi.mock('../api/client', () => ({
  getHealth: vi.fn().mockResolvedValue({ status: 'ok', version: '1.0.1', openbao: 'unsealed' }),
  getServices: vi.fn().mockResolvedValue([]),
  getStats: vi.fn().mockResolvedValue({
    total_services: 2,
    total_api_calls: 47,
    total_exec_calls: 3,
    uptime_seconds: 3600,
    recent_activity: [
      {
        timestamp: '2026-03-24T10:30:00Z',
        service: 'github',
        tool: 'api_call',
        method: 'GET',
        path: '/user/repos',
        status: 200,
      },
    ],
  } satisfies StatsResponse),
  getAuditStats: vi.fn().mockResolvedValue({
    by_type: { credential_accessed: 10, tool_call: 25 },
    by_service: { github: 20 },
    total: 35,
  }),
  getAuditEvents: vi.fn().mockResolvedValue({ events: [], total: 0 }),
}));

beforeEach(() => {
  vi.clearAllMocks();
});

describe('Dashboard - metric cards', () => {
  it('renders metric card with API call count', async () => {
    render(<Dashboard />);
    await waitFor(() => {
      expect(screen.getByText('47')).toBeInTheDocument();
    });
  });

  it('renders metric card with uptime', async () => {
    render(<Dashboard />);
    await waitFor(() => {
      expect(screen.getByText('1h')).toBeInTheDocument();
    });
  });

  it('renders system health status', async () => {
    render(<Dashboard />);
    await waitFor(() => {
      expect(screen.getByText('Healthy')).toBeInTheDocument();
    });
  });

  it('renders vault status', async () => {
    render(<Dashboard />);
    await waitFor(() => {
      expect(screen.getByText('Unsealed')).toBeInTheDocument();
    });
  });

  it('renders audit event count', async () => {
    render(<Dashboard />);
    await waitFor(() => {
      expect(screen.getByText('35')).toBeInTheDocument();
    });
  });
});

describe('Dashboard - activity feed', () => {
  it('renders Recent Activity section heading', async () => {
    render(<Dashboard />);
    await waitFor(() => {
      expect(screen.getByText(/recent activity/i)).toBeInTheDocument();
    });
  });

  it('shows no-activity message when empty', async () => {
    const { getStats, getAuditEvents } = await import('../api/client');
    vi.mocked(getStats).mockResolvedValueOnce({
      total_services: 0,
      total_api_calls: 0,
      total_exec_calls: 0,
      uptime_seconds: 0,
      recent_activity: [],
    });
    vi.mocked(getAuditEvents).mockResolvedValueOnce({ events: [], total: 0 });
    render(<Dashboard />);
    await waitFor(() => {
      expect(screen.getByText(/no activity recorded/i)).toBeInTheDocument();
    });
  });
});

describe('Dashboard - audit breakdown', () => {
  it('renders audit breakdown with event types', async () => {
    render(<Dashboard />);
    await waitFor(() => {
      expect(screen.getByText(/audit breakdown/i)).toBeInTheDocument();
    });
  });
});
