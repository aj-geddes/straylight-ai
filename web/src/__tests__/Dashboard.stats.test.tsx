import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '@testing-library/react';
import { Dashboard } from '../pages/Dashboard';
import type { StatsResponse } from '../api/client';

vi.mock('../api/client', () => ({
  getHealth: vi.fn().mockResolvedValue({ status: 'ok', version: '0.5.0', openbao: 'unsealed' }),
  getServices: vi.fn().mockResolvedValue([]),
  getTemplates: vi.fn().mockResolvedValue([]),
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
      {
        timestamp: '2026-03-24T10:29:55Z',
        service: 'github',
        tool: 'check',
        method: '',
        path: '',
        status: 200,
      },
    ],
  } satisfies StatsResponse),
}));

beforeEach(() => {
  vi.clearAllMocks();
});

describe('Dashboard - stats bar', () => {
  it('renders stats bar with API call count', async () => {
    render(<Dashboard />);
    await waitFor(() => {
      // "47" is in a <span> and "API calls" in adjacent text
      expect(screen.getByText('47')).toBeInTheDocument();
      expect(screen.getByText(/api calls/i)).toBeInTheDocument();
    });
  });

  it('renders stats bar with service count', async () => {
    render(<Dashboard />);
    await waitFor(() => {
      // Stats bar shows "2 services" — the number "2" is in bold span
      expect(screen.getByText('2')).toBeInTheDocument();
      // "services" appears in stats bar (note: services section also says "2 services connected")
      const servicesTexts = screen.getAllByText(/service/i);
      expect(servicesTexts.length).toBeGreaterThan(0);
    });
  });

  it('renders stats bar with uptime', async () => {
    render(<Dashboard />);
    await waitFor(() => {
      // 3600 seconds = 1h uptime
      expect(screen.getByText('1h')).toBeInTheDocument();
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

  it('renders activity entries with service name', async () => {
    render(<Dashboard />);
    await waitFor(() => {
      const githubEntries = screen.getAllByText(/github/i);
      expect(githubEntries.length).toBeGreaterThan(0);
    });
  });

  it('renders status badges for activity entries', async () => {
    render(<Dashboard />);
    await waitFor(() => {
      // Status 200 should appear in activity
      const status200 = screen.getAllByText('200');
      expect(status200.length).toBeGreaterThan(0);
    });
  });

  it('renders tool name in activity entries', async () => {
    render(<Dashboard />);
    await waitFor(() => {
      expect(screen.getByText(/api_call/i)).toBeInTheDocument();
    });
  });

  it('renders path for api_call entries', async () => {
    render(<Dashboard />);
    await waitFor(() => {
      // Path is rendered as "GET /user/repos" or just "/user/repos"
      expect(screen.getByText(/\/user\/repos/)).toBeInTheDocument();
    });
  });

  it('shows empty state message when no activity', async () => {
    const { getStats } = await import('../api/client');
    vi.mocked(getStats).mockResolvedValueOnce({
      total_services: 0,
      total_api_calls: 0,
      total_exec_calls: 0,
      uptime_seconds: 0,
      recent_activity: [],
    });
    render(<Dashboard />);
    await waitFor(() => {
      expect(screen.getByText(/no recent activity/i)).toBeInTheDocument();
    });
  });
});
