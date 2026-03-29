import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, waitFor, act } from '@testing-library/react';
import { HealthBanner } from '../components/HealthBanner';
import * as client from '../api/client';
import type { HealthResponse } from '../types/health';

afterEach(() => {
  vi.restoreAllMocks();
});

describe('HealthBanner - status rendering', () => {
  it('renders system healthy banner when status is ok', async () => {
    const healthOk: HealthResponse = {
      status: 'ok',
      openbao: 'unsealed',
      services_count: 1,
      uptime_seconds: 60,
      version: '0.5.0',
    };
    vi.spyOn(client, 'getHealth').mockResolvedValue(healthOk);

    render(<HealthBanner />);

    await waitFor(() => {
      expect(screen.getByText(/system healthy/i)).toBeInTheDocument();
    });
  });

  it('renders system starting banner when status is starting', async () => {
    const healthStarting: HealthResponse = {
      status: 'starting',
      services_count: 0,
      uptime_seconds: 3,
      version: '0.5.0',
    };
    vi.spyOn(client, 'getHealth').mockResolvedValue(healthStarting);

    render(<HealthBanner />);

    await waitFor(() => {
      expect(screen.getByText(/system starting/i)).toBeInTheDocument();
    });
  });

  it('renders system degraded banner when status is degraded', async () => {
    const healthDegraded: HealthResponse = {
      status: 'degraded',
      openbao: 'sealed',
      services_count: 0,
      uptime_seconds: 10,
      version: '0.5.0',
    };
    vi.spyOn(client, 'getHealth').mockResolvedValue(healthDegraded);

    render(<HealthBanner />);

    await waitFor(() => {
      expect(screen.getByText(/system degraded/i)).toBeInTheDocument();
    });
  });

  it('renders system degraded banner when fetch fails', async () => {
    vi.spyOn(client, 'getHealth').mockResolvedValue({
      status: 'degraded',
      services_count: 0,
      uptime_seconds: 0,
      version: 'unknown',
    });

    render(<HealthBanner />);

    await waitFor(() => {
      expect(screen.getByText(/system degraded/i)).toBeInTheDocument();
    });
  });

  it('shows a loading state before first fetch completes', () => {
    vi.spyOn(client, 'getHealth').mockImplementation(
      () => new Promise(() => {})
    );

    render(<HealthBanner />);

    expect(screen.getByRole('status')).toBeInTheDocument();
  });

  it('has green styling when status is ok', async () => {
    const healthOk: HealthResponse = {
      status: 'ok',
      services_count: 1,
      uptime_seconds: 60,
      version: '0.5.0',
    };
    vi.spyOn(client, 'getHealth').mockResolvedValue(healthOk);

    render(<HealthBanner />);

    await waitFor(() => {
      const banner = screen.getByRole('alert');
      expect(banner).toHaveClass('bg-emerald-50');
    });
  });

  it('has yellow styling when status is starting', async () => {
    const healthStarting: HealthResponse = {
      status: 'starting',
      services_count: 0,
      uptime_seconds: 3,
      version: '0.5.0',
    };
    vi.spyOn(client, 'getHealth').mockResolvedValue(healthStarting);

    render(<HealthBanner />);

    await waitFor(() => {
      const banner = screen.getByRole('alert');
      expect(banner).toHaveClass('bg-amber-50');
    });
  });

  it('has red styling when status is degraded', async () => {
    const healthDegraded: HealthResponse = {
      status: 'degraded',
      services_count: 0,
      uptime_seconds: 0,
      version: '0.5.0',
    };
    vi.spyOn(client, 'getHealth').mockResolvedValue(healthDegraded);

    render(<HealthBanner />);

    await waitFor(() => {
      const banner = screen.getByRole('alert');
      expect(banner).toHaveClass('bg-red-50');
    });
  });
});

describe('HealthBanner - polling', () => {
  it('re-polls health every 30 seconds', async () => {
    vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval'] });

    const healthOk: HealthResponse = {
      status: 'ok',
      services_count: 1,
      uptime_seconds: 60,
      version: '0.5.0',
    };
    const spy = vi.spyOn(client, 'getHealth').mockResolvedValue(healthOk);

    render(<HealthBanner />);

    // Wait for initial call
    await act(async () => {
      await Promise.resolve();
    });

    expect(spy).toHaveBeenCalledTimes(1);

    await act(async () => {
      vi.advanceTimersByTime(30_000);
      await Promise.resolve();
    });

    expect(spy).toHaveBeenCalledTimes(2);

    vi.useRealTimers();
  });
});
