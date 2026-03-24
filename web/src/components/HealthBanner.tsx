import { useEffect, useState } from 'react';
import { getHealth } from '../api/client';
import { StatusIndicator } from './StatusIndicator';
import type { HealthResponse } from '../types/health';

const POLL_INTERVAL_MS = 30_000;

type BannerConfig = {
  bg: string;
  text: string;
  label: string;
};

const BANNER_CONFIGS: Record<HealthResponse['status'], BannerConfig> = {
  ok: {
    bg: 'bg-emerald-50 border-emerald-200 text-emerald-800 dark:bg-emerald-900/20 dark:border-emerald-800 dark:text-emerald-300',
    text: 'System Healthy',
    label: 'System status: healthy',
  },
  starting: {
    bg: 'bg-amber-50 border-amber-200 text-amber-800 dark:bg-amber-900/20 dark:border-amber-800 dark:text-amber-300',
    text: 'System Starting',
    label: 'System status: starting',
  },
  degraded: {
    bg: 'bg-red-50 border-red-200 text-red-800 dark:bg-red-900/20 dark:border-red-800 dark:text-red-300',
    text: 'System Degraded',
    label: 'System status: degraded',
  },
};

/**
 * Pill-style status bar that displays system health.
 * Polls the health endpoint on mount and every 30 seconds.
 */
export function HealthBanner() {
  const [health, setHealth] = useState<HealthResponse | null>(null);

  useEffect(() => {
    let cancelled = false;

    async function poll() {
      const result = await getHealth();
      if (!cancelled) {
        setHealth(result);
      }
    }

    void poll();

    const intervalId = setInterval(() => {
      void poll();
    }, POLL_INTERVAL_MS);

    return () => {
      cancelled = true;
      clearInterval(intervalId);
    };
  }, []);

  if (health === null) {
    return (
      <div
        role="status"
        aria-live="polite"
        className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs text-slate-500 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400"
      >
        <span className="inline-block h-2 w-2 animate-pulse rounded-full bg-slate-400" />
        <span>Checking status...</span>
      </div>
    );
  }

  const config = BANNER_CONFIGS[health.status];

  return (
    <div
      role="alert"
      aria-label={config.label}
      className={`inline-flex items-center gap-2 rounded-full border px-3 py-1.5 text-xs font-medium transition-colors duration-300 ${config.bg}`}
    >
      <StatusIndicator status={health.status} />
      <span>{config.text}</span>
      {health.version !== 'unknown' && (
        <span className="ml-1 opacity-60">v{health.version}</span>
      )}
    </div>
  );
}
