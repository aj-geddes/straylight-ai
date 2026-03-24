import { useEffect, useState, useCallback } from 'react';
import { HealthBanner } from '../components/HealthBanner';
import { ServiceTile } from '../components/ServiceTile';
import { AddServiceDialog } from '../components/AddServiceDialog';
import { getServices, addServiceFromTemplate, getTemplates, getStats } from '../api/client';
import type { StatsResponse } from '../api/client';
import type { Service, ServiceTemplate, AddServiceRequest } from '../types/service';

const REFRESH_INTERVAL_MS = 30_000;
const STATS_REFRESH_INTERVAL_MS = 60_000;

/** Formats uptime seconds into a human-readable string like "1h 5m" or "45s". */
function formatUptime(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (hours > 0) {
    return minutes > 0 ? `${hours}h ${minutes}m` : `${hours}h`;
  }
  return `${minutes}m`;
}

/** Returns status badge class based on HTTP status code. */
function statusBadgeClass(status: number): string {
  if (status >= 200 && status < 300) {
    return 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300';
  }
  if (status >= 400) {
    return 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300';
  }
  return 'bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300';
}

/** Reads oauth=success and service= query params from the current URL. */
function getOAuthSuccessFromURL(): { success: boolean; serviceName: string } {
  const params = new URLSearchParams(window.location.search);
  return {
    success: params.get('oauth') === 'success',
    serviceName: params.get('service') ?? '',
  };
}

/**
 * Main dashboard page.
 * Shows system health, a grid of service tiles, and controls for adding services.
 * Detects oauth=success query param on mount and shows a success banner.
 */
export function Dashboard() {
  const [services, setServices] = useState<Service[]>([]);
  const [templates, setTemplates] = useState<ServiceTemplate[]>([]);
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [oauthSuccess, setOauthSuccess] = useState<string | null>(null);

  const fetchServices = useCallback(async () => {
    try {
      const result = await getServices();
      setServices(result);
    } catch {
      // Keep existing list on error; errors shown via health banner
    }
  }, []);

  const fetchTemplates = useCallback(async () => {
    try {
      const result = await getTemplates();
      setTemplates(result);
    } catch {
      setTemplates([]);
    }
  }, []);

  const fetchStats = useCallback(async () => {
    try {
      const result = await getStats();
      setStats(result);
    } catch {
      // Stats are non-critical; keep existing on error
    }
  }, []);

  useEffect(() => {
    void fetchServices();
    void fetchTemplates();
    void fetchStats();

    // Check for OAuth success redirect.
    const { success, serviceName } = getOAuthSuccessFromURL();
    if (success) {
      setOauthSuccess(serviceName || 'service');
    }

    const servicesInterval = setInterval(() => {
      void fetchServices();
    }, REFRESH_INTERVAL_MS);

    const statsInterval = setInterval(() => {
      void fetchStats();
    }, STATS_REFRESH_INTERVAL_MS);

    return () => {
      clearInterval(servicesInterval);
      clearInterval(statsInterval);
    };
  }, [fetchServices, fetchTemplates, fetchStats]);

  async function handleSaveService(data: AddServiceRequest): Promise<void> {
    await addServiceFromTemplate(data);
    await fetchServices();
  }

  function handleServiceClick(service: Service) {
    window.location.href = `/services/${service.name}`;
  }

  return (
    <div className="space-y-6">
      {oauthSuccess !== null && (
        <div
          role="status"
          className="flex items-center justify-between rounded-md border border-green-200 bg-green-50 px-4 py-3 dark:border-green-800 dark:bg-green-900/20"
        >
          <p className="text-sm font-medium text-green-800 dark:text-green-200">
            Successfully connected{' '}
            <span className="font-semibold">{oauthSuccess}</span> via OAuth.
          </p>
          <button
            type="button"
            onClick={() => setOauthSuccess(null)}
            aria-label="Dismiss"
            className="rounded p-1 text-green-600 hover:bg-green-100 dark:text-green-400 dark:hover:bg-green-900/40"
          >
            <svg
              aria-hidden="true"
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>
      )}
      <div className="flex items-center justify-between">
        <HealthBanner />
      </div>

      {/* Stats bar — subtle summary below health banner */}
      {stats !== null && (
        <div className="flex items-center gap-4 rounded-md border border-slate-200 bg-white px-4 py-2.5 text-sm text-slate-500 dark:border-slate-700 dark:bg-slate-800 dark:text-slate-400">
          <span>
            <span className="font-medium text-slate-900 dark:text-slate-100">{stats.total_api_calls}</span>
            {' '}API call{stats.total_api_calls !== 1 ? 's' : ''}
          </span>
          <span className="text-slate-300 dark:text-slate-600">|</span>
          <span>
            <span className="font-medium text-slate-900 dark:text-slate-100">{stats.total_services}</span>
            {' '}service{stats.total_services !== 1 ? 's' : ''}
          </span>
          <span className="text-slate-300 dark:text-slate-600">|</span>
          <span>
            <span className="font-medium text-slate-900 dark:text-slate-100">{formatUptime(stats.uptime_seconds)}</span>
            {' '}uptime
          </span>
        </div>
      )}

      <section>
        <div className="mb-5 flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">
              Services
            </h2>
            <p className="mt-0.5 text-sm text-slate-500 dark:text-slate-400">
              {services.length > 0
                ? `${services.length} service${services.length === 1 ? '' : 's'} connected`
                : 'Connect your first service to get started'}
            </p>
          </div>
          <button
            type="button"
            onClick={() => setDialogOpen(true)}
            className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm transition-colors hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 dark:bg-indigo-500 dark:hover:bg-indigo-600"
          >
            <svg
              aria-hidden="true"
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            >
              <line x1="12" y1="5" x2="12" y2="19" />
              <line x1="5" y1="12" x2="19" y2="12" />
            </svg>
            Add Service
          </button>
        </div>

        {services.length === 0 ? (
          <div className="flex flex-col items-center justify-center rounded-xl border-2 border-dashed border-slate-200 bg-white py-16 text-center dark:border-slate-700 dark:bg-slate-800/50">
            <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-indigo-100 dark:bg-indigo-900/30">
              <svg
                aria-hidden="true"
                width="24"
                height="24"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="1.5"
                strokeLinecap="round"
                strokeLinejoin="round"
                className="text-indigo-600 dark:text-indigo-400"
              >
                <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
              </svg>
            </div>
            <p className="mb-1 text-sm font-medium text-slate-700 dark:text-slate-300">
              No services configured yet
            </p>
            <p className="mb-5 text-sm text-slate-500 dark:text-slate-400">
              Connect your first service to get started.
            </p>
            <button
              type="button"
              onClick={() => setDialogOpen(true)}
              className="rounded-lg border border-indigo-200 bg-indigo-50 px-4 py-2 text-sm font-medium text-indigo-700 transition-colors hover:bg-indigo-100 dark:border-indigo-800 dark:bg-indigo-900/20 dark:text-indigo-300 dark:hover:bg-indigo-900/30"
            >
              Add your first service
            </button>
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
            {services.map((service) => (
              <ServiceTile
                key={service.name}
                service={service}
                onClick={handleServiceClick}
              />
            ))}
          </div>
        )}
      </section>

      {/* Activity feed */}
      {stats !== null && (
        <section>
          <h2 className="mb-3 text-base font-semibold text-slate-900 dark:text-slate-100">
            Recent Activity
          </h2>
          {stats.recent_activity.length === 0 ? (
            <p className="text-sm text-slate-400 dark:text-slate-500">No recent activity</p>
          ) : (
            <div className="overflow-hidden rounded-lg border border-slate-200 bg-white dark:border-slate-700 dark:bg-slate-800">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-slate-200 bg-slate-50 dark:border-slate-700 dark:bg-slate-900/50">
                    <th className="px-3 py-2 text-left font-medium text-slate-500 dark:text-slate-400">Time</th>
                    <th className="px-3 py-2 text-left font-medium text-slate-500 dark:text-slate-400">Service</th>
                    <th className="px-3 py-2 text-left font-medium text-slate-500 dark:text-slate-400">Tool</th>
                    <th className="px-3 py-2 text-left font-medium text-slate-500 dark:text-slate-400">Path</th>
                    <th className="px-3 py-2 text-left font-medium text-slate-500 dark:text-slate-400">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {stats.recent_activity.slice().reverse().map((entry, i) => (
                    <tr
                      key={i}
                      className={
                        i % 2 === 0
                          ? 'bg-white dark:bg-slate-800'
                          : 'bg-slate-50/60 dark:bg-slate-900/30'
                      }
                    >
                      <td className="px-3 py-2 text-slate-400 dark:text-slate-500">
                        {new Date(entry.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="px-3 py-2 font-medium text-slate-700 dark:text-slate-300">
                        {entry.service}
                      </td>
                      <td className="px-3 py-2 text-slate-500 dark:text-slate-400">
                        {entry.tool}
                      </td>
                      <td className="px-3 py-2 text-slate-400 dark:text-slate-500 font-mono">
                        {entry.method && entry.path
                          ? `${entry.method} ${entry.path}`
                          : entry.path || '—'}
                      </td>
                      <td className="px-3 py-2">
                        <span
                          className={[
                            'inline-block rounded px-1.5 py-0.5 font-medium',
                            statusBadgeClass(entry.status),
                          ].join(' ')}
                        >
                          {entry.status}
                        </span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      )}

      {dialogOpen && (
        <AddServiceDialog
          templates={templates}
          onSave={handleSaveService}
          onClose={() => setDialogOpen(false)}
        />
      )}
    </div>
  );
}
