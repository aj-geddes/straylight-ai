import { useEffect, useState, useCallback } from 'react';
import { getHealth, getStats, getServices, getAuditStats, getAuditEvents } from '../api/client';
import type { StatsResponse, AuditStatsResponse, AuditEvent } from '../api/client';
import type { HealthResponse } from '../types/health';
import type { Service } from '../types/service';
import { StatusIndicator } from '../components/StatusIndicator';
import { ServiceIcon } from '../components/ServiceIcon';

const POLL_MS = 15_000;

function formatUptime(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return h > 0 ? `${d}d ${h}h` : `${d}d`;
  if (h > 0) return m > 0 ? `${h}h ${m}m` : `${h}h`;
  return `${m}m`;
}

function formatTimeAgo(ts: string): string {
  const diff = Math.floor((Date.now() - new Date(ts).getTime()) / 1000);
  if (diff < 60) return 'just now';
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function eventTypeLabel(t: string): string {
  return t.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
}

function eventTypeColor(t: string): string {
  if (t.includes('accessed') || t.includes('read'))
    return 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300';
  if (t.includes('stored') || t.includes('created'))
    return 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300';
  if (t.includes('deleted') || t.includes('revoked') || t.includes('expired'))
    return 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300';
  if (t.includes('rotated') || t.includes('renewed'))
    return 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300';
  return 'bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300';
}

/** Metric card component */
function Metric({ label, value, sub, accent }: { label: string; value: string | number; sub?: string; accent?: string }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-700 dark:bg-slate-800">
      <p className="text-xs font-medium uppercase tracking-wider text-slate-400 dark:text-slate-500">{label}</p>
      <p className={`mt-1.5 text-2xl font-bold tabular-nums ${accent ?? 'text-slate-900 dark:text-slate-100'}`}>
        {value}
      </p>
      {sub && <p className="mt-0.5 text-xs text-slate-400 dark:text-slate-500">{sub}</p>}
    </div>
  );
}

export function Dashboard() {
  const [health, setHealth] = useState<HealthResponse | null>(null);
  const [stats, setStats] = useState<StatsResponse | null>(null);
  const [services, setServices] = useState<Service[]>([]);
  const [auditStats, setAuditStats] = useState<AuditStatsResponse | null>(null);
  const [auditEvents, setAuditEvents] = useState<AuditEvent[]>([]);

  const fetchAll = useCallback(async () => {
    const [h, st, sv, as_, ae] = await Promise.all([
      getHealth(),
      getStats(),
      getServices().catch(() => [] as Service[]),
      getAuditStats(),
      getAuditEvents({ limit: 20 }),
    ]);
    setHealth(h);
    setStats(st);
    setServices(sv);
    setAuditStats(as_);
    setAuditEvents(ae.events);
  }, []);

  useEffect(() => {
    void fetchAll();
    const id = setInterval(() => void fetchAll(), POLL_MS);
    return () => clearInterval(id);
  }, [fetchAll]);

  const healthColor = health?.status === 'ok'
    ? 'text-emerald-600 dark:text-emerald-400'
    : health?.status === 'starting'
      ? 'text-amber-600 dark:text-amber-400'
      : 'text-red-600 dark:text-red-400';

  const vaultLabel = health?.openbao === 'unsealed' ? 'Unsealed' : health?.openbao === 'sealed' ? 'Sealed' : 'Unavailable';
  const vaultColor = health?.openbao === 'unsealed'
    ? 'text-emerald-600 dark:text-emerald-400'
    : 'text-red-600 dark:text-red-400';

  const availableCount = services.filter((s) => s.status === 'available').length;
  const degradedCount = services.length - availableCount;

  // Top event types for audit breakdown
  const topEventTypes = auditStats
    ? Object.entries(auditStats.by_type)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 6)
    : [];

  const topServices = auditStats
    ? Object.entries(auditStats.by_service)
        .sort(([, a], [, b]) => b - a)
        .slice(0, 5)
    : [];

  return (
    <div className="space-y-6">
      {/* Page header */}
      <div>
        <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100">Dashboard</h1>
        <p className="mt-0.5 text-sm text-slate-500 dark:text-slate-400">
          System overview and live metrics
        </p>
      </div>

      {/* Metric cards */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Metric
          label="System"
          value={health ? (health.status === 'ok' ? 'Healthy' : health.status === 'starting' ? 'Starting' : 'Degraded') : '...'}
          sub={health?.version !== 'unknown' ? `v${health?.version}` : undefined}
          accent={healthColor}
        />
        <Metric
          label="Vault"
          value={health ? vaultLabel : '...'}
          sub="OpenBao"
          accent={vaultColor}
        />
        <Metric
          label="Uptime"
          value={stats ? formatUptime(stats.uptime_seconds) : '...'}
        />
        <Metric
          label="Services"
          value={services.length}
          sub={services.length > 0 ? `${availableCount} active${degradedCount > 0 ? `, ${degradedCount} degraded` : ''}` : 'None configured'}
        />
      </div>

      {/* Second row — request metrics */}
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        <Metric
          label="API Calls"
          value={stats?.total_api_calls ?? 0}
          sub="Proxied requests"
        />
        <Metric
          label="Exec Calls"
          value={stats?.total_exec_calls ?? 0}
          sub="Command executions"
        />
        <Metric
          label="Audit Events"
          value={auditStats?.total ?? 0}
          sub="Total logged"
        />
        <Metric
          label="Credential Access"
          value={auditStats?.by_type?.credential_accessed ?? 0}
          sub="Vault reads"
        />
      </div>

      {/* Main content: two columns */}
      <div className="grid gap-6 lg:grid-cols-3">
        {/* Left column: Service status + audit breakdown */}
        <div className="space-y-6 lg:col-span-1">
          {/* Service status */}
          <div className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-700 dark:bg-slate-800">
            <div className="mb-4 flex items-center justify-between">
              <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">Service Status</h2>
              <a
                href="/services"
                className="text-xs font-medium text-indigo-600 hover:text-indigo-700 dark:text-indigo-400 dark:hover:text-indigo-300"
              >
                Manage &rarr;
              </a>
            </div>
            {services.length === 0 ? (
              <p className="text-sm text-slate-400 dark:text-slate-500">
                No services configured.{' '}
                <a href="/services" className="text-indigo-600 hover:underline dark:text-indigo-400">Add one</a>
              </p>
            ) : (
              <ul className="space-y-2.5">
                {services.map((s) => (
                  <li key={s.name}>
                    <a
                      href={`/services/${s.name}`}
                      className="flex items-center gap-3 rounded-lg px-2 py-1.5 transition-colors hover:bg-slate-50 dark:hover:bg-slate-700/50"
                    >
                      <ServiceIcon name={s.name} size={28} />
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm font-medium text-slate-800 dark:text-slate-200">{s.name}</p>
                        <p className="truncate text-xs text-slate-400 dark:text-slate-500">{s.type}</p>
                      </div>
                      <StatusIndicator status={s.status === 'available' ? 'ok' : 'degraded'} />
                    </a>
                  </li>
                ))}
              </ul>
            )}
          </div>

          {/* Audit breakdown */}
          {topEventTypes.length > 0 && (
            <div className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-700 dark:bg-slate-800">
              <h2 className="mb-4 text-sm font-semibold text-slate-900 dark:text-slate-100">Audit Breakdown</h2>
              <ul className="space-y-2">
                {topEventTypes.map(([type, count]) => {
                  const pct = auditStats!.total > 0 ? (count / auditStats!.total) * 100 : 0;
                  return (
                    <li key={type}>
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-slate-600 dark:text-slate-400">{eventTypeLabel(type)}</span>
                        <span className="font-medium tabular-nums text-slate-900 dark:text-slate-100">{count}</span>
                      </div>
                      <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-slate-100 dark:bg-slate-700">
                        <div
                          className="h-full rounded-full bg-indigo-500 transition-all duration-500"
                          style={{ width: `${Math.max(pct, 2)}%` }}
                        />
                      </div>
                    </li>
                  );
                })}
              </ul>
            </div>
          )}

          {/* Top services by usage */}
          {topServices.length > 0 && (
            <div className="rounded-xl border border-slate-200 bg-white p-5 dark:border-slate-700 dark:bg-slate-800">
              <h2 className="mb-4 text-sm font-semibold text-slate-900 dark:text-slate-100">Top Services</h2>
              <ul className="space-y-2.5">
                {topServices.map(([name, count]) => (
                  <li key={name} className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <ServiceIcon name={name} size={22} />
                      <span className="text-sm text-slate-700 dark:text-slate-300">{name}</span>
                    </div>
                    <span className="text-xs font-medium tabular-nums text-slate-500 dark:text-slate-400">
                      {count} event{count !== 1 ? 's' : ''}
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>

        {/* Right column: Activity feed */}
        <div className="lg:col-span-2">
          <div className="rounded-xl border border-slate-200 bg-white dark:border-slate-700 dark:bg-slate-800">
            <div className="flex items-center justify-between border-b border-slate-200 px-5 py-4 dark:border-slate-700">
              <h2 className="text-sm font-semibold text-slate-900 dark:text-slate-100">Recent Activity</h2>
              <span className="text-xs text-slate-400 dark:text-slate-500">
                Last {auditEvents.length} events
              </span>
            </div>
            {auditEvents.length === 0 && stats?.recent_activity?.length === 0 ? (
              <div className="px-5 py-10 text-center">
                <p className="text-sm text-slate-400 dark:text-slate-500">No activity recorded yet.</p>
                <p className="mt-1 text-xs text-slate-400 dark:text-slate-500">
                  Activity will appear here as Claude uses your services.
                </p>
              </div>
            ) : auditEvents.length > 0 ? (
              <ul className="divide-y divide-slate-100 dark:divide-slate-700/50">
                {auditEvents.map((evt) => (
                  <li key={evt.id} className="flex gap-3 px-5 py-3">
                    <div className="mt-0.5 flex-shrink-0">
                      <span
                        className={`inline-flex h-6 w-6 items-center justify-center rounded-full text-[10px] font-bold ${eventTypeColor(evt.type)}`}
                      >
                        {evt.type.charAt(0).toUpperCase()}
                      </span>
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className={`inline-block rounded px-1.5 py-0.5 text-[10px] font-medium ${eventTypeColor(evt.type)}`}>
                          {eventTypeLabel(evt.type)}
                        </span>
                        {evt.service && (
                          <span className="text-xs font-medium text-slate-700 dark:text-slate-300">{evt.service}</span>
                        )}
                      </div>
                      {evt.tool && (
                        <p className="mt-0.5 truncate text-xs text-slate-400 dark:text-slate-500">
                          Tool: {evt.tool}
                          {evt.details?.method && evt.details?.path && (
                            <span className="ml-1 font-mono">{evt.details.method} {evt.details.path}</span>
                          )}
                        </p>
                      )}
                    </div>
                    <span className="flex-shrink-0 text-xs text-slate-400 dark:text-slate-500">
                      {formatTimeAgo(evt.timestamp)}
                    </span>
                  </li>
                ))}
              </ul>
            ) : (
              /* Fall back to stats recent_activity if no audit events */
              <ul className="divide-y divide-slate-100 dark:divide-slate-700/50">
                {stats?.recent_activity?.slice().reverse().map((entry, i) => (
                  <li key={i} className="flex items-center gap-3 px-5 py-3">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-medium text-slate-700 dark:text-slate-300">{entry.service}</span>
                        <span className="text-xs text-slate-400 dark:text-slate-500">{entry.tool}</span>
                      </div>
                      {entry.method && entry.path && (
                        <p className="mt-0.5 truncate text-xs font-mono text-slate-400 dark:text-slate-500">
                          {entry.method} {entry.path}
                        </p>
                      )}
                    </div>
                    <span
                      className={`inline-block rounded px-1.5 py-0.5 text-[10px] font-medium tabular-nums ${
                        entry.status >= 200 && entry.status < 300
                          ? 'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/30 dark:text-emerald-300'
                          : entry.status >= 400
                            ? 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300'
                            : 'bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300'
                      }`}
                    >
                      {entry.status}
                    </span>
                    <span className="flex-shrink-0 text-xs text-slate-400 dark:text-slate-500">
                      {formatTimeAgo(entry.timestamp)}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
