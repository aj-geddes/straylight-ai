import type { Service, ServiceStatus } from '../types/service';
import { ServiceIcon } from './ServiceIcon';

const STATUS_COLORS: Record<ServiceStatus, string> = {
  available: 'bg-emerald-500',
  expired: 'bg-amber-400',
  not_configured: 'bg-slate-400',
};

const STATUS_LABELS: Record<ServiceStatus, string> = {
  available: 'Connected',
  expired: 'Expired',
  not_configured: 'Not Configured',
};

const STATUS_BADGE_STYLES: Record<ServiceStatus, string> = {
  available: 'bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-900/20 dark:text-emerald-400 dark:border-emerald-800',
  expired: 'bg-amber-50 text-amber-700 border-amber-200 dark:bg-amber-900/20 dark:text-amber-400 dark:border-amber-800',
  not_configured: 'bg-slate-100 text-slate-600 border-slate-200 dark:bg-slate-700 dark:text-slate-400 dark:border-slate-600',
};

interface ServiceTileProps {
  service: Service;
  onClick: (service: Service) => void;
}

/**
 * Clean card displaying a service with icon, name, type badge, auth method,
 * and status badge. If account_info is present, shows avatar, identity, and
 * key stats. Clicking invokes the onClick callback.
 */
export function ServiceTile({ service, onClick }: ServiceTileProps) {
  const statusColor = STATUS_COLORS[service.status];
  const statusLabel = STATUS_LABELS[service.status];
  const statusBadge = STATUS_BADGE_STYLES[service.status];
  const accountInfo = service.account_info;

  return (
    <button
      type="button"
      onClick={() => onClick(service)}
      className="group flex w-full flex-col items-start gap-3 rounded-xl border border-slate-200 bg-white p-4 text-left shadow-sm transition-all hover:border-slate-300 hover:shadow-md focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 dark:border-slate-700 dark:bg-slate-800 dark:hover:border-slate-600"
    >
      <div className="flex w-full items-center gap-3">
        <ServiceIcon name={service.name} size={36} />

        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-semibold text-slate-900 dark:text-slate-100">
            {service.name}
          </p>
          <p className="truncate text-xs text-slate-500 dark:text-slate-400">
            {service.type}
          </p>
        </div>

        <div className="flex flex-col items-end gap-1">
          <span
            title={service.status}
            aria-label={service.status}
            className={`h-2.5 w-2.5 flex-shrink-0 rounded-full ${statusColor}`}
          />
        </div>
      </div>

      {service.auth_method_name && (
        <p className="text-xs text-slate-500 dark:text-slate-400">
          {service.auth_method_name}
        </p>
      )}

      {accountInfo && (
        <div className="flex w-full items-center gap-2">
          {accountInfo.avatar_url && (
            <img
              src={accountInfo.avatar_url}
              alt={`${accountInfo.username ?? accountInfo.display_name ?? service.name} avatar`}
              className="h-7 w-7 flex-shrink-0 rounded-full object-cover"
            />
          )}
          <div className="min-w-0 flex-1">
            <p className="truncate text-xs text-slate-700 dark:text-slate-300">
              {accountInfo.username && accountInfo.display_name
                ? `${accountInfo.username} (${accountInfo.display_name})`
                : accountInfo.username ?? accountInfo.display_name}
            </p>
            {(accountInfo.extra || accountInfo.plan) && (
              <div className="mt-0.5 flex flex-wrap gap-1">
                {accountInfo.plan && (
                  <span className="rounded bg-indigo-50 px-1 py-0.5 text-xs text-indigo-600 dark:bg-indigo-900/20 dark:text-indigo-400">
                    {accountInfo.plan}
                  </span>
                )}
                {accountInfo.extra &&
                  Object.entries(accountInfo.extra).map(([key, value]) => (
                    <span
                      key={key}
                      className="rounded bg-slate-100 px-1 py-0.5 text-xs text-slate-500 dark:bg-slate-700 dark:text-slate-400"
                    >
                      {value} {key.replace(/_/g, ' ')}
                    </span>
                  ))}
              </div>
            )}
          </div>
        </div>
      )}

      <div className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-medium ${statusBadge}`}>
        {statusLabel}
      </div>
    </button>
  );
}
