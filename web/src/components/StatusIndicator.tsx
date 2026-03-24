import type { HealthResponse } from '../types/health';

type Status = HealthResponse['status'];

const STATUS_COLORS: Record<Status, string> = {
  ok: 'bg-emerald-500',
  starting: 'bg-amber-400',
  degraded: 'bg-red-500',
};

interface StatusIndicatorProps {
  status: Status;
  label?: string;
}

/**
 * Small colored dot indicating system status.
 */
export function StatusIndicator({ status, label }: StatusIndicatorProps) {
  const colorClass = STATUS_COLORS[status];
  const title = label ?? status;

  return (
    <span
      role="img"
      aria-hidden="true"
      title={title}
      aria-label={title}
      className={`inline-block h-2.5 w-2.5 rounded-full ${colorClass}`}
    />
  );
}
