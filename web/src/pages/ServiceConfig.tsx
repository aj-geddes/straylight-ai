import { useEffect, useState } from 'react';
import { getService, updateService, deleteService } from '../api/client';
import { PasteKeyDialog } from '../components/PasteKeyDialog';
import { DeleteConfirmDialog } from '../components/DeleteConfirmDialog';
import { ServiceIcon } from '../components/ServiceIcon';
import type { Service, UpdateServiceRequest } from '../types/service';

interface ServiceConfigProps {
  name: string;
  onBack: () => void;
}

type DialogState = 'none' | 'update_credential' | 'delete_confirm';

const STATUS_BADGE: Record<Service['status'], { label: string; className: string }> = {
  available: {
    label: 'Connected',
    className: 'bg-emerald-50 text-emerald-700 border border-emerald-200 dark:bg-emerald-900/20 dark:text-emerald-400 dark:border-emerald-800',
  },
  expired: {
    label: 'Expired',
    className: 'bg-amber-50 text-amber-700 border border-amber-200 dark:bg-amber-900/20 dark:text-amber-400 dark:border-amber-800',
  },
  not_configured: {
    label: 'Not Configured',
    className: 'bg-slate-100 text-slate-600 border border-slate-200 dark:bg-slate-700 dark:text-slate-400 dark:border-slate-600',
  },
};

/**
 * Service detail page.
 * Displays service configuration without credential values.
 * Provides actions: update credential, delete service.
 */
export function ServiceConfig({ name, onBack }: ServiceConfigProps) {
  const [service, setService] = useState<Service | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [dialog, setDialog] = useState<DialogState>('none');

  useEffect(() => {
    let cancelled = false;

    async function fetchService() {
      setLoading(true);
      setLoadError(null);
      try {
        const data = await getService(name);
        if (!cancelled) {
          setService(data);
        }
      } catch (err) {
        if (!cancelled) {
          setLoadError(err instanceof Error ? err.message : 'Failed to load service');
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    void fetchService();
    return () => { cancelled = true; };
  }, [name]);

  async function handleUpdateCredential(data: UpdateServiceRequest): Promise<void> {
    const updated = await updateService(name, data);
    setService(updated);
    setDialog('none');
  }

  async function handleDelete(): Promise<void> {
    await deleteService(name);
    onBack();
  }

  if (loading) {
    return (
      <div className="flex items-center gap-2 text-slate-500 dark:text-slate-400">
        <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-slate-300 border-t-indigo-600 dark:border-slate-600 dark:border-t-indigo-400" aria-hidden="true" />
        <span>Loading...</span>
      </div>
    );
  }

  if (loadError) {
    return (
      <div className="rounded-xl border border-red-200 bg-red-50 p-5 dark:border-red-800 dark:bg-red-900/20">
        <p className="text-sm text-red-700 dark:text-red-400">{loadError}</p>
        <button
          type="button"
          onClick={onBack}
          className="mt-3 text-sm text-slate-500 underline hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200"
        >
          Go back
        </button>
      </div>
    );
  }

  if (!service) return null;

  const statusBadge = STATUS_BADGE[service.status];

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      {/* Back button + heading */}
      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={onBack}
          aria-label="Back"
          className="flex items-center gap-1 rounded-md border border-slate-300 px-3 py-1.5 text-sm text-slate-600 transition-colors hover:bg-slate-50 dark:border-slate-600 dark:text-slate-400 dark:hover:bg-slate-800"
        >
          <svg aria-hidden="true" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="15 18 9 12 15 6" />
          </svg>
          Back
        </button>
        <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100">{service.name}</h1>
        <span className={`rounded-full px-2.5 py-1 text-xs font-medium ${statusBadge.className}`}>
          {statusBadge.label}
        </span>
      </div>

      {/* Service info card */}
      <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-700 dark:bg-slate-800">
        <div className="mb-4 flex items-center gap-3">
          <ServiceIcon name={service.name} size={40} />
          <div>
            <p className="font-semibold text-slate-900 dark:text-slate-100">{service.name}</p>
            {service.auth_method_name && (
              <p className="text-sm text-slate-500 dark:text-slate-400">{service.auth_method_name}</p>
            )}
          </div>
        </div>

        <dl className="grid grid-cols-2 gap-4 text-sm">
          <div>
            <dt className="font-medium text-slate-500 dark:text-slate-400">Type</dt>
            <dd className="mt-0.5 text-slate-900 dark:text-slate-100">{service.type}</dd>
          </div>
          <div>
            <dt className="font-medium text-slate-500 dark:text-slate-400">Status</dt>
            <dd className="mt-0.5 text-slate-900 dark:text-slate-100">{service.status}</dd>
          </div>
          <div className="col-span-2">
            <dt className="font-medium text-slate-500 dark:text-slate-400">Target URL</dt>
            <dd className="mt-0.5 break-all font-mono text-xs text-slate-700 dark:text-slate-300">
              {service.target}
            </dd>
          </div>
          <div>
            <dt className="font-medium text-slate-500 dark:text-slate-400">Injection Method</dt>
            <dd className="mt-0.5 text-slate-900 dark:text-slate-100">{service.inject}</dd>
          </div>
          {service.header_template && (
            <div>
              <dt className="font-medium text-slate-500 dark:text-slate-400">Header Template</dt>
              <dd className="mt-0.5 font-mono text-xs text-slate-700 dark:text-slate-300">
                {service.header_template}
              </dd>
            </div>
          )}
        </dl>
      </div>

      {/* Account info card — only shown when enrichment data is available */}
      {service.account_info && (
        <div className="rounded-xl border border-slate-200 bg-white p-5 shadow-sm dark:border-slate-700 dark:bg-slate-800">
          <h2 className="mb-4 text-sm font-semibold text-slate-900 dark:text-slate-100">Account</h2>

          <div className="mb-4 flex items-center gap-3">
            {service.account_info.avatar_url && (
              <img
                src={service.account_info.avatar_url}
                alt={`${service.account_info.username ?? service.account_info.display_name ?? service.name} avatar`}
                className="h-10 w-10 rounded-full object-cover"
              />
            )}
            <div>
              {service.account_info.display_name && (
                <p className="font-medium text-slate-900 dark:text-slate-100">
                  {service.account_info.display_name}
                </p>
              )}
              {service.account_info.username && (
                <p className="text-sm text-slate-500 dark:text-slate-400">
                  {service.account_info.username}
                </p>
              )}
              {service.account_info.url && (
                <a
                  href={service.account_info.url}
                  target="_blank"
                  rel="noopener noreferrer"
                  aria-label="View profile"
                  className="text-xs text-indigo-600 hover:underline dark:text-indigo-400"
                >
                  Profile
                </a>
              )}
            </div>
            {service.account_info.plan && (
              <span className="ml-auto rounded-full bg-indigo-50 px-2 py-0.5 text-xs font-medium text-indigo-700 dark:bg-indigo-900/20 dark:text-indigo-300">
                {service.account_info.plan}
              </span>
            )}
          </div>

          {service.account_info.extra && Object.keys(service.account_info.extra).length > 0 && (
            <dl className="grid grid-cols-2 gap-3 text-sm">
              {Object.entries(service.account_info.extra).map(([key, value]) => (
                <div key={key}>
                  <dt className="font-medium text-slate-500 dark:text-slate-400">{key}</dt>
                  <dd className="mt-0.5 text-slate-900 dark:text-slate-100">{value}</dd>
                </div>
              ))}
            </dl>
          )}
        </div>
      )}

      {/* Actions */}
      <div className="flex gap-3">
        <button
          type="button"
          onClick={() => setDialog('update_credential')}
          className="inline-flex items-center gap-2 rounded-lg border border-indigo-200 bg-indigo-50 px-4 py-2 text-sm font-medium text-indigo-700 transition-colors hover:bg-indigo-100 dark:border-indigo-800 dark:bg-indigo-900/20 dark:text-indigo-300 dark:hover:bg-indigo-900/30"
        >
          <svg aria-hidden="true" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
          </svg>
          Update Credential
        </button>
        <button
          type="button"
          onClick={() => setDialog('delete_confirm')}
          className="inline-flex items-center gap-2 rounded-lg border border-red-200 bg-red-50 px-4 py-2 text-sm font-medium text-red-700 transition-colors hover:bg-red-100 dark:border-red-800 dark:bg-red-900/20 dark:text-red-400 dark:hover:bg-red-900/30"
        >
          <svg aria-hidden="true" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <polyline points="3 6 5 6 21 6" />
            <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
          </svg>
          Delete
        </button>
      </div>

      {dialog === 'update_credential' && (
        <PasteKeyDialog
          mode="update"
          serviceName={name}
          onSave={handleUpdateCredential}
          onClose={() => setDialog('none')}
        />
      )}

      {dialog === 'delete_confirm' && (
        <DeleteConfirmDialog
          serviceName={name}
          onConfirm={handleDelete}
          onCancel={() => setDialog('none')}
        />
      )}
    </div>
  );
}
