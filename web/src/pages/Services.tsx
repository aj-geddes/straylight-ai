import { useEffect, useState, useCallback } from 'react';
import { ServiceTile } from '../components/ServiceTile';
import { AddServiceDialog } from '../components/AddServiceDialog';
import { getServices, addServiceFromTemplate, getTemplates } from '../api/client';
import type { Service, ServiceTemplate, AddServiceRequest } from '../types/service';

const REFRESH_INTERVAL_MS = 30_000;

/** Reads oauth=success and service= query params from the current URL. */
function getOAuthSuccessFromURL(): { success: boolean; serviceName: string } {
  const params = new URLSearchParams(window.location.search);
  return {
    success: params.get('oauth') === 'success',
    serviceName: params.get('service') ?? '',
  };
}

/**
 * Services page — manage configured services.
 * Add, view, and navigate to service configuration.
 */
export function Services() {
  const [services, setServices] = useState<Service[]>([]);
  const [templates, setTemplates] = useState<ServiceTemplate[]>([]);
  const [dialogOpen, setDialogOpen] = useState(false);
  const [oauthSuccess, setOauthSuccess] = useState<string | null>(null);

  const fetchServices = useCallback(async () => {
    try {
      const result = await getServices();
      setServices(result);
    } catch {
      // Keep existing list on error
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

  useEffect(() => {
    void fetchServices();
    void fetchTemplates();

    const { success, serviceName } = getOAuthSuccessFromURL();
    if (success) {
      setOauthSuccess(serviceName || 'service');
    }

    const id = setInterval(() => void fetchServices(), REFRESH_INTERVAL_MS);
    return () => clearInterval(id);
  }, [fetchServices, fetchTemplates]);

  async function handleSaveService(data: AddServiceRequest): Promise<void> {
    await addServiceFromTemplate(data);
    await fetchServices();
  }

  function handleServiceClick(service: Service) {
    window.location.href = `/services/${service.name}`;
  }

  return (
    <div className="space-y-6">
      {/* OAuth success banner */}
      {oauthSuccess !== null && (
        <div
          role="status"
          className="flex items-center justify-between rounded-lg border border-emerald-200 bg-emerald-50 px-4 py-3 dark:border-emerald-800 dark:bg-emerald-900/20"
        >
          <p className="text-sm font-medium text-emerald-800 dark:text-emerald-200">
            Successfully connected{' '}
            <span className="font-semibold">{oauthSuccess}</span> via OAuth.
          </p>
          <button
            type="button"
            onClick={() => setOauthSuccess(null)}
            aria-label="Dismiss"
            className="rounded p-1 text-emerald-600 hover:bg-emerald-100 dark:text-emerald-400 dark:hover:bg-emerald-900/40"
          >
            <svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>
      )}

      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-slate-900 dark:text-slate-100">Services</h1>
          <p className="mt-0.5 text-sm text-slate-500 dark:text-slate-400">
            {services.length > 0
              ? `${services.length} service${services.length === 1 ? '' : 's'} configured`
              : 'Connect your first service to get started'}
          </p>
        </div>
        <button
          type="button"
          onClick={() => setDialogOpen(true)}
          className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-4 py-2 text-sm font-medium text-white shadow-sm transition-colors hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:ring-offset-2 dark:bg-indigo-500 dark:hover:bg-indigo-600"
        >
          <svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
            <line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" />
          </svg>
          Add Service
        </button>
      </div>

      {/* Service grid */}
      {services.length === 0 ? (
        <div className="flex flex-col items-center justify-center rounded-xl border-2 border-dashed border-slate-200 bg-white py-16 text-center dark:border-slate-700 dark:bg-slate-800/50">
          <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-full bg-indigo-100 dark:bg-indigo-900/30">
            <svg
              aria-hidden="true" width="24" height="24" viewBox="0 0 24 24" fill="none"
              stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"
              className="text-indigo-600 dark:text-indigo-400"
            >
              <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
            </svg>
          </div>
          <p className="mb-1 text-sm font-medium text-slate-700 dark:text-slate-300">
            No services configured yet
          </p>
          <p className="mb-5 text-sm text-slate-500 dark:text-slate-400">
            Add a service to store and manage its credentials securely.
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
