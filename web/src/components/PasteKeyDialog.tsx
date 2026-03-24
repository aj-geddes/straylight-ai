import { useState } from 'react';
import type { ServiceTemplate, CreateServiceRequest, UpdateServiceRequest } from '../types/service';

type CreateMode = {
  mode: 'create';
  template?: ServiceTemplate;
  serviceName?: never;
  onSave: (data: CreateServiceRequest) => Promise<void>;
};

type UpdateMode = {
  mode: 'update';
  serviceName: string;
  template?: never;
  onSave: (data: UpdateServiceRequest) => Promise<void>;
};

type PasteKeyDialogProps = (CreateMode | UpdateMode) & {
  onClose: () => void;
};

/**
 * Modal dialog for adding a new service or updating an existing credential.
 * In create mode: shows full form pre-filled from template.
 * In update mode: shows only the credential field.
 */
export function PasteKeyDialog(props: PasteKeyDialogProps) {
  const { mode, onClose } = props;

  const templateName =
    mode === 'create'
      ? (props.template?.display_name ?? props.template?.name ?? '')
      : '';
  const initialName = templateName;
  const credentialLabel = 'API Key';

  const [name, setName] = useState(initialName);
  const [credential, setCredential] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [validationErrors, setValidationErrors] = useState<Record<string, string>>({});

  function validate(): boolean {
    const errors: Record<string, string> = {};
    if (mode === 'create' && !name.trim()) {
      errors.name = 'Name is required';
    }
    if (!credential.trim()) {
      errors.credential = 'Credential is required';
    }
    setValidationErrors(errors);
    return Object.keys(errors).length === 0;
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!validate()) return;

    setSaving(true);
    setError(null);

    try {
      if (mode === 'create') {
        const template = props.template;
        await (props.onSave as CreateMode['onSave'])({
          name: name.trim(),
          type: template?.type ?? 'http_proxy',
          target: template?.target ?? '',
          inject: template?.inject ?? 'header',
          credential: credential,
          header_template: template?.header_template,
        });
      } else {
        await (props.onSave as UpdateMode['onSave'])({
          credential: credential,
        });
      }
      setCredential('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unexpected error occurred');
    } finally {
      setSaving(false);
    }
  }

  const title =
    mode === 'create'
      ? templateName
        ? `Add ${templateName}`
        : 'Add Service'
      : 'Update Credential';

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label={title}
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4 backdrop-blur-sm"
    >
      <div className="w-full max-w-md rounded-xl border border-slate-200 bg-white p-6 shadow-2xl dark:border-slate-700 dark:bg-slate-900">
        <h2 className="mb-5 text-base font-semibold text-slate-900 dark:text-slate-100">{title}</h2>

        <form onSubmit={handleSubmit} noValidate>
          <div className="space-y-4">
            {mode === 'create' && (
              <div>
                <label
                  htmlFor="service-name"
                  className="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300"
                >
                  Service Name
                </label>
                <input
                  id="service-name"
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  autoComplete="off"
                  className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 placeholder-slate-400 transition-colors focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-100 dark:placeholder-slate-500 dark:focus:border-indigo-400"
                />
                {validationErrors.name && (
                  <p className="mt-1 text-xs text-red-600 dark:text-red-400">{validationErrors.name}</p>
                )}
              </div>
            )}

            <div>
              <label
                htmlFor="credential-input"
                className="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300"
              >
                {credentialLabel}
              </label>
              <input
                id="credential-input"
                type="password"
                value={credential}
                onChange={(e) => setCredential(e.target.value)}
                autoComplete="new-password"
                className="w-full rounded-md border border-slate-300 bg-white px-3 py-2 text-sm text-slate-900 placeholder-slate-400 transition-colors focus:border-indigo-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 dark:border-slate-600 dark:bg-slate-800 dark:text-slate-100 dark:placeholder-slate-500 dark:focus:border-indigo-400"
              />
              {validationErrors.credential && (
                <p className="mt-1 text-xs text-red-600 dark:text-red-400">{validationErrors.credential}</p>
              )}
            </div>
          </div>

          {error && (
            <p className="mt-3 text-sm text-red-600 dark:text-red-400" role="alert">
              {error}
            </p>
          )}

          <div className="mt-6 flex justify-end gap-3">
            <button
              type="button"
              onClick={onClose}
              disabled={saving}
              className="rounded-md border border-slate-300 px-4 py-2 text-sm font-medium text-slate-600 transition-colors hover:bg-slate-50 disabled:opacity-50 dark:border-slate-600 dark:text-slate-400 dark:hover:bg-slate-800"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving}
              className="inline-flex items-center gap-2 rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-700 disabled:opacity-50 dark:bg-indigo-500 dark:hover:bg-indigo-600"
            >
              {saving ? 'Saving...' : 'Save'}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
