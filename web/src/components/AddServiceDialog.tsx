import { useState } from 'react';
import type { ServiceTemplate, AuthMethod, AddServiceRequest } from '../types/service';
import { AuthMethodPicker } from './AuthMethodPicker';
import { CredentialForm } from './CredentialForm';
import { OAuthSetupStep } from './OAuthSetupStep';
import { DeviceFlowStep } from './DeviceFlowStep';
import { WebOAuthStep } from './WebOAuthStep';
import { ServiceIcon } from './ServiceIcon';

/**
 * Providers that support the Device Authorization Flow (RFC 8628).
 * For these providers, the DeviceFlowStep is shown instead of OAuthSetupStep,
 * eliminating the need for the user to register their own OAuth App.
 */
const DEVICE_FLOW_PROVIDERS = new Set(['github', 'google', 'microsoft']);

/**
 * Providers that support the standard web redirect OAuth flow (authorization code).
 * For these providers, WebOAuthStep is shown, which:
 * - If credentials are configured: shows a simple "Sign in with {Provider}" button.
 * - If not configured: falls back to DeviceFlowStep (if supported) or OAuthSetupStep.
 *
 * Web OAuth takes priority over device flow for Google since it provides a
 * simpler browser-based UX when server credentials are available.
 */
const WEB_OAUTH_PROVIDERS = new Set(['google', 'facebook']);

type Step = 'select-service' | 'select-auth' | 'enter-credentials' | 'oauth-setup' | 'device-flow' | 'web-oauth';

interface AddServiceDialogProps {
  templates: ServiceTemplate[];
  onSave: (data: AddServiceRequest) => Promise<void>;
  onClose: () => void;
}

const STEP_LABELS: Record<Step, string> = {
  'select-service': 'Select Service',
  'select-auth': 'Auth Method',
  'enter-credentials': 'Credentials',
  'oauth-setup': 'OAuth Setup',
  'device-flow': 'Connect',
  'web-oauth': 'Connect',
};

function StepIndicator({ current }: { current: Step }) {
  // Both oauth-setup and device-flow replace enter-credentials in the credential
  // step, so map them both to position 3 in the indicator.
  const steps: Step[] = ['select-service', 'select-auth', 'enter-credentials'];
  const displayStep: Step =
    current === 'oauth-setup' || current === 'device-flow' || current === 'web-oauth'
      ? 'enter-credentials'
      : current;
  const currentIndex = steps.indexOf(displayStep);

  return (
    <div className="flex items-center gap-1.5" aria-label="Progress">
      {steps.map((step, index) => (
        <div key={step} className="flex items-center gap-1.5">
          <div
            className={[
              'flex h-6 w-6 items-center justify-center rounded-full text-xs font-medium',
              index < currentIndex
                ? 'bg-indigo-600 text-white dark:bg-indigo-500'
                : index === currentIndex
                  ? 'bg-indigo-100 text-indigo-700 ring-2 ring-indigo-600 dark:bg-indigo-900/40 dark:text-indigo-300 dark:ring-indigo-400'
                  : 'bg-slate-100 text-slate-400 dark:bg-slate-700 dark:text-slate-500',
            ].join(' ')}
          >
            {index < currentIndex ? (
              <svg aria-hidden="true" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="20 6 9 17 4 12" />
              </svg>
            ) : (
              index + 1
            )}
          </div>
          <span className={`text-xs ${index <= currentIndex ? 'text-slate-700 dark:text-slate-300' : 'text-slate-400 dark:text-slate-500'}`}>
            {STEP_LABELS[step]}
          </span>
          {index < steps.length - 1 && (
            <div className={`h-px w-6 ${index < currentIndex ? 'bg-indigo-600 dark:bg-indigo-400' : 'bg-slate-200 dark:bg-slate-600'}`} />
          )}
        </div>
      ))}
    </div>
  );
}

/**
 * Multi-step wizard dialog for adding a new service.
 * Steps: 1) Select template, 2) Select auth method (skipped if only one),
 * 3) Enter credentials.
 */
export function AddServiceDialog({ templates, onSave, onClose }: AddServiceDialogProps) {
  const [step, setStep] = useState<Step>('select-service');
  const [selectedTemplate, setSelectedTemplate] = useState<ServiceTemplate | null>(null);
  const [selectedAuthId, setSelectedAuthId] = useState<string | null>(null);
  const [credentials, setCredentials] = useState<Record<string, string>>({});
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [serviceName, setServiceName] = useState('');
  const [targetUrl, setTargetUrl] = useState('');

  function handleTemplateSelect(template: ServiceTemplate) {
    setSelectedTemplate(template);
    setCredentials({});
    setFieldErrors({});
    setSaveError(null);
    setServiceName('');
    setTargetUrl('');

    if (template.auth_methods.length === 1) {
      // Only one auth method: skip step 2
      const onlyMethod = template.auth_methods[0];
      setSelectedAuthId(onlyMethod.id);
      if (isOAuthMethod(onlyMethod)) {
        // Web OAuth providers get the redirect-based flow (checks config internally).
        // Device flow providers get device flow. Others get manual setup.
        if (WEB_OAUTH_PROVIDERS.has(template.id)) {
          setStep('web-oauth');
        } else if (DEVICE_FLOW_PROVIDERS.has(template.id)) {
          setStep('device-flow');
        } else {
          setStep('oauth-setup');
        }
        return;
      }
      setStep('enter-credentials');
    } else {
      // Multiple auth methods: pre-select first and show step 2
      setSelectedAuthId(template.auth_methods[0]?.id ?? null);
      setStep('select-auth');
    }
  }

  function isOAuthMethod(method: AuthMethod | undefined): boolean {
    if (!method) return false;
    const t = method.injection?.type;
    return t === 'oauth' || (t === 'named_strategy' && method.injection?.strategy === 'oauth');
  }

  function handleAuthNext() {
    setFieldErrors({});
    const method = selectedTemplate?.auth_methods.find((m) => m.id === selectedAuthId);
    if (isOAuthMethod(method)) {
      // Web OAuth providers get the redirect-based flow (checks config internally).
      // Device flow providers get device flow. Others get manual setup.
      if (selectedTemplate && WEB_OAUTH_PROVIDERS.has(selectedTemplate.id)) {
        setStep('web-oauth');
      } else if (selectedTemplate && DEVICE_FLOW_PROVIDERS.has(selectedTemplate.id)) {
        setStep('device-flow');
      } else {
        setStep('oauth-setup');
      }
      return;
    }
    setStep('enter-credentials');
  }

  function handleStartOAuth() {
    const provider = selectedTemplate?.id ?? 'unknown';
    const serviceName = selectedTemplate?.id ?? 'unknown';
    window.location.href = `/api/v1/oauth/${provider}/start?service_name=${serviceName}`;
  }

  function handleFieldChange(key: string, value: string) {
    setCredentials((prev) => ({ ...prev, [key]: value }));
    if (fieldErrors[key]) {
      setFieldErrors((prev) => {
        const next = { ...prev };
        delete next[key];
        return next;
      });
    }
  }

  function validateCredentials(method: AuthMethod): Record<string, string> {
    const errors: Record<string, string> = {};
    for (const field of method.fields) {
      if (field.required && !credentials[field.key]?.trim()) {
        errors[field.key] = `${field.label} is required`;
      } else if (field.pattern && credentials[field.key]) {
        try {
          const re = new RegExp(field.pattern);
          if (!re.test(credentials[field.key])) {
            errors[field.key] = `${field.label} format is invalid`;
          }
        } catch {
          // Invalid regex in schema — skip validation
        }
      }
    }
    return errors;
  }

  /** Pattern matching the backend validation for service names. */
  const SERVICE_NAME_PATTERN = /^[a-z][a-z0-9_-]{0,62}$/;

  function validateServiceName(): string | null {
    const isCustom = selectedTemplate?.id === 'custom';
    if (isCustom && !serviceName.trim()) {
      return 'Service Name is required for custom services';
    }
    if (serviceName.trim() && !SERVICE_NAME_PATTERN.test(serviceName.trim())) {
      return 'Service Name format is invalid (lowercase letters, numbers, hyphens only)';
    }
    return null;
  }

  async function handleSave() {
    if (!selectedTemplate || !selectedAuthId) return;

    const method = selectedTemplate.auth_methods.find((m) => m.id === selectedAuthId);
    if (!method) return;

    const nameError = validateServiceName();
    if (nameError) {
      setFieldErrors((prev) => ({ ...prev, _service_name: nameError }));
      return;
    }

    // Custom services require a target URL.
    const isCustom = selectedTemplate.id === 'custom';
    if (isCustom && !selectedTemplate.target) {
      const url = targetUrl.trim();
      if (!url) {
        setFieldErrors((prev) => ({ ...prev, _target_url: 'Target URL is required' }));
        return;
      }
      try {
        const parsed = new URL(url);
        if (parsed.protocol !== 'https:') {
          setFieldErrors((prev) => ({ ...prev, _target_url: 'Target URL must use https://' }));
          return;
        }
      } catch {
        setFieldErrors((prev) => ({ ...prev, _target_url: 'Target URL must be a valid URL with https://' }));
        return;
      }
    }

    const errors = validateCredentials(method);
    if (Object.keys(errors).length > 0) {
      setFieldErrors(errors);
      return;
    }

    setSaving(true);
    setSaveError(null);

    try {
      await onSave({
        template: selectedTemplate.id,
        auth_method: selectedAuthId,
        credentials: { ...credentials },
        name: serviceName.trim() || selectedTemplate.id,
        target: targetUrl.trim() || undefined,
      });
      // Clear sensitive data
      setCredentials({});
      onClose();
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'An unexpected error occurred');
    } finally {
      setSaving(false);
    }
  }

  const currentAuthMethod = selectedTemplate?.auth_methods.find(
    (m) => m.id === selectedAuthId
  );

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-label="Add Service"
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/40 p-4 backdrop-blur-sm"
    >
      <div className="w-full max-w-lg rounded-xl border border-slate-200 bg-white shadow-2xl dark:border-slate-700 dark:bg-slate-900">
        {/* Header */}
        <div className="flex items-start justify-between border-b border-slate-200 px-6 py-4 dark:border-slate-700">
          <div>
            <h2 className="text-base font-semibold text-slate-900 dark:text-slate-100">
              Add Service
            </h2>
            <div className="mt-2">
              <StepIndicator current={step} />
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close"
            className="rounded-md p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-600 dark:hover:bg-slate-700 dark:hover:text-slate-300"
          >
            <svg aria-hidden="true" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <line x1="18" y1="6" x2="6" y2="18" />
              <line x1="6" y1="6" x2="18" y2="18" />
            </svg>
          </button>
        </div>

        {/* Body */}
        <div className="px-6 py-5">
          {step === 'select-service' && (
            <div>
              <p className="mb-4 text-sm text-slate-500 dark:text-slate-400">
                Choose a service to connect.
              </p>
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-3">
                {templates.map((template) => (
                  <button
                    key={template.id}
                    type="button"
                    onClick={() => handleTemplateSelect(template)}
                    className="flex flex-col items-center gap-2 rounded-lg border border-slate-200 bg-white p-3 text-center transition-all hover:border-indigo-300 hover:shadow-md focus:outline-none focus:ring-2 focus:ring-indigo-500 dark:border-slate-600 dark:bg-slate-800 dark:hover:border-indigo-500"
                  >
                    <ServiceIcon name={template.id} size={32} />
                    <span className="text-sm font-medium text-slate-800 dark:text-slate-200">
                      {template.display_name}
                    </span>
                    {template.description && (
                      <span className="text-xs text-slate-500 dark:text-slate-400 line-clamp-2">
                        {template.description}
                      </span>
                    )}
                  </button>
                ))}
                {templates.length === 0 && (
                  <p className="col-span-3 text-center text-sm text-slate-400 dark:text-slate-500 py-4">
                    No templates available.
                  </p>
                )}
              </div>
            </div>
          )}

          {step === 'select-auth' && selectedTemplate && (
            <div>
              <div className="mb-4 flex items-center gap-2">
                <ServiceIcon name={selectedTemplate.id} size={20} />
                <span className="text-sm font-medium text-slate-700 dark:text-slate-300">
                  {selectedTemplate.display_name}
                </span>
              </div>
              <p className="mb-3 text-sm text-slate-500 dark:text-slate-400">
                How would you like to authenticate?
              </p>
              <AuthMethodPicker
                methods={selectedTemplate.auth_methods}
                selectedId={selectedAuthId}
                onSelect={setSelectedAuthId}
              />
            </div>
          )}

          {step === 'enter-credentials' && selectedTemplate && currentAuthMethod && (
            <div>
              <div className="mb-4 flex items-center gap-2">
                <ServiceIcon name={selectedTemplate.id} size={20} />
                <span className="text-sm font-medium text-slate-700 dark:text-slate-300">
                  {selectedTemplate.display_name}
                </span>
                <span className="text-slate-400 dark:text-slate-500">/</span>
                <span className="text-sm text-slate-500 dark:text-slate-400">
                  {currentAuthMethod.name}
                </span>
              </div>
              {/* Service Name field — required for custom, optional for templates */}
              <div className="mb-4">
                <label
                  htmlFor="service-name-input"
                  className="mb-1 block text-sm font-medium text-slate-700 dark:text-slate-300"
                >
                  Service Name
                  {selectedTemplate.id !== 'custom' && (
                    <span className="ml-1 text-xs font-normal text-slate-400 dark:text-slate-500">
                      (optional)
                    </span>
                  )}
                </label>
                <input
                  id="service-name-input"
                  type="text"
                  value={serviceName}
                  onChange={(e) => {
                    setServiceName(e.target.value);
                    if (fieldErrors._service_name) {
                      setFieldErrors((prev) => {
                        const next = { ...prev };
                        delete next._service_name;
                        return next;
                      });
                    }
                  }}
                  placeholder={selectedTemplate.id === 'custom' ? 'my-api-service' : selectedTemplate.id}
                  className={[
                    'w-full rounded-md border px-3 py-2 text-sm text-slate-900 transition-colors',
                    'placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500',
                    'dark:bg-slate-800 dark:text-slate-100 dark:placeholder:text-slate-500',
                    fieldErrors._service_name
                      ? 'border-red-400 focus:ring-red-400 dark:border-red-500'
                      : 'border-slate-300 dark:border-slate-600',
                  ].join(' ')}
                />
                {fieldErrors._service_name && (
                  <p role="alert" className="mt-1 text-xs text-red-600 dark:text-red-400">
                    {fieldErrors._service_name}
                  </p>
                )}
                {!fieldErrors._service_name && (
                  <p className="mt-1 text-xs text-slate-400 dark:text-slate-500">
                    Lowercase letters, numbers, hyphens
                    {selectedTemplate.id !== 'custom' && '. Leave blank to use the default name.'}
                  </p>
                )}
              </div>
              {/* Target URL — shown for custom services that have no built-in target */}
              {selectedTemplate.id === 'custom' && !selectedTemplate.target && (
                <div className="mb-4">
                  <label
                    htmlFor="target-url-input"
                    className="mb-1 block text-sm font-medium text-slate-700 dark:text-slate-300"
                  >
                    Target URL
                    <span className="ml-1 text-red-500" aria-hidden="true">*</span>
                  </label>
                  <input
                    id="target-url-input"
                    type="url"
                    value={targetUrl}
                    onChange={(e) => {
                      setTargetUrl(e.target.value);
                      if (fieldErrors._target_url) {
                        setFieldErrors((prev) => {
                          const next = { ...prev };
                          delete next._target_url;
                          return next;
                        });
                      }
                    }}
                    placeholder="https://api.example.com"
                    className={[
                      'w-full rounded-md border px-3 py-2 text-sm text-slate-900 transition-colors',
                      'placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500',
                      'dark:bg-slate-800 dark:text-slate-100 dark:placeholder:text-slate-500',
                      fieldErrors._target_url
                        ? 'border-red-400 focus:ring-red-400 dark:border-red-500'
                        : 'border-slate-300 dark:border-slate-600',
                    ].join(' ')}
                  />
                  {fieldErrors._target_url && (
                    <p role="alert" className="mt-1 text-xs text-red-600 dark:text-red-400">
                      {fieldErrors._target_url}
                    </p>
                  )}
                  {!fieldErrors._target_url && (
                    <p className="mt-1 text-xs text-slate-400 dark:text-slate-500">
                      The base URL of the API (must use https://)
                    </p>
                  )}
                </div>
              )}
              <CredentialForm
                fields={currentAuthMethod.fields}
                values={credentials}
                onChange={handleFieldChange}
                errors={fieldErrors}
              />
              {/* Contextual help link — shown when the auth method has a key_url */}
              {currentAuthMethod.key_url && (
                <p className="mt-3 text-xs text-slate-500 dark:text-slate-400">
                  <a
                    href={currentAuthMethod.key_url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-indigo-600 hover:underline dark:text-indigo-400"
                  >
                    Where do I get this?
                  </a>
                </p>
              )}
              {saveError && (
                <p role="alert" className="mt-3 text-sm text-red-600 dark:text-red-400">
                  {saveError}
                </p>
              )}
            </div>
          )}

          {step === 'oauth-setup' && selectedTemplate && (
            <div>
              <div className="mb-4 flex items-center gap-2">
                <ServiceIcon name={selectedTemplate.id} size={20} />
                <span className="text-sm font-medium text-slate-700 dark:text-slate-300">
                  {selectedTemplate.display_name}
                </span>
              </div>
              <OAuthSetupStep
                provider={selectedTemplate.id}
                displayName={selectedTemplate.display_name}
                serviceName={selectedTemplate.id}
                onStartOAuth={handleStartOAuth}
              />
            </div>
          )}

          {step === 'device-flow' && selectedTemplate && (
            <div>
              <div className="mb-4 flex items-center gap-2">
                <ServiceIcon name={selectedTemplate.id} size={20} />
                <span className="text-sm font-medium text-slate-700 dark:text-slate-300">
                  {selectedTemplate.display_name}
                </span>
              </div>
              <DeviceFlowStep
                provider={selectedTemplate.id}
                displayName={selectedTemplate.display_name}
                serviceName={selectedTemplate.id}
                onSuccess={onClose}
              />
            </div>
          )}

          {step === 'web-oauth' && selectedTemplate && (
            <div>
              <div className="mb-4 flex items-center gap-2">
                <ServiceIcon name={selectedTemplate.id} size={20} />
                <span className="text-sm font-medium text-slate-700 dark:text-slate-300">
                  {selectedTemplate.display_name}
                </span>
              </div>
              <WebOAuthStep
                provider={selectedTemplate.id}
                displayName={selectedTemplate.display_name}
                serviceName={selectedTemplate.id}
                onSuccess={onClose}
              />
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="flex items-center justify-between border-t border-slate-200 px-6 py-4 dark:border-slate-700">
          <div>
            {(step === 'select-auth' || step === 'enter-credentials' || step === 'oauth-setup' || step === 'device-flow' || step === 'web-oauth') && (
              <button
                type="button"
                onClick={() => {
                  if (step === 'enter-credentials') {
                    if (selectedTemplate && selectedTemplate.auth_methods.length > 1) {
                      setStep('select-auth');
                    } else {
                      setStep('select-service');
                    }
                  } else if (step === 'oauth-setup' || step === 'device-flow' || step === 'web-oauth') {
                    if (selectedTemplate && selectedTemplate.auth_methods.length > 1) {
                      setStep('select-auth');
                    } else {
                      setStep('select-service');
                    }
                  } else {
                    setStep('select-service');
                  }
                  setFieldErrors({});
                  setSaveError(null);
                }}
                className="rounded-md border border-slate-300 px-4 py-2 text-sm font-medium text-slate-600 transition-colors hover:bg-slate-50 dark:border-slate-600 dark:text-slate-400 dark:hover:bg-slate-700"
              >
                Back
              </button>
            )}
          </div>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={onClose}
              className="rounded-md border border-slate-300 px-4 py-2 text-sm font-medium text-slate-600 transition-colors hover:bg-slate-50 dark:border-slate-600 dark:text-slate-400 dark:hover:bg-slate-700"
            >
              Cancel
            </button>
            {step === 'select-auth' && (
              <button
                type="button"
                onClick={handleAuthNext}
                disabled={!selectedAuthId}
                className="rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-700 disabled:opacity-50 dark:bg-indigo-500 dark:hover:bg-indigo-600"
              >
                {isOAuthMethod(currentAuthMethod)
                  ? `Connect with ${selectedTemplate?.display_name ?? 'Provider'}`
                  : 'Next'}
              </button>
            )}
            {step === 'enter-credentials' && (
              <button
                type="button"
                onClick={handleSave}
                disabled={saving}
                className="inline-flex items-center gap-2 rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-700 disabled:opacity-50 dark:bg-indigo-500 dark:hover:bg-indigo-600"
              >
                {saving && (
                  <span className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent" aria-hidden="true" />
                )}
                {saving ? 'Saving...' : 'Save'}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
