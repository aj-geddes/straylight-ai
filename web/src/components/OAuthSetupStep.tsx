import { useState, useEffect } from 'react';
import { getOAuthConfig, saveOAuthConfig } from '../api/client';

/** The OAuth App registration page URL for each supported provider. */
const PROVIDER_REGISTRATION_URLS: Record<string, { url: string; label: string }> = {
  github: {
    url: 'https://github.com/settings/developers',
    label: 'New OAuth App',
  },
  google: {
    url: 'https://console.cloud.google.com/apis/credentials',
    label: 'Create Credentials',
  },
  stripe: {
    url: 'https://dashboard.stripe.com/settings/connect',
    label: 'Connect Settings',
  },
};

/** The fixed callback URL that users must register with their OAuth App. */
const CALLBACK_URL = 'http://localhost:9470/api/v1/oauth/callback';

interface OAuthSetupStepProps {
  /** The canonical provider name (e.g., "github"). */
  provider: string;
  /** The human-readable provider name (e.g., "GitHub"). */
  displayName: string;
  /** The service instance name passed to the OAuth start URL. */
  serviceName: string;
  /** Called when the user is ready to start the OAuth flow (redirect to provider). */
  onStartOAuth: () => void;
}

/**
 * OAuth setup step shown in the AddServiceDialog when the user selects an
 * OAuth auth method.
 *
 * - If OAuth App credentials are already configured: shows a Connect button.
 * - If not configured: shows a form for entering client_id and client_secret,
 *   along with instructions on registering an OAuth App.
 */
export function OAuthSetupStep({
  provider,
  displayName,
  serviceName: _serviceName,
  onStartOAuth,
}: OAuthSetupStepProps) {
  const [loading, setLoading] = useState(true);
  const [configured, setConfigured] = useState(false);
  const [clientId, setClientId] = useState('');
  const [clientSecret, setClientSecret] = useState('');
  const [clientIdError, setClientIdError] = useState('');
  const [saveError, setSaveError] = useState('');
  const [saving, setSaving] = useState(false);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let cancelled = false;
    getOAuthConfig(provider)
      .then((config) => {
        if (!cancelled) {
          setConfigured(config.configured);
          if (config.client_id) {
            setClientId(config.client_id);
          }
          setLoading(false);
        }
      })
      .catch(() => {
        if (!cancelled) {
          setConfigured(false);
          setLoading(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [provider]);

  async function handleSaveAndConnect() {
    setClientIdError('');
    setSaveError('');

    if (!clientId.trim()) {
      setClientIdError('Client ID is required');
      return;
    }
    if (!clientSecret.trim()) {
      setSaveError('Client Secret is required');
      return;
    }

    setSaving(true);
    try {
      await saveOAuthConfig(provider, clientId.trim(), clientSecret.trim());
      onStartOAuth();
    } catch (err) {
      setSaveError(err instanceof Error ? err.message : 'Failed to save credentials');
    } finally {
      setSaving(false);
    }
  }

  async function handleCopyCallback() {
    try {
      await navigator.clipboard.writeText(CALLBACK_URL);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard not available — user can copy manually
    }
  }

  if (loading) {
    return (
      <div className="flex items-center gap-2 py-4 text-sm text-slate-500 dark:text-slate-400">
        <span
          className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-slate-300 border-t-indigo-600 dark:border-slate-600 dark:border-t-indigo-400"
          aria-hidden="true"
        />
        Checking OAuth configuration…
      </div>
    );
  }

  if (configured) {
    return (
      <div className="space-y-4">
        <p className="text-sm text-slate-600 dark:text-slate-400">
          OAuth App credentials are configured for{' '}
          <span className="font-medium text-slate-900 dark:text-slate-100">{displayName}</span>.
          Click below to authorize access.
        </p>
        <button
          type="button"
          onClick={onStartOAuth}
          className="w-full rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-700 dark:bg-indigo-500 dark:hover:bg-indigo-600"
        >
          Connect with {displayName}
        </button>
      </div>
    );
  }

  const registration = PROVIDER_REGISTRATION_URLS[provider];

  return (
    <div className="space-y-5">
      <div className="rounded-md border border-amber-200 bg-amber-50 p-3 dark:border-amber-800 dark:bg-amber-900/20">
        <p className="text-sm text-amber-800 dark:text-amber-200">
          To connect with {displayName} via OAuth, you need to register an OAuth App and enter the
          credentials below.
        </p>
      </div>

      {registration && (
        <div className="text-sm text-slate-600 dark:text-slate-400">
          <span className="font-medium text-slate-700 dark:text-slate-300">Step 1:</span>{' '}
          Register an OAuth App at{' '}
          <a
            href={registration.url}
            target="_blank"
            rel="noopener noreferrer"
            className="font-medium text-indigo-600 hover:underline dark:text-indigo-400"
          >
            {registration.label}
          </a>
        </div>
      )}

      <div className="text-sm text-slate-600 dark:text-slate-400">
        <span className="font-medium text-slate-700 dark:text-slate-300">Step 2:</span> Set the
        Callback / Redirect URI to:
        <div className="mt-1.5 flex items-center gap-2 rounded-md border border-slate-200 bg-slate-50 px-3 py-2 dark:border-slate-600 dark:bg-slate-800">
          <code className="flex-1 break-all font-mono text-xs text-slate-700 dark:text-slate-300">
            {CALLBACK_URL}
          </code>
          <button
            type="button"
            onClick={handleCopyCallback}
            aria-label="Copy callback URL"
            className="shrink-0 rounded p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-600 dark:hover:bg-slate-700 dark:hover:text-slate-300"
          >
            {copied ? (
              <svg
                aria-hidden="true"
                width="14"
                height="14"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2.5"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <polyline points="20 6 9 17 4 12" />
              </svg>
            ) : (
              <svg
                aria-hidden="true"
                width="14"
                height="14"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
              </svg>
            )}
          </button>
        </div>
      </div>

      <div className="space-y-3">
        <p className="text-sm font-medium text-slate-700 dark:text-slate-300">
          Step 3: Enter your OAuth App credentials
        </p>

        <div>
          <label
            htmlFor={`oauth-client-id-${provider}`}
            className="block text-sm font-medium text-slate-700 dark:text-slate-300"
          >
            Client ID
          </label>
          <input
            id={`oauth-client-id-${provider}`}
            type="text"
            value={clientId}
            onChange={(e) => {
              setClientId(e.target.value);
              if (clientIdError) setClientIdError('');
            }}
            placeholder="Enter Client ID"
            className={[
              'mt-1 block w-full rounded-md border px-3 py-2 text-sm shadow-sm',
              'focus:outline-none focus:ring-2 focus:ring-indigo-500',
              'dark:bg-slate-800 dark:text-slate-100',
              clientIdError
                ? 'border-red-300 dark:border-red-600'
                : 'border-slate-300 dark:border-slate-600',
            ].join(' ')}
          />
          {clientIdError && (
            <p className="mt-1 text-xs text-red-600 dark:text-red-400">{clientIdError}</p>
          )}
        </div>

        <div>
          <label
            htmlFor={`oauth-client-secret-${provider}`}
            className="block text-sm font-medium text-slate-700 dark:text-slate-300"
          >
            Client Secret
          </label>
          <input
            id={`oauth-client-secret-${provider}`}
            type="password"
            value={clientSecret}
            onChange={(e) => setClientSecret(e.target.value)}
            placeholder="Enter Client Secret"
            className={[
              'mt-1 block w-full rounded-md border px-3 py-2 text-sm shadow-sm',
              'focus:outline-none focus:ring-2 focus:ring-indigo-500',
              'dark:bg-slate-800 dark:text-slate-100',
              'border-slate-300 dark:border-slate-600',
            ].join(' ')}
          />
        </div>
      </div>

      {saveError && (
        <p role="alert" className="text-sm text-red-600 dark:text-red-400">
          {saveError}
        </p>
      )}

      <button
        type="button"
        onClick={handleSaveAndConnect}
        disabled={saving}
        className="inline-flex w-full items-center justify-center gap-2 rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-700 disabled:opacity-50 dark:bg-indigo-500 dark:hover:bg-indigo-600"
      >
        {saving && (
          <span
            className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent"
            aria-hidden="true"
          />
        )}
        {saving ? 'Saving...' : 'Save & Connect'}
      </button>
    </div>
  );
}
