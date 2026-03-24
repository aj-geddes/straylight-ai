import { useState, useEffect } from 'react';
import { getOAuthConfig } from '../api/client';
import { OAuthSetupStep } from './OAuthSetupStep';
import { DeviceFlowStep } from './DeviceFlowStep';

/**
 * Providers that support the Device Authorization Flow (RFC 8628).
 * When web OAuth is not configured for these providers, fall back to device flow
 * instead of the manual OAuthSetupStep.
 */
const DEVICE_FLOW_PROVIDERS = new Set(['github', 'google', 'microsoft']);

interface WebOAuthStepProps {
  /** The canonical provider name (e.g., "google"). */
  provider: string;
  /** The human-readable provider name (e.g., "Google"). */
  displayName: string;
  /** The service instance name passed to the OAuth start URL. */
  serviceName: string;
  /** Called when the flow completes (device flow path only). */
  onSuccess?: () => void;
}

type CheckState = 'checking' | 'configured' | 'unconfigured';

/**
 * WebOAuthStep renders the appropriate OAuth entry point depending on whether
 * server-side credentials are configured:
 *
 * - configured     → simple "Sign in with {Provider}" button (web redirect)
 * - unconfigured + device flow provider → DeviceFlowStep fallback
 * - unconfigured + no device flow → OAuthSetupStep fallback
 *
 * This lets users click once and get redirected to the provider's login page,
 * while still supporting the manual client_id/secret setup path for
 * operators who have not yet set env vars.
 */
export function WebOAuthStep({
  provider,
  displayName,
  serviceName,
  onSuccess,
}: WebOAuthStepProps) {
  const [state, setState] = useState<CheckState>('checking');

  useEffect(() => {
    let cancelled = false;
    getOAuthConfig(provider)
      .then((config) => {
        if (!cancelled) {
          setState(config.configured ? 'configured' : 'unconfigured');
        }
      })
      .catch(() => {
        if (!cancelled) {
          setState('unconfigured');
        }
      });
    return () => {
      cancelled = true;
    };
  }, [provider]);

  if (state === 'checking') {
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

  if (state === 'configured') {
    return (
      <div className="space-y-4 text-center py-4">
        <p className="text-sm text-slate-600 dark:text-slate-400">
          Click below to sign in with your {displayName} account. You&apos;ll be
          redirected to {displayName} to authorize access.
        </p>
        <button
          type="button"
          onClick={() => {
            window.location.href = `/api/v1/oauth/${provider}/start?service_name=${serviceName}`;
          }}
          className="w-full rounded-md bg-indigo-600 px-6 py-3 text-sm font-medium text-white transition-colors hover:bg-indigo-700 dark:bg-indigo-500 dark:hover:bg-indigo-600"
        >
          Sign in with {displayName}
        </button>
      </div>
    );
  }

  // unconfigured: fall back to device flow or manual setup
  if (DEVICE_FLOW_PROVIDERS.has(provider)) {
    return (
      <DeviceFlowStep
        provider={provider}
        displayName={displayName}
        serviceName={serviceName}
        onSuccess={onSuccess ?? (() => {})}
      />
    );
  }

  return (
    <OAuthSetupStep
      provider={provider}
      displayName={displayName}
      serviceName={serviceName}
      onStartOAuth={() => {
        window.location.href = `/api/v1/oauth/${provider}/start?service_name=${serviceName}`;
      }}
    />
  );
}
