import { useState, useEffect, useRef } from 'react';
import { startDeviceFlow, pollDeviceFlow } from '../api/client';
import type { DeviceCodeResponse } from '../api/client';

/** Minimum polling interval in milliseconds — never go below what GitHub specifies. */
export const MIN_POLL_INTERVAL_MS = 5_000;

type FlowState =
  | { kind: 'idle' }
  | { kind: 'starting' }
  | { kind: 'error'; message: string }
  | { kind: 'polling'; deviceCode: DeviceCodeResponse }
  | { kind: 'expired' }
  | { kind: 'complete' };

interface DeviceFlowStepProps {
  /** The canonical provider name (e.g., "github"). */
  provider: string;
  /** The human-readable provider name (e.g., "GitHub"). */
  displayName: string;
  /** The service instance name to create after authorization. */
  serviceName: string;
  /** Called when authorization is complete and the token has been stored. */
  onSuccess: () => void;
  /**
   * Override the minimum poll interval in milliseconds.
   * Only used in tests to avoid real timer delays.
   * Production code always uses MIN_POLL_INTERVAL_MS as the floor.
   * @internal
   */
  _testPollIntervalMs?: number;
}

/**
 * DeviceFlowStep implements the GitHub Device Authorization Flow (RFC 8628).
 *
 * The user experience is:
 * 1. Click "Start Authorization"
 * 2. A prominent code appears: "Your code: XXXX-XXXX"
 * 3. A link opens github.com/login/device in a new tab
 * 4. The component polls the backend every interval seconds
 * 5. When the user authorizes: "Connected!" → calls onSuccess
 *
 * This replaces OAuthSetupStep for providers that support device flow,
 * eliminating the need for the user to register their own OAuth App.
 */
export function DeviceFlowStep({
  provider,
  displayName,
  serviceName,
  onSuccess,
  _testPollIntervalMs,
}: DeviceFlowStepProps) {
  const [state, setState] = useState<FlowState>({ kind: 'idle' });
  const pollTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Clean up polling timer on unmount.
  useEffect(() => {
    return () => {
      if (pollTimerRef.current !== null) {
        clearTimeout(pollTimerRef.current);
      }
    };
  }, []);

  async function handleStart() {
    setState({ kind: 'starting' });

    try {
      const dcr = await startDeviceFlow(provider, serviceName);
      setState({ kind: 'polling', deviceCode: dcr });
      schedulePoll(dcr, dcr.interval);
    } catch (err) {
      setState({
        kind: 'error',
        message: err instanceof Error ? err.message : 'Failed to start authorization',
      });
    }
  }

  function schedulePoll(dcr: DeviceCodeResponse, intervalSeconds: number) {
    const ms = _testPollIntervalMs !== undefined
      ? _testPollIntervalMs
      : Math.max(intervalSeconds * 1000, MIN_POLL_INTERVAL_MS);
    pollTimerRef.current = setTimeout(() => {
      void doPoll(dcr);
    }, ms);
  }

  async function doPoll(dcr: DeviceCodeResponse) {
    try {
      const result = await pollDeviceFlow(provider, dcr.device_code, serviceName);
      switch (result.status) {
        case 'complete':
          setState({ kind: 'complete' });
          onSuccess();
          break;
        case 'expired':
          setState({ kind: 'expired' });
          break;
        case 'pending':
        default:
          // Still waiting — schedule the next poll.
          schedulePoll(dcr, dcr.interval);
          break;
      }
    } catch {
      // Network error during poll — keep polling, don't surface to user.
      schedulePoll(dcr, dcr.interval);
    }
  }

  function handleReset() {
    if (pollTimerRef.current !== null) {
      clearTimeout(pollTimerRef.current);
      pollTimerRef.current = null;
    }
    setState({ kind: 'idle' });
  }

  return (
    <div className="space-y-4">
      <p className="text-sm font-semibold text-slate-900 dark:text-slate-100">
        Connect with {displayName}
      </p>

      {state.kind === 'idle' && (
        <>
          <ol className="space-y-1 text-sm text-slate-600 dark:text-slate-400 list-decimal list-inside">
            <li>Click &quot;Start Authorization&quot; below</li>
            <li>A code will appear — copy it</li>
            <li>Open the link that appears and enter your code</li>
            <li>Authorize Straylight-AI to access your {displayName} account</li>
          </ol>
          <button
            type="button"
            onClick={handleStart}
            className="w-full rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-700 dark:bg-indigo-500 dark:hover:bg-indigo-600"
          >
            Start Authorization
          </button>
        </>
      )}

      {state.kind === 'starting' && (
        <div className="flex items-center gap-2 py-4 text-sm text-slate-500 dark:text-slate-400">
          <span
            className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-slate-300 border-t-indigo-600 dark:border-slate-600 dark:border-t-indigo-400"
            aria-hidden="true"
          />
          Starting authorization…
        </div>
      )}

      {state.kind === 'error' && (
        <>
          <p role="alert" className="rounded-md border border-red-200 bg-red-50 p-3 text-sm text-red-700 dark:border-red-800 dark:bg-red-900/20 dark:text-red-300">
            {state.message}
          </p>
          <button
            type="button"
            onClick={handleStart}
            className="w-full rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-700 dark:bg-indigo-500 dark:hover:bg-indigo-600"
          >
            Start Authorization
          </button>
        </>
      )}

      {state.kind === 'polling' && (
        <div className="space-y-4">
          <div className="rounded-md border border-slate-200 bg-slate-50 p-4 text-center dark:border-slate-600 dark:bg-slate-800">
            <p className="mb-1 text-xs text-slate-500 dark:text-slate-400">Your code</p>
            <p className="font-mono text-3xl font-bold tracking-widest text-slate-900 dark:text-slate-100">
              {state.deviceCode.user_code}
            </p>
          </div>

          <p className="text-sm text-slate-600 dark:text-slate-400">
            Open{' '}
            <a
              href={state.deviceCode.verification_uri}
              target="_blank"
              rel="noopener noreferrer"
              className="font-medium text-indigo-600 hover:underline dark:text-indigo-400"
            >
              {state.deviceCode.verification_uri.replace('https://', '')}
            </a>{' '}
            in your browser and enter the code above.
          </p>

          <div className="flex items-center gap-2 text-sm text-slate-500 dark:text-slate-400">
            <span
              className="inline-block h-4 w-4 animate-spin rounded-full border-2 border-slate-300 border-t-indigo-600 dark:border-slate-600 dark:border-t-indigo-400"
              aria-hidden="true"
            />
            Waiting for authorization…
          </div>
        </div>
      )}

      {state.kind === 'expired' && (
        <div className="space-y-4">
          <div className="rounded-md border border-amber-200 bg-amber-50 p-3 dark:border-amber-800 dark:bg-amber-900/20">
            <p className="text-sm text-amber-800 dark:text-amber-200">
              The authorization code has expired. Click "Try Again" to get a new code.
            </p>
          </div>
          <button
            type="button"
            onClick={handleReset}
            className="w-full rounded-md bg-indigo-600 px-4 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-700 dark:bg-indigo-500 dark:hover:bg-indigo-600"
          >
            Try Again
          </button>
        </div>
      )}

      {state.kind === 'complete' && (
        <div className="rounded-md border border-green-200 bg-green-50 p-4 text-center dark:border-green-800 dark:bg-green-900/20">
          <p className="text-sm font-medium text-green-800 dark:text-green-200">
            Connected! Authorization complete.
          </p>
        </div>
      )}
    </div>
  );
}
