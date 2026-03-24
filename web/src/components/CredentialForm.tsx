import { useState } from 'react';
import type { CredentialField } from '../types/service';

interface CredentialFormProps {
  fields: CredentialField[];
  values: Record<string, string>;
  onChange: (key: string, value: string) => void;
  errors: Record<string, string>;
}

interface PasswordFieldState {
  [key: string]: boolean;
}

/**
 * Dynamically renders form fields from CredentialField definitions.
 * Supports text, password (with show/hide toggle), and textarea inputs.
 */
export function CredentialForm({ fields, values, onChange, errors }: CredentialFormProps) {
  const [revealed, setRevealed] = useState<PasswordFieldState>({});

  function toggleReveal(key: string) {
    setRevealed((prev) => ({ ...prev, [key]: !prev[key] }));
  }

  return (
    <div className="space-y-4">
      {fields.map((field) => {
        const fieldId = `cred-field-${field.key}`;
        const helpId = field.help_text ? `${fieldId}-help` : undefined;
        const errorId = errors[field.key] ? `${fieldId}-error` : undefined;
        const isRevealed = revealed[field.key] ?? false;

        const inputType =
          field.type === 'password'
            ? isRevealed
              ? 'text'
              : 'password'
            : field.type;

        const baseInputClass =
          'w-full rounded-md border px-3 py-2 text-sm transition-colors focus:outline-none focus:ring-2 ' +
          'bg-white text-slate-900 placeholder-slate-400 border-slate-300 ' +
          'focus:border-indigo-500 focus:ring-indigo-500/20 ' +
          'dark:bg-slate-800 dark:text-slate-100 dark:placeholder-slate-500 dark:border-slate-600 ' +
          'dark:focus:border-indigo-400 dark:focus:ring-indigo-400/20 ' +
          (errors[field.key] ? 'border-red-500 dark:border-red-500' : '');

        return (
          <div key={field.key}>
            <label
              htmlFor={fieldId}
              className="mb-1.5 block text-sm font-medium text-slate-700 dark:text-slate-300"
            >
              {field.label}
              {field.required && (
                <span className="ml-1 text-red-500" aria-hidden="true">
                  *
                </span>
              )}
            </label>

            <div className="relative">
              {field.type === 'textarea' ? (
                <textarea
                  id={fieldId}
                  value={values[field.key] ?? ''}
                  onChange={(e) => onChange(field.key, e.target.value)}
                  placeholder={field.placeholder}
                  rows={4}
                  aria-describedby={[helpId, errorId].filter(Boolean).join(' ') || undefined}
                  aria-invalid={errors[field.key] ? 'true' : undefined}
                  autoComplete="off"
                  className={`${baseInputClass} font-mono resize-y`}
                />
              ) : (
                <input
                  id={fieldId}
                  type={inputType}
                  value={values[field.key] ?? ''}
                  onChange={(e) => onChange(field.key, e.target.value)}
                  placeholder={field.placeholder}
                  autoComplete={field.type === 'password' ? 'new-password' : 'off'}
                  aria-describedby={[helpId, errorId].filter(Boolean).join(' ') || undefined}
                  aria-invalid={errors[field.key] ? 'true' : undefined}
                  className={`${baseInputClass} ${field.type === 'password' ? 'pr-10' : ''}`}
                />
              )}

              {field.type === 'password' && (
                <button
                  type="button"
                  onClick={() => toggleReveal(field.key)}
                  aria-label={isRevealed ? 'Hide' : 'Show'}
                  className="absolute right-2.5 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300"
                >
                  {isRevealed ? (
                    <svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
                      <line x1="1" y1="1" x2="23" y2="23" />
                    </svg>
                  ) : (
                    <svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                      <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                      <circle cx="12" cy="12" r="3" />
                    </svg>
                  )}
                </button>
              )}
            </div>

            {field.help_text && (
              <p
                id={helpId}
                className="mt-1.5 text-xs text-slate-500 dark:text-slate-400"
              >
                {field.help_text}
              </p>
            )}

            {errors[field.key] && (
              <p
                id={errorId}
                role="alert"
                className="mt-1 text-xs font-medium text-red-600 dark:text-red-400"
              >
                {errors[field.key]}
              </p>
            )}
          </div>
        );
      })}
    </div>
  );
}
