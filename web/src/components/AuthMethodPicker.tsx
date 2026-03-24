import type { AuthMethod } from '../types/service';

interface AuthMethodPickerProps {
  methods: AuthMethod[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}

/**
 * Radio button group for selecting an auth method.
 * Shows name and description for each option.
 * The first method is highlighted as recommended.
 */
export function AuthMethodPicker({ methods, selectedId, onSelect }: AuthMethodPickerProps) {
  return (
    <fieldset className="space-y-2">
      <legend className="sr-only">Authentication method</legend>
      {methods.map((method, index) => {
        const isSelected = selectedId === method.id;
        const isRecommended = index === 0;

        return (
          <label
            key={method.id}
            className={[
              'flex cursor-pointer items-start gap-3 rounded-lg border p-3 transition-colors',
              isSelected
                ? 'border-indigo-500 bg-indigo-50 dark:border-indigo-400 dark:bg-indigo-900/20'
                : 'border-slate-200 bg-white hover:border-slate-300 hover:bg-slate-50 dark:border-slate-600 dark:bg-slate-800 dark:hover:border-slate-500',
            ].join(' ')}
          >
            <input
              type="radio"
              name="auth-method"
              value={method.id}
              checked={isSelected}
              onChange={() => onSelect(method.id)}
              className="mt-0.5 h-4 w-4 text-indigo-600 focus:ring-indigo-500 dark:focus:ring-indigo-400"
            />
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-slate-900 dark:text-slate-100">
                  {method.name}
                </span>
                {isRecommended && (
                  <span className="rounded-full bg-indigo-100 px-2 py-0.5 text-xs font-medium text-indigo-700 dark:bg-indigo-900/40 dark:text-indigo-300">
                    Recommended
                  </span>
                )}
              </div>
              {method.description && (
                <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">
                  {method.description}
                </p>
              )}
            </div>
          </label>
        );
      })}
    </fieldset>
  );
}
