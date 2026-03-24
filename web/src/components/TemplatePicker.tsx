import type { ServiceTemplate } from '../types/service';
import { ServiceIcon } from './ServiceIcon';

interface TemplatePickerProps {
  templates: ServiceTemplate[];
  onSelect: (template: ServiceTemplate) => void;
  onSelectCustom: () => void;
}

/**
 * Grid of service template tiles.
 * Clicking a tile calls onSelect; the Custom Service tile calls onSelectCustom.
 * Supports both new (id/display_name) and legacy (name) template shapes.
 */
export function TemplatePicker({
  templates,
  onSelect,
  onSelectCustom,
}: TemplatePickerProps) {
  return (
    <div className="grid grid-cols-2 gap-3 sm:grid-cols-3">
      {templates.map((template) => {
        const key = template.id ?? template.name ?? '';
        const displayName = template.display_name ?? template.name ?? key;

        return (
          <button
            key={key}
            type="button"
            onClick={() => onSelect(template)}
            className="flex flex-col items-center gap-2 rounded-xl border border-slate-200 bg-white p-4 text-center transition-all hover:border-indigo-300 hover:shadow-md focus:outline-none focus:ring-2 focus:ring-indigo-500 dark:border-slate-600 dark:bg-slate-800 dark:hover:border-indigo-500"
          >
            <ServiceIcon name={key} size={36} />
            <span className="text-sm font-semibold text-slate-800 dark:text-slate-200">
              {displayName}
            </span>
            {template.description && (
              <span className="text-xs text-slate-500 dark:text-slate-400 line-clamp-2">
                {template.description}
              </span>
            )}
          </button>
        );
      })}

      <button
        type="button"
        onClick={onSelectCustom}
        className="flex flex-col items-center gap-2 rounded-xl border border-dashed border-slate-300 bg-slate-50 p-4 text-center transition-all hover:border-indigo-400 hover:bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500 dark:border-slate-600 dark:bg-slate-800/50 dark:hover:bg-slate-800"
      >
        <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-slate-200 dark:bg-slate-700">
          <svg
            aria-hidden="true"
            width="18"
            height="18"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            className="text-slate-500 dark:text-slate-400"
          >
            <line x1="12" y1="5" x2="12" y2="19" />
            <line x1="5" y1="12" x2="19" y2="12" />
          </svg>
        </div>
        <span className="text-sm font-medium text-slate-500 dark:text-slate-400">
          Custom Service
        </span>
      </button>
    </div>
  );
}
