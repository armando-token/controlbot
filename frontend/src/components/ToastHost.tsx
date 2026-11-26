import React from 'react';
import { AlertCircle, CheckCircle2, Info, TriangleAlert, X } from 'lucide-react';
import { useUiStore } from '../stores/uiStore';

export const ToastHost: React.FC = () => {
  const toasts = useUiStore((s) => s.toasts);
  const dismissToast = useUiStore((s) => s.dismissToast);

  if (toasts.length === 0) return null;

  return (
    <div
      className="fixed bottom-4 right-4 z-[70] flex flex-col gap-2 pointer-events-none max-w-sm w-full"
      aria-live="polite"
    >
      {toasts.map((t) => {
        const icon =
          t.tone === 'success' ? (
            <CheckCircle2 size={16} strokeWidth={1.75} style={{ color: 'var(--status-ok)' }} />
          ) : t.tone === 'warn' ? (
            <TriangleAlert size={16} strokeWidth={1.75} style={{ color: 'var(--status-warn)' }} />
          ) : t.tone === 'error' ? (
            <AlertCircle size={16} strokeWidth={1.75} style={{ color: 'var(--status-danger)' }} />
          ) : (
            <Info size={16} strokeWidth={1.75} style={{ color: 'var(--accent-computer)' }} />
          );

        return (
          <div
            key={t.id}
            className="pointer-events-auto flex items-start gap-2.5 px-3.5 py-2.5 rounded-xl"
            style={{
              backgroundColor: 'var(--bg-elevated)',
              border: '1px solid var(--border-strong)',
              boxShadow: 'var(--shadow-md)',
            }}
          >
            <span className="mt-0.5 shrink-0">{icon}</span>
            <div className="min-w-0 flex-1">
              <div
                className="text-[13px] font-medium leading-snug"
                style={{ color: 'var(--text-primary)' }}
              >
                {t.title}
              </div>
              {t.description && (
                <div
                  className="text-[12px] mt-0.5 leading-snug"
                  style={{ color: 'var(--text-secondary)' }}
                >
                  {t.description}
                </div>
              )}
            </div>
            <button
              type="button"
              onClick={() => dismissToast(t.id)}
              aria-label="Dismiss notification"
              className="p-0.5 rounded hover:bg-[var(--bg-subtle)] shrink-0"
              style={{ color: 'var(--text-muted)' }}
            >
              <X size={14} strokeWidth={1.75} />
            </button>
          </div>
        );
      })}
    </div>
  );
};
