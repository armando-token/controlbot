import React, { useEffect, useId, useRef } from 'react';
import { X } from 'lucide-react';

interface ModalProps {
  open: boolean;
  onClose: () => void;
  title?: string;
  subtitle?: string;
  ariaLabel?: string;
  maxWidthClass?: string;
  hideHeader?: boolean;
  children: React.ReactNode;
}

const FOCUSABLE_SELECTOR =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

function getFocusableElements(container: HTMLElement): HTMLElement[] {
  return Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE_SELECTOR)).filter(
    (el) =>
      !el.hasAttribute('disabled') &&
      el.getAttribute('aria-hidden') !== 'true' &&
      el.getClientRects().length > 0,
  );
}

export const Modal: React.FC<ModalProps> = ({
  open,
  onClose,
  title,
  subtitle,
  ariaLabel,
  maxWidthClass = 'max-w-lg',
  hideHeader = false,
  children,
}) => {
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);
  const wasOpenRef = useRef(false);
  const onCloseRef = useRef(onClose);
  onCloseRef.current = onClose;

  if (open && !wasOpenRef.current) {
    const active = document.activeElement;
    if (
      active instanceof HTMLElement &&
      (!dialogRef.current || !dialogRef.current.contains(active))
    ) {
      previousFocusRef.current = active;
    }
  }

  const titleId = useId();
  const subtitleId = useId();

  useEffect(() => {
    wasOpenRef.current = open;
    if (!open) return;
    if (!previousFocusRef.current) {
      const prev = document.activeElement instanceof HTMLElement ? document.activeElement : null;
      if (prev && (!dialogRef.current || !dialogRef.current.contains(prev))) {
        previousFocusRef.current = prev;
      }
    }

    const raf = window.requestAnimationFrame(() => {
      const root = dialogRef.current;
      if (!root) return;
      if (!root.contains(document.activeElement)) {
        const focusables = getFocusableElements(root);
        const first =
          root.querySelector<HTMLElement>('[autofocus], [data-autofocus]') ??
          focusables.find((el) => el.getAttribute('aria-label') !== 'Close dialog') ??
          focusables[0];
        (first ?? root).focus();
      }
    });

    const onKey = (e: KeyboardEvent) => {
      if (e.isComposing) return;
      if (e.key === 'Escape') {
        e.preventDefault();
        e.stopPropagation();
        onCloseRef.current();
        return;
      }
      if (e.key === 'Tab') {
        const root = dialogRef.current;
        if (!root) return;
        const focusables = getFocusableElements(root);
        if (focusables.length === 0) {
          e.preventDefault();
          root.focus();
          return;
        }
        const first = focusables[0];
        const last = focusables[focusables.length - 1];
        if (!first || !last) return;
        const active = document.activeElement;
        if (e.shiftKey) {
          if (active === first || active === root || !root.contains(active)) {
            e.preventDefault();
            last.focus();
          }
        } else if (active === last || !root.contains(active)) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    window.addEventListener('keydown', onKey, true);
    return () => {
      window.cancelAnimationFrame(raf);
      window.removeEventListener('keydown', onKey, true);
      const restoreTarget = previousFocusRef.current;
      previousFocusRef.current = null;
      if (
        restoreTarget &&
        restoreTarget.isConnected &&
        restoreTarget !== document.body &&
        restoreTarget !== document.documentElement
      ) {
        restoreTarget.focus();
      } else {
        const fallback = document.querySelector<HTMLElement>(
          'textarea[aria-label="Message composer"], button[aria-label="Search and commands"]',
        );
        fallback?.focus();
      }
    };
  }, [open]);

  if (!open) return null;

  const dialogLabel = ariaLabel ?? (title || 'Dialog');

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ backgroundColor: 'rgba(15, 23, 42, 0.36)', backdropFilter: 'blur(2px)' }}
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) {
          e.preventDefault();
          onClose();
        }
      }}
    >
      <div
        ref={dialogRef}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-labelledby={!hideHeader && title ? titleId : undefined}
        aria-describedby={!hideHeader && subtitle ? subtitleId : undefined}
        aria-label={`${dialogLabel}`}
        className={`w-full ${maxWidthClass} max-h-[90vh] flex flex-col overflow-hidden outline-none`}
        style={{
          backgroundColor: 'var(--bg-elevated)',
          border: '1px solid var(--border-strong)',
          borderRadius: 'var(--radius-lg)',
          boxShadow: 'var(--shadow-lg)',
        }}
      >
        {!hideHeader && (
          <div
            className="flex items-start justify-between gap-3 px-5 py-4 shrink-0"
            style={{ borderBottom: '1px solid var(--border-subtle)' }}
          >
            <div className="min-w-0">
              {title && (
                <h2
                  id={titleId}
                  className="text-[15px] font-semibold tracking-tight truncate"
                  style={{ color: 'var(--text-primary)' }}
                >
                  {title}
                </h2>
              )}
              {subtitle && (
                <p
                  id={subtitleId}
                  className="text-[12.5px] mt-0.5"
                  style={{ color: 'var(--text-secondary)' }}
                >
                  {subtitle}
                </p>
              )}
            </div>
            <button
              type="button"
              onClick={onClose}
              aria-label="Close dialog"
              className="p-1.5 rounded-lg transition-colors hover:bg-[var(--bg-subtle)]"
              style={{ color: 'var(--text-secondary)' }}
            >
              <X size={16} strokeWidth={1.75} />
            </button>
          </div>
        )}
        <div className="overflow-y-auto flex-1">{children}</div>
      </div>
    </div>
  );
};
