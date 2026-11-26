import React from 'react';
import { Modal } from '../../components/Modal';
import { useUiStore } from '../../stores/uiStore';

const SHORTCUTS: { keys: string; action: string }[] = [
  { keys: '⌘ / Ctrl + K', action: 'Open global search & command palette' },
  { keys: '⌘ / Ctrl + Shift + F', action: 'Jump directly to a bot' },
  { keys: '⌘ / Ctrl + N', action: 'Create a new bot' },
  { keys: '⌘ / Ctrl + Shift + N', action: 'Create a new group chat' },
  { keys: '⌘ / Ctrl + B', action: 'Toggle compact sidebar' },
  { keys: '⌘ / Ctrl + 1–9', action: 'Switch to bot 1 through 9' },
  { keys: '⌘ + Shift + I  /  Ctrl + Alt + B', action: 'Toggle right inspector panel' },
  { keys: '⌘ / Ctrl + I', action: 'Focus message composer' },
  { keys: '⌘ / Ctrl + D', action: 'Toggle voice dictation' },
  { keys: '⌘ / Ctrl + F', action: 'Find inside an open interactive Page' },
  { keys: '⌘ / Ctrl + ,', action: 'Open Settings' },
  { keys: '⌘ / Ctrl + /', action: 'Show keyboard shortcuts' },
  { keys: 'Escape', action: 'Close open dialog or palette' },
];

export const ShortcutsDialog: React.FC = () => {
  const open = useUiStore((s) => s.shortcutsOpen);
  const setOpen = useUiStore((s) => s.setShortcutsOpen);

  return (
    <Modal
      open={open}
      onClose={() => setOpen(false)}
      title="Keyboard shortcuts"
      subtitle="Navigate your bots, Pages, and computer without leaving the keyboard."
    >
      <div className="p-5 divide-y divide-[var(--border-subtle)]">
        {SHORTCUTS.map((s) => (
          <div key={s.keys} className="flex items-center justify-between gap-4 py-2.5 text-[13px]">
            <span style={{ color: 'var(--text-primary)' }}>{s.action}</span>
            <kbd
              className="px-2 py-0.5 rounded-md font-mono text-[11.5px] shrink-0"
              style={{
                backgroundColor: 'var(--bg-subtle)',
                border: '1px solid var(--border-subtle)',
                color: 'var(--text-secondary)',
              }}
            >
              {s.keys}
            </kbd>
          </div>
        ))}
      </div>
    </Modal>
  );
};
