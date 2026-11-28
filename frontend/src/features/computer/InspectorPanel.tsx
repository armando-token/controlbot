import React from 'react';
import { Database, FolderArchive, Info, Monitor, X } from 'lucide-react';
import type { Bot, Channel, InspectorTab } from '../../lib/types';
import { useUiStore } from '../../stores/uiStore';
import { LibraryTab } from '../artifacts/LibraryTab';
import { BotDetailsTab } from '../routines/BotDetailsTab';
import { ComputerTab } from './ComputerTab';

interface InspectorPanelProps {
  bot?: Bot | null;
  channel?: Channel | null;
  allBots: Bot[];
}

const TABS: { id: InspectorTab; label: string; icon: React.ComponentType<{ size?: number; strokeWidth?: number }> }[] = [
  { id: 'details', label: 'Details', icon: Info },
  { id: 'library', label: 'Library', icon: FolderArchive },
  { id: 'computer', label: 'Computer', icon: Monitor },
];

export const InspectorPanel: React.FC<InspectorPanelProps> = ({
  bot,
  channel,
  allBots,
}) => {
  const inspectorTab = useUiStore((s) => s.inspectorTab);
  const setInspectorTab = useUiStore((s) => s.setInspectorTab);
  const setInspectorOpen = useUiStore((s) => s.setInspectorOpen);
  const setMemoryOpen = useUiStore((s) => s.setMemoryOpen);

  return (
    <aside
      className="h-full flex flex-col"
      style={{
        backgroundColor: 'var(--bg-canvas)',
        borderLeft: '1px solid var(--border-subtle)',
      }}
    >
      <h2 className="sr-only">Inspector</h2>
      {/* Top 3-tab bar */}
      <div
        className="h-13 px-3 flex items-center justify-between gap-2 shrink-0"
        style={{ borderBottom: '1px solid var(--border-subtle)' }}
      >
        <div role="tablist" aria-label="Inspector tabs" className="flex items-center gap-1">
          {TABS.map((t) => {
            const Icon = t.icon;
            const active = inspectorTab === t.id;
            return (
              <button
                key={t.id}
                type="button"
                role="tab"
                aria-selected={active}
                aria-label={`${t.label}`}
                onClick={() => setInspectorTab(t.id)}
                className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[12.5px] font-medium transition-colors"
                style={{
                  backgroundColor: active ? 'var(--bg-active)' : 'transparent',
                  color:
                    active && t.id === 'computer'
                      ? 'var(--accent-computer)'
                      : active
                        ? 'var(--text-primary)'
                        : 'var(--text-secondary)',
                }}
              >
                <Icon size={14} strokeWidth={1.8} />
                <span>{t.label}</span>
              </button>
            );
          })}
        </div>

        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={() => setMemoryOpen(true)}
            title="Open Memory Browser"
            aria-label="Open Memory Browser"
            className="p-1.5 rounded-lg hover:bg-[var(--bg-subtle)]"
            style={{ color: 'var(--text-muted)' }}
          >
            <Database size={15} strokeWidth={1.75} />
          </button>
          <button
            type="button"
            onClick={() => setInspectorOpen(false)}
            title="Close panel (Cmd+Shift+I)"
            aria-label="Close inspector panel"
            className="p-1.5 rounded-lg hover:bg-[var(--bg-subtle)]"
            style={{ color: 'var(--text-muted)' }}
          >
            <X size={15.5} strokeWidth={1.75} />
          </button>
        </div>
      </div>

      {/* Active Tab Content */}
      <div className="flex-1 min-h-0 overflow-hidden">
        {inspectorTab === 'details' && (
          <BotDetailsTab bot={bot} channel={channel} allBots={allBots} />
        )}
        {inspectorTab === 'library' && (
          <LibraryTab bot={bot} channel={channel} allBots={allBots} />
        )}
        {inspectorTab === 'computer' && <ComputerTab bot={bot} />}
      </div>
    </aside>
  );
};
