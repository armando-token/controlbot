import React from 'react';
import { ArrowDownRight, FileText, PanelRightOpen } from 'lucide-react';
import type { ArtifactRef } from '../../lib/types';
import { useUiStore } from '../../stores/uiStore';

interface PageChatCardProps {
  artifact: ArtifactRef;
}

export const PageChatCard: React.FC<PageChatCardProps> = ({ artifact }) => {
  const setActivePageId = useUiStore((s) => s.setActivePageId);
  const activePageId = useUiStore((s) => s.activePageId);

  const isSuperseded = Boolean(artifact.superseded_by_id);
  const isOpen = activePageId === artifact.id;

  return (
    <div
      className="mt-2.5 flex items-center justify-between gap-3 px-3.5 py-2.5 rounded-xl transition-colors"
      style={{
        backgroundColor: isOpen ? 'var(--bg-active)' : 'var(--bg-sidebar)',
        border: isOpen
          ? '1px solid var(--border-strong)'
          : '1px solid var(--border-subtle)',
      }}
    >
      <div className="flex items-center gap-2.5 min-w-0">
        <span
          className="w-8 h-8 rounded-lg flex items-center justify-center shrink-0"
          style={{
            backgroundColor: 'var(--bg-canvas)',
            border: '1px solid var(--border-subtle)',
            color: 'var(--accent-computer)',
          }}
        >
          <FileText size={16} strokeWidth={1.75} />
        </span>
        <div className="min-w-0">
          <div
            className="text-[13.5px] font-medium truncate"
            style={{ color: 'var(--text-primary)' }}
          >
            {artifact.title}
          </div>
          <div className="text-[11.5px] flex items-center gap-1.5" style={{ color: 'var(--text-muted)' }}>
            <span>Page · v{artifact.version || 1}</span>
            {isSuperseded && (
              <span className="inline-flex items-center gap-0.5 text-[11px] font-medium" style={{ color: 'var(--text-secondary)' }}>
                <ArrowDownRight size={12} />
                Updated below
              </span>
            )}
          </div>
        </div>
      </div>

      <button
        type="button"
        onClick={() => setActivePageId(artifact.id)}
        className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12.5px] font-medium shrink-0 transition-colors hover:opacity-90"
        style={{
          backgroundColor: 'var(--bg-canvas)',
          border: '1px solid var(--border-strong)',
          color: 'var(--text-primary)',
        }}
      >
        <PanelRightOpen size={13} strokeWidth={1.75} />
        {isOpen ? 'Viewing' : 'Open'}
      </button>
    </div>
  );
};
