import React, { useState } from 'react';
import {
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  FileCode2,
  Globe,
  Loader2,
  Plug,
  Search,
  Terminal,
  XCircle,
} from 'lucide-react';
import type { ToolCallItem } from '../../lib/types';

interface ToolCallCardProps {
  call: ToolCallItem;
}

export const ToolCallCard: React.FC<ToolCallCardProps> = ({ call }) => {
  const [expanded, setExpanded] = useState(false);

  const categoryIcon = () => {
    switch (call.category) {
      case 'browser':
        return <Globe size={13} strokeWidth={1.8} />;
      case 'terminal':
        return <Terminal size={13} strokeWidth={1.8} />;
      case 'file':
        return <FileCode2 size={13} strokeWidth={1.8} />;
      case 'search':
        return <Search size={13} strokeWidth={1.8} />;
      default:
        return <Plug size={13} strokeWidth={1.8} />;
    }
  };

  const statusIcon = () => {
    if (call.status === 'running') {
      return (
        <Loader2
          size={13}
          strokeWidth={2}
          className="animate-spin"
          style={{ color: 'var(--accent-computer)' }}
        />
      );
    }
    if (call.status === 'error') {
      return <XCircle size={13} strokeWidth={2} style={{ color: 'var(--status-danger)' }} />;
    }
    return <CheckCircle2 size={13} strokeWidth={2} style={{ color: 'var(--status-ok)' }} />;
  };

  const hasPreview = Boolean(call.output_preview && call.output_preview.trim());

  return (
    <div
      className="my-1.5 rounded-xl overflow-hidden"
      style={{
        backgroundColor: 'var(--bg-sidebar)',
        border: '1px solid var(--border-subtle)',
      }}
    >
      <button
        type="button"
        onClick={() => hasPreview && setExpanded((v) => !v)}
        disabled={!hasPreview}
        className="w-full flex items-center justify-between gap-2 px-3 py-1.5 text-left text-[12.5px] disabled:cursor-default hover:bg-[var(--bg-subtle)] transition-colors"
      >
        <div className="flex items-center gap-2 min-w-0">
          <span style={{ color: 'var(--text-secondary)' }}>{categoryIcon()}</span>
          <span className="font-mono text-[12px] font-medium shrink-0" style={{ color: 'var(--text-primary)' }}>
            {call.tool_name}
          </span>
          {call.summary && (
            <span className="truncate" style={{ color: 'var(--text-secondary)' }}>
              · {call.summary}
            </span>
          )}
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          {statusIcon()}
          {hasPreview &&
            (expanded ? (
              <ChevronDown size={13} style={{ color: 'var(--text-muted)' }} />
            ) : (
              <ChevronRight size={13} style={{ color: 'var(--text-muted)' }} />
            ))}
        </div>
      </button>

      {expanded && hasPreview && (
        <pre
          className="m-0 px-3 py-2 text-[11.5px] font-mono overflow-x-auto max-h-56 whitespace-pre-wrap"
          style={{
            backgroundColor: 'var(--bg-terminal)',
            color: '#D1D5DB',
            borderTop: '1px solid var(--border-subtle)',
          }}
        >
          {call.output_preview}
        </pre>
      )}
    </div>
  );
};
