import React, { useState } from 'react';
import { ChevronDown, ChevronRight, Sparkles } from 'lucide-react';

interface ThinkingAccordionProps {
  text: string;
  summary?: string;
  streaming?: boolean;
}

export const ThinkingAccordion: React.FC<ThinkingAccordionProps> = ({
  text,
  summary,
  streaming = false,
}) => {
  const [open, setOpen] = useState(false);

  if (!text && !streaming) return null;

  const thinkingLabel = summary || (streaming ? 'Thinking' : 'Thought process');

  return (
    <div className="mb-2">
      <button
        type="button"
        aria-label={`${thinkingLabel}`}
        onClick={() => setOpen((v) => !v)}
        className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[12px] transition-colors hover:bg-[var(--bg-active)]"
        style={{
          backgroundColor: 'var(--bg-subtle)',
          color: 'var(--text-secondary)',
        }}
      >
        {open ? (
          <ChevronDown size={13} strokeWidth={1.9} />
        ) : (
          <ChevronRight size={13} strokeWidth={1.9} />
        )}
        <Sparkles
          size={12}
          strokeWidth={1.9}
          className={streaming ? 'animate-pulse' : ''}
          style={{ color: 'var(--accent-computer)' }}
        />
        <span>{summary || (streaming ? 'Thinking…' : 'Thought process')}</span>
      </button>

      {open && text && (
        <div
          className="mt-1.5 px-3 py-2.5 rounded-xl text-[12.5px] leading-relaxed whitespace-pre-wrap font-mono"
          style={{
            backgroundColor: 'var(--bg-sidebar)',
            border: '1px solid var(--border-subtle)',
            color: 'var(--text-secondary)',
          }}
        >
          {text}
        </div>
      )}
    </div>
  );
};
