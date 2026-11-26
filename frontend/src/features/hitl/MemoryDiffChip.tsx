import React from 'react';
import { Brain } from 'lucide-react';
import type { MemoryDiff } from '../../lib/types';

interface MemoryDiffChipProps {
  diffs: MemoryDiff[];
}

export const MemoryDiffChip: React.FC<MemoryDiffChipProps> = ({ diffs }) => {
  if (!diffs || diffs.length === 0) return null;

  return (
    <div className="flex flex-wrap gap-1.5 mt-2">
      {diffs.map((d, idx) => (
        <span
          key={`${idx}-${d.text}`}
          className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-[11.5px]"
          style={{
            backgroundColor: 'var(--bg-subtle)',
            color: 'var(--text-secondary)',
            border: '1px solid var(--border-subtle)',
          }}
        >
          <Brain size={12} strokeWidth={1.75} style={{ color: 'var(--accent-computer)' }} />
          <span className="capitalize font-medium">{d.action}:</span>
          <span className="truncate max-w-[260px]">{d.text}</span>
        </span>
      ))}
    </div>
  );
};
