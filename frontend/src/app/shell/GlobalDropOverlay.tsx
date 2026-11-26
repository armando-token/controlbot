import React, { useEffect, useState } from 'react';
import { UploadCloud } from 'lucide-react';
import { attachmentsApi } from '../../lib/api';
import { useUiStore } from '../../stores/uiStore';

interface GlobalDropOverlayProps {
  activeThreadId: string | null;
}

export const GlobalDropOverlay: React.FC<GlobalDropOverlayProps> = ({
  activeThreadId,
}) => {
  const addComposerAttachment = useUiStore((s) => s.addComposerAttachment);
  const pushToast = useUiStore((s) => s.pushToast);

  const [dragging, setDragging] = useState(false);

  useEffect(() => {
    let depth = 0;

    const onDragEnter = (e: DragEvent) => {
      if (!e.dataTransfer?.types?.includes('Files')) return;
      e.preventDefault();
      depth += 1;
      setDragging(true);
    };

    const onDragOver = (e: DragEvent) => {
      if (!e.dataTransfer?.types?.includes('Files')) return;
      e.preventDefault();
    };

    const onDragLeave = (e: DragEvent) => {
      e.preventDefault();
      depth = Math.max(0, depth - 1);
      if (depth === 0) setDragging(false);
    };

    const onDrop = async (e: DragEvent) => {
      e.preventDefault();
      depth = 0;
      setDragging(false);
      const files = e.dataTransfer?.files;
      if (!files || files.length === 0) return;
      if (!activeThreadId) {
        pushToast({ tone: 'warn', title: 'Select a conversation before dropping files' });
        return;
      }

      try {
        let count = 0;
        for (const file of Array.from(files)) {
          const uploaded = await attachmentsApi.upload(file, activeThreadId);
          addComposerAttachment(activeThreadId, uploaded);
          count += 1;
        }
        pushToast({
          tone: 'success',
          title: `Attached ${count} ${count === 1 ? 'file' : 'files'}`,
        });
      } catch (err) {
        pushToast({
          tone: 'error',
          title: 'Upload failed',
          description: err instanceof Error ? err.message : 'Could not attach file',
        });
      }
    };

    window.addEventListener('dragenter', onDragEnter);
    window.addEventListener('dragover', onDragOver);
    window.addEventListener('dragleave', onDragLeave);
    window.addEventListener('drop', onDrop);
    return () => {
      window.removeEventListener('dragenter', onDragEnter);
      window.removeEventListener('dragover', onDragOver);
      window.removeEventListener('dragleave', onDragLeave);
      window.removeEventListener('drop', onDrop);
    };
  }, [activeThreadId, addComposerAttachment, pushToast]);

  if (!dragging) return null;

  return (
    <div
      className="fixed inset-0 z-[60] flex items-center justify-center p-6 pointer-events-none"
      style={{
        backgroundColor: 'rgba(124, 58, 237, 0.10)',
        backdropFilter: 'blur(3px)',
      }}
    >
      <div
        className="px-8 py-6 rounded-2xl flex flex-col items-center gap-2 text-center"
        style={{
          backgroundColor: 'var(--bg-elevated)',
          border: '2px dashed var(--accent-computer)',
          boxShadow: 'var(--shadow-lg)',
        }}
      >
        <UploadCloud size={32} style={{ color: 'var(--accent-computer)' }} />
        <div className="text-[15px] font-semibold" style={{ color: 'var(--text-primary)' }}>
          Drop files to add to chat
        </div>
        <div className="text-[12.5px]" style={{ color: 'var(--text-secondary)' }}>
          Attachments are uploaded securely to the active thread composer.
        </div>
      </div>
    </div>
  );
};
