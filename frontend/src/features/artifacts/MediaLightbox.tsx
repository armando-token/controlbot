import React, { useState } from 'react';
import { Download, ZoomIn, ZoomOut } from 'lucide-react';
import { Modal } from '../../components/Modal';
import { withAuthToken } from '../../lib/api';
import { useUiStore } from '../../stores/uiStore';

export const MediaLightbox: React.FC = () => {
  const artifact = useUiStore((s) => s.lightboxArtifact);
  const setArtifact = useUiStore((s) => s.setLightboxArtifact);
  const [zoom, setZoom] = useState(1);

  if (!artifact) return null;

  const src = artifact.url ? withAuthToken(artifact.url) : '';
  const isVideo = Boolean(artifact.mime_type?.startsWith('video/'));
  const isAudio = Boolean(artifact.mime_type?.startsWith('audio/'));

  return (
    <Modal
      open={Boolean(artifact)}
      onClose={() => {
        setZoom(1);
        setArtifact(null);
      }}
      title={artifact.title}
      subtitle={artifact.mime_type}
      maxWidthClass="max-w-4xl"
    >
      <div className="p-4 space-y-3">
        <div className="flex items-center justify-end gap-1.5">
          {!isVideo && !isAudio && (
            <>
              <button
                type="button"
                onClick={() => setZoom((z) => Math.max(0.5, Number((z - 0.25).toFixed(2))))}
                className="p-1.5 rounded-lg hover:bg-[var(--bg-subtle)]"
                title="Zoom out"
                aria-label="Zoom out"
              >
                <ZoomOut size={15} />
              </button>
              <span className="text-[12px] tabular-nums w-12 text-center">
                {Math.round(zoom * 100)}%
              </span>
              <button
                type="button"
                onClick={() => setZoom((z) => Math.min(2, Number((z + 0.25).toFixed(2))))}
                className="p-1.5 rounded-lg hover:bg-[var(--bg-subtle)]"
                title="Zoom in"
                aria-label="Zoom in"
              >
                <ZoomIn size={15} />
              </button>
            </>
          )}
          {src && (
            <a
              href={src}
              download={artifact.title}
              aria-label={`Download ${artifact.title}`}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[12px] font-medium hover:bg-[var(--bg-subtle)]"
              style={{ border: '1px solid var(--border-subtle)' }}
            >
              <Download size={14} />
              Download
            </a>
          )}
        </div>

        <div
          className="rounded-xl overflow-auto max-h-[68vh] flex items-center justify-center p-4"
          style={{ backgroundColor: 'var(--bg-sidebar)' }}
        >
          {src ? (
            isVideo ? (
              <video src={src} controls className="max-w-full max-h-[62vh] rounded-lg" />
            ) : isAudio ? (
              <audio controls src={src} className="w-full max-w-md" />
            ) : (
              <img
                src={src}
                alt={artifact.title}
                style={{ transform: `scale(${zoom})`, transformOrigin: 'center' }}
                className="max-w-full max-h-[62vh] rounded-lg transition-transform"
              />
            )
          ) : (
            <div className="text-[13px]" style={{ color: 'var(--text-muted)' }}>
              No preview URL available.
            </div>
          )}
        </div>
      </div>
    </Modal>
  );
};
