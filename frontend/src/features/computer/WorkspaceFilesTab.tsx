import React, { useEffect, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Check,
  ChevronRight,
  Download,
  FileCode2,
  FilePlus2,
  Folder,
  FolderPlus,
  RefreshCw,
  Trash2,
  Upload,
} from 'lucide-react';
import { Modal } from '../../components/Modal';
import { computerApi, legacyApi } from '../../lib/api';
import { formatBytes } from '../../lib/markdown';
import { useUiStore } from '../../stores/uiStore';

interface WorkspaceFilesTabProps {
  vmId?: string;
  defaultProject?: string | null;
}

export const WorkspaceFilesTab: React.FC<WorkspaceFilesTabProps> = ({
  vmId = 'default',
  defaultProject = '',
}) => {
  const queryClient = useQueryClient();
  const pushToast = useUiStore((s) => s.pushToast);

  const [project, setProject] = useState(defaultProject || '');
  const [relPath, setRelPath] = useState('');
  const [previewPath, setPreviewPath] = useState<string | null>(null);
  const [fileDraft, setFileDraft] = useState('');
  const [newFolderOpen, setNewFolderOpen] = useState(false);
  const [newFolderName, setNewFolderName] = useState('');
  const [newFileOpen, setNewFileOpen] = useState(false);
  const [newFileName, setNewFileName] = useState('');
  const [newFileContent, setNewFileContent] = useState('');
  const uploadInputRef = useRef<HTMLInputElement | null>(null);

  useEffect(() => {
    setProject(defaultProject || '');
    setRelPath('');
    setPreviewPath(null);
    setFileDraft('');
  }, [defaultProject]);

  const projectsQuery = useQuery({
    queryKey: ['local-projects'],
    queryFn: () => legacyApi.projects(),
    staleTime: 60_000,
  });

  const filesQuery = useQuery({
    queryKey: ['workspace-files', vmId, project, relPath],
    queryFn: () => computerApi.listFiles(vmId, relPath, project),
  });

  const fileReadQuery = useQuery({
    queryKey: ['workspace-file', vmId, project, previewPath],
    queryFn: async () => {
      const data = await computerApi.readFile(vmId, previewPath!, project);
      setFileDraft(data.content);
      return data;
    },
    enabled: Boolean(previewPath),
  });

  const uploadMutation = useMutation({
    mutationFn: (file: File) => computerApi.uploadFile(vmId, file, relPath, project),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['workspace-files', vmId] });
      pushToast({ tone: 'success', title: 'File uploaded' });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Upload failed', description: err.message });
    },
  });

  const mkdirMutation = useMutation({
    mutationFn: (name: string) => {
      const target = relPath ? `${relPath}/${name}` : name;
      return computerApi.mkdir(vmId, target, project);
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['workspace-files', vmId] });
      setNewFolderName('');
      setNewFolderOpen(false);
      pushToast({ tone: 'success', title: 'Folder created' });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not create folder', description: err.message });
    },
  });

  const writeFileMutation = useMutation({
    mutationFn: ({ path, content }: { path: string; content: string }) =>
      computerApi.writeFile(vmId, path, content, project),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['workspace-files', vmId] });
      void queryClient.invalidateQueries({ queryKey: ['workspace-file', vmId] });
      setNewFileName('');
      setNewFileContent('');
      setNewFileOpen(false);
      pushToast({ tone: 'success', title: 'File saved' });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not save file', description: err.message });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (targetPath: string) => computerApi.deleteFile(vmId, targetPath, project),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['workspace-files', vmId] });
      pushToast({ tone: 'info', title: 'Deleted' });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Delete failed', description: err.message });
    },
  });

  const pathSegments = relPath ? relPath.split('/').filter(Boolean) : [];
  const entries = filesQuery.data?.entries ?? [];

  return (
    <div className="h-full flex flex-col">
      {/* Project & Actions Bar */}
      <div
        className="p-3 space-y-2 shrink-0"
        style={{ borderBottom: '1px solid var(--border-subtle)' }}
      >
        <div className="flex items-center gap-1.5">
          <select
            value={project}
            onChange={(e) => {
              setProject(e.target.value);
              setRelPath('');
            }}
            aria-label="Workspace project"
            className="flex-1 px-2.5 py-1.5 rounded-lg text-[12.5px] outline-none"
            style={{
              backgroundColor: 'var(--bg-sidebar)',
              border: '1px solid var(--border-strong)',
            }}
          >
            <option value="">Default workspace</option>
            {(projectsQuery.data?.projects ?? []).map((p) => (
              <option key={p.name} value={p.name}>
                {p.name}
              </option>
            ))}
          </select>

          <button
            type="button"
            onClick={() => void filesQuery.refetch()}
            title="Refresh files"
            aria-label="Refresh files"
            className="p-1.5 rounded-lg hover:bg-[var(--bg-subtle)]"
            style={{ color: 'var(--text-secondary)' }}
          >
            <RefreshCw size={14} />
          </button>
        </div>
        {projectsQuery.isError && (
          <div className="text-[11px]" style={{ color: 'var(--status-danger)' }}>
            Could not load project list:{' '}
            {projectsQuery.error instanceof Error ? projectsQuery.error.message : 'Request failed'}
          </div>
        )}

        <div className="flex items-center gap-1.5">
          <input
            ref={uploadInputRef}
            type="file"
            className="hidden"
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) uploadMutation.mutate(f);
              e.target.value = '';
            }}
          />
          <button
            type="button"
            onClick={() => uploadInputRef.current?.click()}
            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[12px] font-medium hover:bg-[var(--bg-active)]"
            style={{ backgroundColor: 'var(--bg-subtle)', color: 'var(--text-primary)' }}
          >
            <Upload size={12.5} />
            Upload
          </button>
          <button
            type="button"
            onClick={() => setNewFolderOpen(true)}
            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[12px] font-medium hover:bg-[var(--bg-active)]"
            style={{ backgroundColor: 'var(--bg-subtle)', color: 'var(--text-primary)' }}
          >
            <FolderPlus size={12.5} />
            Folder
          </button>
          <button
            type="button"
            onClick={() => setNewFileOpen(true)}
            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[12px] font-medium hover:bg-[var(--bg-active)]"
            style={{ backgroundColor: 'var(--bg-subtle)', color: 'var(--text-primary)' }}
          >
            <FilePlus2 size={12.5} />
            New file
          </button>
        </div>

        {/* Breadcrumbs */}
        <div className="flex items-center flex-wrap gap-1 text-[11.5px] font-mono">
          <button
            type="button"
            onClick={() => setRelPath('')}
            className="px-1.5 py-0.5 rounded hover:bg-[var(--bg-subtle)]"
            style={{ color: 'var(--text-secondary)' }}
          >
            /workspace
          </button>
          {pathSegments.map((seg, idx) => {
            const target = pathSegments.slice(0, idx + 1).join('/');
            return (
              <React.Fragment key={target}>
                <ChevronRight size={12} style={{ color: 'var(--text-muted)' }} />
                <button
                  type="button"
                  onClick={() => setRelPath(target)}
                  className="px-1.5 py-0.5 rounded hover:bg-[var(--bg-subtle)]"
                  style={{ color: 'var(--text-primary)' }}
                >
                  {seg}
                </button>
              </React.Fragment>
            );
          })}
        </div>
      </div>

      {/* Entries List */}
      <div className="flex-1 overflow-y-auto p-2.5 space-y-1">
        {filesQuery.isLoading ? (
          <div className="text-[12.5px] py-6 text-center" style={{ color: 'var(--text-muted)' }}>
            Loading workspace…
          </div>
        ) : filesQuery.isError ? (
          <div className="text-[12.5px] py-6 text-center" style={{ color: 'var(--status-danger)' }}>
            {(filesQuery.error as Error).message}
          </div>
        ) : entries.length === 0 ? (
          <div className="text-[12.5px] py-8 text-center" style={{ color: 'var(--text-muted)' }}>
            Empty folder
          </div>
        ) : (
          entries.map((entry) => (
            <div
              key={entry.rel_path}
              className="group flex items-center justify-between gap-2 px-2.5 py-1.5 rounded-xl hover:bg-[var(--bg-subtle)]"
            >
              <button
                type="button"
                onClick={() => {
                  if (entry.is_dir) {
                    setRelPath(entry.rel_path);
                  } else {
                    setFileDraft('');
                    setPreviewPath(entry.rel_path);
                  }
                }}
                className="flex items-center gap-2 min-w-0 flex-1 text-left"
              >
                {entry.is_dir ? (
                  <Folder size={15} style={{ color: 'var(--accent-computer)' }} className="shrink-0" />
                ) : (
                  <FileCode2 size={15} style={{ color: 'var(--text-secondary)' }} className="shrink-0" />
                )}
                <span className="text-[13px] truncate" style={{ color: 'var(--text-primary)' }}>
                  {entry.name}
                </span>
              </button>

              <div className="flex items-center gap-1 shrink-0">
                {!entry.is_dir && (
                  <span className="text-[11px] tabular-nums mr-1" style={{ color: 'var(--text-muted)' }}>
                    {formatBytes(entry.size_bytes)}
                  </span>
                )}
                {!entry.is_dir && (
                  <a
                    href={computerApi.downloadFileUrl(vmId, entry.rel_path, project)}
                    download={entry.name}
                    title="Download"
                    aria-label={`Download ${entry.name}`}
                    className="opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 p-1 rounded hover:bg-[var(--bg-active)]"
                    style={{ color: 'var(--text-secondary)' }}
                  >
                    <Download size={13} />
                  </a>
                )}
                <button
                  type="button"
                  onClick={() => deleteMutation.mutate(entry.rel_path)}
                  title="Delete"
                  aria-label={`Delete ${entry.name}`}
                  className="opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 p-1 rounded hover:bg-[var(--status-danger-bg)]"
                  style={{ color: 'var(--status-danger)' }}
                >
                  <Trash2 size={13} />
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      {/* File Preview / Edit Modal */}
      <Modal
        open={Boolean(previewPath)}
        onClose={() => setPreviewPath(null)}
        title={previewPath || 'File'}
        subtitle={
          fileReadQuery.data
            ? `${formatBytes(fileReadQuery.data.size_bytes)}${fileReadQuery.data.truncated ? ' (truncated)' : ''}`
            : undefined
        }
        maxWidthClass="max-w-3xl"
      >
        <div className="p-4 space-y-3">
          {fileReadQuery.isLoading ? (
            <div className="text-[13px] py-8 text-center" style={{ color: 'var(--text-muted)' }}>
              Reading file…
            </div>
          ) : fileReadQuery.isError ? (
            <div className="py-6 space-y-3 text-center">
              <div className="text-[13px]" style={{ color: 'var(--status-danger)' }}>
                {fileReadQuery.error instanceof Error
                  ? fileReadQuery.error.message
                  : 'Could not read file'}
              </div>
              <div className="flex justify-center">
                <button
                  type="button"
                  onClick={() => setPreviewPath(null)}
                  className="px-3 py-1.5 rounded-lg text-[12.5px] hover:bg-[var(--bg-subtle)]"
                  style={{ color: 'var(--text-secondary)' }}
                >
                  Close
                </button>
              </div>
            </div>
          ) : (
            <>
              <textarea
                rows={18}
                value={fileDraft}
                onChange={(e) => setFileDraft(e.target.value)}
                className="w-full p-3.5 rounded-xl text-[12.5px] font-mono leading-relaxed outline-none resize-y"
                style={{
                  backgroundColor: 'var(--bg-terminal)',
                  color: '#E5E7EB',
                  border: '1px solid var(--border-strong)',
                }}
              />
              <div className="flex items-center justify-between gap-2">
                {previewPath && (
                  <a
                    href={computerApi.downloadFileUrl(vmId, previewPath, project)}
                    download
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12.5px] hover:bg-[var(--bg-subtle)]"
                    style={{ color: 'var(--text-secondary)' }}
                  >
                    <Download size={14} />
                    Download
                  </a>
                )}
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    onClick={() => setPreviewPath(null)}
                    className="px-3 py-1.5 rounded-lg text-[12.5px] hover:bg-[var(--bg-subtle)]"
                    style={{ color: 'var(--text-secondary)' }}
                  >
                    Close
                  </button>
                  <button
                    type="button"
                    disabled={writeFileMutation.isPending || !previewPath}
                    onClick={() =>
                      previewPath &&
                      writeFileMutation.mutate({ path: previewPath, content: fileDraft })
                    }
                    className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-[12.5px] font-medium"
                    style={{
                      backgroundColor: 'var(--accent-primary)',
                      color: 'var(--bg-canvas)',
                    }}
                  >
                    <Check size={14} />
                    {writeFileMutation.isPending ? 'Saving…' : 'Save file'}
                  </button>
                </div>
              </div>
            </>
          )}
        </div>
      </Modal>

      {/* New Folder Modal */}
      <Modal
        open={newFolderOpen}
        onClose={() => setNewFolderOpen(false)}
        title="New folder"
        maxWidthClass="max-w-sm"
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (newFolderName.trim()) mkdirMutation.mutate(newFolderName.trim());
          }}
          className="p-4 space-y-3"
        >
          <input
            type="text"
            autoFocus
            required
            value={newFolderName}
            onChange={(e) => setNewFolderName(e.target.value)}
            placeholder="folder-name"
            className="w-full px-3 py-2 rounded-lg text-[13px] font-mono outline-none bg-[var(--bg-sidebar)] border border-[var(--border-strong)]"
          />
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setNewFolderOpen(false)}
              className="px-3 py-1.5 rounded-lg text-[12.5px]"
              style={{ color: 'var(--text-secondary)' }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={mkdirMutation.isPending}
              className="px-3.5 py-1.5 rounded-lg text-[12.5px] font-medium"
              style={{ backgroundColor: 'var(--accent-primary)', color: 'var(--bg-canvas)' }}
            >
              Create
            </button>
          </div>
        </form>
      </Modal>

      {/* New File Modal */}
      <Modal
        open={newFileOpen}
        onClose={() => setNewFileOpen(false)}
        title="New file"
        maxWidthClass="max-w-lg"
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (newFileName.trim()) {
              const path = relPath
                ? `${relPath}/${newFileName.trim()}`
                : newFileName.trim();
              writeFileMutation.mutate({ path, content: newFileContent });
            }
          }}
          className="p-4 space-y-3"
        >
          <input
            type="text"
            autoFocus
            required
            value={newFileName}
            onChange={(e) => setNewFileName(e.target.value)}
            placeholder="notes.md"
            className="w-full px-3 py-2 rounded-lg text-[13px] font-mono outline-none bg-[var(--bg-sidebar)] border border-[var(--border-strong)]"
          />
          <textarea
            rows={8}
            value={newFileContent}
            onChange={(e) => setNewFileContent(e.target.value)}
            placeholder="File content…"
            className="w-full p-3 rounded-lg text-[12.5px] font-mono outline-none bg-[var(--bg-sidebar)] border border-[var(--border-strong)]"
          />
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setNewFileOpen(false)}
              className="px-3 py-1.5 rounded-lg text-[12.5px]"
              style={{ color: 'var(--text-secondary)' }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={writeFileMutation.isPending}
              className="px-3.5 py-1.5 rounded-lg text-[12.5px] font-medium"
              style={{ backgroundColor: 'var(--accent-primary)', color: 'var(--bg-canvas)' }}
            >
              Create file
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
};
