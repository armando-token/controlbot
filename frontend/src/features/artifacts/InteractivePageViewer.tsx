import React, { useEffect, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle,
  ArrowRight,
  Check,
  ChevronDown,
  ChevronUp,
  Download,
  Edit3,
  Eye,
  Globe,
  Lock,
  Pin,
  PinOff,
  Printer,
  Search,
  Users,
  X,
} from 'lucide-react';
import { MarkdownRenderer } from '../../components/MarkdownRenderer';
import { libraryApi, pagesApi } from '../../lib/api';
import { downloadTextFile, formatRelativeTime } from '../../lib/markdown';
import type { ShareScope } from '../../lib/types';
import { useUiStore } from '../../stores/uiStore';

interface InteractivePageViewerProps {
  pageId: string;
}

interface StashedDraft {
  pageId: string;
  title: string;
  content_md: string;
}

function clearSearchHighlights(root: HTMLElement | null): void {
  if (!root) return;
  const marks = root.querySelectorAll('mark.gb-search-hit');
  marks.forEach((mark) => {
    const parent = mark.parentNode;
    if (!parent) return;
    parent.replaceChild(document.createTextNode(mark.textContent ?? ''), mark);
    parent.normalize();
  });
}

function applySearchHighlights(root: HTMLElement, query: string): HTMLElement[] {
  const needle = query.trim().toLowerCase();
  if (!needle) return [];

  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
    acceptNode: (node) => {
      const parent = node.parentElement;
      if (!parent) return NodeFilter.FILTER_REJECT;
      const tag = parent.tagName;
      if (
        tag === 'SCRIPT' ||
        tag === 'STYLE' ||
        tag === 'TEXTAREA' ||
        tag === 'INPUT' ||
        tag === 'BUTTON'
      ) {
        return NodeFilter.FILTER_REJECT;
      }
      if (parent.closest('button, mark.gb-search-hit')) {
        return NodeFilter.FILTER_REJECT;
      }
      if (!node.nodeValue || !node.nodeValue.toLowerCase().includes(needle)) {
        return NodeFilter.FILTER_SKIP;
      }
      return NodeFilter.FILTER_ACCEPT;
    },
  });

  const textNodes: Text[] = [];
  let current = walker.nextNode();
  while (current) {
    textNodes.push(current as Text);
    current = walker.nextNode();
  }

  const marks: HTMLElement[] = [];
  for (const textNode of textNodes) {
    const text = textNode.nodeValue ?? '';
    const lower = text.toLowerCase();
    const ranges: { start: number; end: number }[] = [];
    let startIdx = 0;
    while (startIdx < lower.length) {
      const idx = lower.indexOf(needle, startIdx);
      if (idx === -1) break;
      ranges.push({ start: idx, end: idx + needle.length });
      startIdx = idx + needle.length;
    }
    if (ranges.length === 0) continue;

    const frag = document.createDocumentFragment();
    let cursor = 0;
    for (const r of ranges) {
      if (r.start > cursor) {
        frag.appendChild(document.createTextNode(text.slice(cursor, r.start)));
      }
      const mark = document.createElement('mark');
      mark.className = 'gb-search-hit';
      mark.textContent = text.slice(r.start, r.end);
      frag.appendChild(mark);
      marks.push(mark);
      cursor = r.end;
    }
    if (cursor < text.length) {
      frag.appendChild(document.createTextNode(text.slice(cursor)));
    }
    textNode.parentNode?.replaceChild(frag, textNode);
  }

  return marks;
}

export const InteractivePageViewer: React.FC<InteractivePageViewerProps> = ({ pageId }) => {
  const queryClient = useQueryClient();
  const setActivePageId = useUiStore((s) => s.setActivePageId);
  const pushToast = useUiStore((s) => s.pushToast);

  const pageQuery = useQuery({
    queryKey: ['page', pageId],
    queryFn: () => pagesApi.get(pageId),
  });

  const page = pageQuery.data;

  const [editingTitle, setEditingTitle] = useState(false);
  const [titleDraft, setTitleDraft] = useState('');
  const [editMode, setEditMode] = useState(false);
  const [mdDraft, setMdDraft] = useState('');
  const [searchOpen, setSearchOpen] = useState(false);
  const [searchTerm, setSearchTerm] = useState('');
  const [matchCount, setMatchCount] = useState(0);
  const [activeMatchIdx, setActiveMatchIdx] = useState(0);
  const [pendingNavTarget, setPendingNavTarget] = useState<string | null | undefined>(undefined);
  const [stashedDraft, setStashedDraft] = useState<StashedDraft | null>(null);

  const searchInputRef = useRef<HTMLInputElement | null>(null);
  const contentRef = useRef<HTMLDivElement | null>(null);
  const marksRef = useRef<HTMLElement[]>([]);
  const lastLoadedPageIdRef = useRef<string | null>(null);
  const latestSnapshotRef = useRef<{
    pageId: string;
    title: string;
    dirty: boolean;
    mdDraft: string;
  }>({ pageId, title: '', dirty: false, mdDraft: '' });

  const isDirty = Boolean(page && editMode && mdDraft !== page.content_md);

  useEffect(() => {
    const prev = latestSnapshotRef.current;
    if (prev.pageId !== pageId && prev.dirty) {
      setStashedDraft({
        pageId: prev.pageId,
        title: prev.title,
        content_md: prev.mdDraft,
      });
    }
    setPendingNavTarget(undefined);
    setEditMode(false);
    setEditingTitle(false);
    setSearchOpen(false);
    setSearchTerm('');
    setMatchCount(0);
    setActiveMatchIdx(0);
  }, [pageId]);

  useEffect(() => {
    latestSnapshotRef.current = {
      pageId,
      title: page?.title || 'Untitled page',
      dirty: isDirty,
      mdDraft,
    };
  }, [pageId, page?.title, isDirty, mdDraft]);

  useEffect(() => {
    if (!page) return;
    const isNewPage = lastLoadedPageIdRef.current !== page.id;
    if (isNewPage) {
      lastLoadedPageIdRef.current = page.id;
      setTitleDraft(page.title);
      if (stashedDraft && stashedDraft.pageId === page.id) {
        setMdDraft(stashedDraft.content_md);
        setEditMode(true);
        setStashedDraft(null);
      } else {
        setMdDraft(page.content_md);
      }
      return;
    }
    // Avoid clobbering unsaved local edits during background refetches
    if (!editMode) {
      setTitleDraft(page.title);
      setMdDraft(page.content_md);
    }
  }, [page, editMode, stashedDraft]);

  // In-page Cmd/Ctrl+F search shortcut
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'f' && !e.shiftKey) {
        e.preventDefault();
        setSearchOpen(true);
        window.requestAnimationFrame(() => searchInputRef.current?.focus());
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  const updateMutation = useMutation({
    mutationFn: (
      patch: Partial<{ title: string; content_md: string; share_scope: ShareScope }>,
    ) => pagesApi.update(pageId, patch),
    onSuccess: (updated) => {
      queryClient.setQueryData(['page', pageId], updated);
      void queryClient.invalidateQueries({ queryKey: ['library'] });
      void queryClient.invalidateQueries({ queryKey: ['thread-messages'] });
      pushToast({ tone: 'success', title: 'Page saved' });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not save page', description: err.message });
    },
  });

  const pinMutation = useMutation({
    mutationFn: (pinned: boolean) => libraryApi.togglePin(pageId, pinned),
    onSuccess: (updated) => {
      queryClient.setQueryData(['page', pageId], updated);
      void queryClient.invalidateQueries({ queryKey: ['library'] });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not update pin', description: err.message });
    },
  });

  // DOM TextWalker search highlighting (never mutates raw Markdown source)
  useEffect(() => {
    const root = contentRef.current;
    clearSearchHighlights(root);
    marksRef.current = [];

    if (!root || editMode || !searchOpen || !searchTerm.trim()) {
      setMatchCount(0);
      return;
    }

    const marks = applySearchHighlights(root, searchTerm);
    marksRef.current = marks;
    setMatchCount(marks.length);

    return () => {
      clearSearchHighlights(root);
      marksRef.current = [];
    };
  }, [page?.id, page?.version, page?.content_md, editMode, searchOpen, searchTerm]);

  // Toggle active match highlight without rebuilding the DOM on Prev/Next
  useEffect(() => {
    const marks = marksRef.current;
    if (marks.length === 0) return;
    for (const m of marks) {
      m.classList.remove('gb-search-hit-active');
    }
    const clampedIdx = ((activeMatchIdx % marks.length) + marks.length) % marks.length;
    const activeMark = marks[clampedIdx];
    if (activeMark) {
      activeMark.classList.add('gb-search-hit-active');
      activeMark.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }
  }, [activeMatchIdx, matchCount, page?.id, page?.version, page?.content_md, editMode, searchOpen, searchTerm]);

  const stepSearchMatch = (delta: number) => {
    if (matchCount <= 0) return;
    setActiveMatchIdx((idx) => (idx + delta + matchCount) % matchCount);
  };

  const requestNavigate = (targetPageId: string | null) => {
    if (isDirty) {
      setPendingNavTarget(targetPageId);
      return;
    }
    setActivePageId(targetPageId);
  };

  const handleToggleEditMode = async () => {
    if (!page) return;
    if (editMode) {
      if (mdDraft !== page.content_md) {
        try {
          const updated = await updateMutation.mutateAsync({ content_md: mdDraft });
          setMdDraft(updated.content_md);
          setEditMode(false);
        } catch {
          // Stay in edit mode so mdDraft is preserved; onError toast already fires
        }
        return;
      }
      setEditMode(false);
    } else {
      setMdDraft(page.content_md);
      setEditMode(true);
    }
  };

  const handleSaveDraft = async () => {
    try {
      const updated = await updateMutation.mutateAsync({ content_md: mdDraft });
      setMdDraft(updated.content_md);
      setEditMode(false);
    } catch {
      // Keep editMode & mdDraft intact on error
    }
  };

  const commitTitle = () => {
    setEditingTitle(false);
    const trimmed = titleDraft.trim();
    if (!trimmed || !page || trimmed === page.title) {
      if (page) setTitleDraft(page.title);
      return;
    }
    updateMutation.mutate({ title: trimmed });
  };

  if (pageQuery.isLoading) {
    return (
      <div
        className="h-full flex items-center justify-center text-[13px]"
        style={{ color: 'var(--text-muted)' }}
      >
        Loading page…
      </div>
    );
  }

  if (!page) {
    return (
      <div className="h-full flex flex-col items-center justify-center gap-3 p-6">
        <div className="text-[14px]" style={{ color: 'var(--text-secondary)' }}>
          Could not load this page.
        </div>
        <button
          type="button"
          onClick={() => setActivePageId(null)}
          className="px-3 py-1.5 rounded-lg text-[13px] font-medium"
          style={{
            backgroundColor: 'var(--bg-subtle)',
            color: 'var(--text-primary)',
          }}
        >
          Back to chat
        </button>
      </div>
    );
  }

  return (
    <div
      className="h-full flex flex-col gb-printable-page"
      style={{
        backgroundColor: 'var(--bg-canvas)',
        borderRight: '1px solid var(--border-subtle)',
      }}
    >
      {/* Top Toolbar */}
      <div
        className="h-13 px-4 flex items-center justify-between gap-2 shrink-0 gb-no-print"
        style={{ borderBottom: '1px solid var(--border-subtle)' }}
      >
        <div className="min-w-0 flex-1 flex items-center gap-2">
          {editingTitle ? (
            <input
              type="text"
              autoFocus
              value={titleDraft}
              onChange={(e) => setTitleDraft(e.target.value)}
              onBlur={commitTitle}
              onKeyDown={(e) => {
                if (e.key === 'Enter') commitTitle();
                if (e.key === 'Escape') {
                  setEditingTitle(false);
                  setTitleDraft(page.title);
                }
              }}
              className="px-2 py-1 text-[14.5px] font-semibold rounded-lg outline-none w-full max-w-md"
              style={{
                backgroundColor: 'var(--bg-sidebar)',
                border: '1px solid var(--border-strong)',
              }}
            />
          ) : (
            <button
              type="button"
              onClick={() => setEditingTitle(true)}
              title="Click to rename page"
              className="text-[14.5px] font-semibold tracking-tight truncate px-1.5 py-1 -ml-1.5 rounded-lg hover:bg-[var(--bg-subtle)] text-left"
              style={{ color: 'var(--text-primary)' }}
            >
              {page.title}
            </button>
          )}
          <span
            className="text-[11.5px] shrink-0 hidden md:inline"
            style={{ color: 'var(--text-muted)' }}
          >
            v{page.version} · {formatRelativeTime(page.updated_at)}
          </span>
        </div>

        <div className="flex items-center gap-1 shrink-0">
          <button
            type="button"
            onClick={() => {
              setSearchOpen((v) => !v);
              window.requestAnimationFrame(() => searchInputRef.current?.focus());
            }}
            title="Find in page (Cmd/Ctrl+F)"
            aria-label="Find in page"
            aria-pressed={searchOpen}
            className="p-1.5 rounded-lg hover:bg-[var(--bg-subtle)]"
            style={{
              backgroundColor: searchOpen ? 'var(--bg-active)' : 'transparent',
              color: 'var(--text-secondary)',
            }}
          >
            <Search size={15} strokeWidth={1.75} />
          </button>

          <button
            type="button"
            disabled={updateMutation.isPending}
            onClick={() => void handleToggleEditMode()}
            className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[12.5px] font-medium hover:bg-[var(--bg-subtle)] disabled:opacity-50"
            style={{
              backgroundColor: editMode ? 'var(--bg-active)' : 'transparent',
              color: 'var(--text-primary)',
            }}
          >
            {editMode ? (
              <>
                <Eye size={14} strokeWidth={1.75} />
                <span>{updateMutation.isPending ? 'Saving…' : 'Preview'}</span>
              </>
            ) : (
              <>
                <Edit3 size={14} strokeWidth={1.75} />
                <span>Edit</span>
              </>
            )}
          </button>

          <button
            type="button"
            onClick={() => pinMutation.mutate(!page.pinned)}
            disabled={pinMutation.isPending}
            title={page.pinned ? 'Unpin page' : 'Pin page'}
            aria-label={page.pinned ? 'Unpin page' : 'Pin page'}
            className="p-1.5 rounded-lg hover:bg-[var(--bg-subtle)] disabled:opacity-50"
            style={{
              color: page.pinned ? 'var(--accent-computer)' : 'var(--text-secondary)',
            }}
          >
            {page.pinned ? <PinOff size={15} strokeWidth={1.75} /> : <Pin size={15} strokeWidth={1.75} />}
          </button>

          {/* Share Scope */}
          <div className="relative inline-flex items-center">
            <span className="sr-only">Share scope</span>
            <select
              value={page.share_scope}
              onChange={(e) =>
                updateMutation.mutate({ share_scope: e.target.value as ShareScope })
              }
              aria-label="Share access"
              className="px-2 py-1.5 rounded-lg text-[12px] outline-none cursor-pointer"
              style={{
                backgroundColor: 'var(--bg-subtle)',
                color: 'var(--text-secondary)',
                border: '1px solid var(--border-subtle)',
              }}
            >
              <option value="private">Only you</option>
              <option value="team">Your team</option>
              <option value="public">Anyone with link</option>
            </select>
          </div>

          <button
            type="button"
            onClick={() =>
              downloadTextFile(
                `${page.title.toLowerCase().replace(/[^a-z0-9]+/g, '-') || 'page'}.md`,
                page.content_md,
              )
            }
            title="Export Markdown"
            aria-label="Export Markdown"
            className="p-1.5 rounded-lg hover:bg-[var(--bg-subtle)]"
            style={{ color: 'var(--text-secondary)' }}
          >
            <Download size={15} strokeWidth={1.75} />
          </button>

          <button
            type="button"
            onClick={() => window.print()}
            title="Print / Export PDF"
            aria-label="Print or export PDF"
            className="p-1.5 rounded-lg hover:bg-[var(--bg-subtle)]"
            style={{ color: 'var(--text-secondary)' }}
          >
            <Printer size={15} strokeWidth={1.75} />
          </button>

          <button
            type="button"
            onClick={() => requestNavigate(null)}
            title="Close split-screen page"
            aria-label="Close split-screen page"
            className="p-1.5 rounded-lg hover:bg-[var(--bg-subtle)]"
            style={{ color: 'var(--text-secondary)' }}
          >
            <X size={16} strokeWidth={1.75} />
          </button>
        </div>
      </div>

      {/* Optional In-Page Search Bar */}
      {searchOpen && (
        <div
          className="px-4 py-2 flex items-center gap-2 gb-no-print"
          style={{
            backgroundColor: 'var(--bg-sidebar)',
            borderBottom: '1px solid var(--border-subtle)',
          }}
        >
          <Search size={14} style={{ color: 'var(--text-muted)' }} />
          <input
            ref={searchInputRef}
            type="text"
            aria-label="Search inside this page"
            value={searchTerm}
            onChange={(e) => {
              setSearchTerm(e.target.value);
              setActiveMatchIdx(0);
            }}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.preventDefault();
                stepSearchMatch(e.shiftKey ? -1 : 1);
              } else if (e.key === 'Escape') {
                e.preventDefault();
                setSearchOpen(false);
                setSearchTerm('');
              }
            }}
            placeholder="Search inside this page…"
            className="flex-1 text-[13px] bg-transparent outline-none"
          />
          {searchTerm.trim() && (
            <>
              <span className="text-[12px] tabular-nums" style={{ color: 'var(--text-muted)' }}>
                {matchCount === 0
                  ? '0 matches'
                  : `${(activeMatchIdx % matchCount) + 1} / ${matchCount}`}
              </span>
              <button
                type="button"
                disabled={matchCount === 0}
                onClick={() => stepSearchMatch(-1)}
                aria-label="Previous match"
                title="Previous match (Shift+Enter)"
                className="p-1 rounded hover:bg-[var(--bg-subtle)] disabled:opacity-40"
                style={{ color: 'var(--text-secondary)' }}
              >
                <ChevronUp size={13.5} />
              </button>
              <button
                type="button"
                disabled={matchCount === 0}
                onClick={() => stepSearchMatch(1)}
                aria-label="Next match"
                title="Next match (Enter)"
                className="p-1 rounded hover:bg-[var(--bg-subtle)] disabled:opacity-40"
                style={{ color: 'var(--text-secondary)' }}
              >
                <ChevronDown size={13.5} />
              </button>
            </>
          )}
          <button
            type="button"
            aria-label="Close search"
            onClick={() => {
              setSearchOpen(false);
              setSearchTerm('');
            }}
            className="p-1 rounded hover:bg-[var(--bg-subtle)]"
            style={{ color: 'var(--text-muted)' }}
          >
            <X size={13.5} />
          </button>
        </div>
      )}

      {/* Unsaved Draft Confirmation (Internal navigation) */}
      {pendingNavTarget !== undefined && (
        <div
          className="px-4 py-2.5 flex flex-wrap items-center justify-between gap-2 gb-no-print text-[12.5px]"
          style={{
            backgroundColor: 'var(--status-warn-bg)',
            borderBottom: '1px solid rgba(217, 119, 6, 0.25)',
            color: 'var(--text-primary)',
          }}
        >
          <div className="flex items-center gap-2">
            <AlertTriangle size={14} style={{ color: 'var(--status-warn)' }} />
            <span>You have unsaved changes in this page.</span>
          </div>
          <div className="flex items-center gap-1.5">
            <button
              type="button"
              disabled={updateMutation.isPending}
              onClick={async () => {
                try {
                  await updateMutation.mutateAsync({ content_md: mdDraft });
                  const dest = pendingNavTarget;
                  latestSnapshotRef.current.dirty = false;
                  setPendingNavTarget(undefined);
                  setEditMode(false);
                  setActivePageId(dest ?? null);
                } catch {
                  // Stay here on error
                }
              }}
              className="px-2.5 py-1 rounded-lg text-[12px] font-medium"
              style={{
                backgroundColor: 'var(--accent-primary)',
                color: 'var(--bg-canvas)',
              }}
            >
              Save &amp; leave
            </button>
            <button
              type="button"
              onClick={() => {
                const dest = pendingNavTarget;
                latestSnapshotRef.current.dirty = false;
                setMdDraft(page.content_md);
                setEditMode(false);
                setPendingNavTarget(undefined);
                setActivePageId(dest ?? null);
              }}
              className="px-2.5 py-1 rounded-lg text-[12px]"
              style={{
                backgroundColor: 'var(--bg-canvas)',
                border: '1px solid var(--border-strong)',
              }}
            >
              Discard
            </button>
            <button
              type="button"
              onClick={() => setPendingNavTarget(undefined)}
              className="px-2 py-1 rounded-lg text-[12px]"
              style={{ color: 'var(--text-secondary)' }}
            >
              Keep editing
            </button>
          </div>
        </div>
      )}

      {/* Stashed Draft Recovery Banner (if external pageId changed while dirty) */}
      {stashedDraft && stashedDraft.pageId !== page.id && (
        <div
          className="px-4 py-2 flex flex-wrap items-center justify-between gap-2 gb-no-print text-[12px]"
          style={{
            backgroundColor: 'var(--status-warn-bg)',
            borderBottom: '1px solid rgba(217, 119, 6, 0.25)',
            color: 'var(--text-primary)',
          }}
        >
          <span>
            Unsaved draft stashed from <strong>{stashedDraft.title}</strong>.
          </span>
          <div className="flex items-center gap-1.5">
            <button
              type="button"
              onClick={() => setActivePageId(stashedDraft.pageId)}
              className="px-2.5 py-1 rounded-lg font-medium"
              style={{
                backgroundColor: 'var(--bg-canvas)',
                border: '1px solid var(--border-strong)',
              }}
            >
              Restore &amp; return
            </button>
            <button
              type="button"
              onClick={() => setStashedDraft(null)}
              className="px-2 py-1 rounded-lg"
              style={{ color: 'var(--text-secondary)' }}
            >
              Dismiss
            </button>
          </div>
        </div>
      )}

      {/* Main Page Body */}
      <div className="flex-1 overflow-y-auto px-6 sm:px-10 py-7">
        <div className="max-w-[740px] mx-auto">
          {/* Superseded Version Banner */}
          {page.superseded_by_id && (
            <div
              className="mb-4 px-3.5 py-2.5 rounded-xl flex flex-wrap items-center justify-between gap-2 text-[12.5px] gb-no-print"
              style={{
                backgroundColor: 'var(--accent-computer-tint)',
                border: '1px solid rgba(124, 58, 237, 0.25)',
                color: 'var(--text-primary)',
              }}
            >
              <span>A newer version of this page is available.</span>
              <button
                type="button"
                onClick={() => requestNavigate(page.superseded_by_id)}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[12px] font-semibold"
                style={{
                  backgroundColor: 'var(--bg-canvas)',
                  color: 'var(--accent-computer)',
                  border: '1px solid rgba(124, 58, 237, 0.3)',
                }}
              >
                <span>View latest version</span>
                <ArrowRight size={13} />
              </button>
            </div>
          )}

          {/* Scope subtitle pill */}
          <div
            className="inline-flex items-center gap-1.5 text-[11.5px] mb-4 px-2.5 py-0.5 rounded-full gb-no-print"
            style={{ backgroundColor: 'var(--bg-subtle)', color: 'var(--text-secondary)' }}
          >
            {page.share_scope === 'private' ? (
              <Lock size={11.5} />
            ) : page.share_scope === 'team' ? (
              <Users size={11.5} />
            ) : (
              <Globe size={11.5} />
            )}
            <span>
              {page.share_scope === 'private'
                ? 'Private to you'
                : page.share_scope === 'team'
                  ? 'Shared with your team'
                  : 'Anyone with link'}
            </span>
          </div>

          {editMode ? (
            <div className="space-y-3">
              <textarea
                aria-label="Page Markdown editor"
                value={mdDraft}
                onChange={(e) => setMdDraft(e.target.value)}
                rows={20}
                className="w-full p-4 rounded-xl text-[13.5px] font-mono leading-relaxed outline-none resize-y"
                style={{
                  backgroundColor: 'var(--bg-sidebar)',
                  border: '1px solid var(--border-strong)',
                  color: 'var(--text-primary)',
                }}
              />
              <div className="flex items-center justify-end gap-2">
                <button
                  type="button"
                  onClick={() => {
                    setMdDraft(page.content_md);
                    setEditMode(false);
                  }}
                  className="px-3 py-1.5 rounded-lg text-[12.5px] hover:bg-[var(--bg-subtle)]"
                  style={{ color: 'var(--text-secondary)' }}
                >
                  Cancel
                </button>
                <button
                  type="button"
                  disabled={updateMutation.isPending}
                  onClick={() => void handleSaveDraft()}
                  className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-[12.5px] font-medium disabled:opacity-50"
                  style={{
                    backgroundColor: 'var(--accent-primary)',
                    color: 'var(--bg-canvas)',
                  }}
                >
                  <Check size={14} strokeWidth={2.2} />
                  {updateMutation.isPending ? 'Saving…' : 'Save changes'}
                </button>
              </div>
            </div>
          ) : (
            <div key={`${page.id}:${page.version}:${page.content_md}`} ref={contentRef}>
              <MarkdownRenderer content={page.content_md} />
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
