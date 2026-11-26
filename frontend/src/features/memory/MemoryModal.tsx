import React, { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle,
  Database,
  Download,
  Edit3,
  Loader2,
  Plus,
  RefreshCw,
  Search,
  Trash2,
  X,
} from 'lucide-react';
import { Modal } from '../../components/Modal';
import { ApiError, apiFetch, memoryApi } from '../../lib/api';
import { downloadTextFile, formatRelativeTime } from '../../lib/markdown';
import type {
  MemoryItem,
  MemoryKind,
  MemoryProvenance,
  MemoryScope,
  RosterResponse,
} from '../../lib/types';
import { useUiStore } from '../../stores/uiStore';

const SCOPES: { id: MemoryScope; label: string }[] = [
  { id: 'user', label: 'User' },
  { id: 'agent_role', label: 'Agent role' },
  { id: 'thread', label: 'Thread' },
  { id: 'project_area', label: 'Project area' },
  { id: 'org_approved', label: 'Org approved' },
];

const KINDS: { id: MemoryKind; label: string }[] = [
  { id: 'preference', label: 'Preference' },
  { id: 'approved_procedure', label: 'Approved procedure' },
  { id: 'dated_observation', label: 'Dated observation' },
  { id: 'source_reference', label: 'Source reference' },
];

const PROVENANCES: MemoryProvenance[] = ['operator', 'agent', 'system', 'untrusted'];

interface EditingState {
  id: string;
  scope: MemoryScope;
  scope_id: string;
  revision: number;
  title: string;
  content: string;
  valid_until: string;
}

function buildScopeAclQuery(
  scope: MemoryScope,
  scopeId: string,
  actorRole: string,
): string {
  const params = new URLSearchParams();
  const trimmedId = scopeId.trim();
  if (scope === 'user' && trimmedId) {
    params.set('user_id', trimmedId);
  } else if (scope === 'agent_role' && trimmedId) {
    params.set('agent_role', trimmedId);
  } else if (scope === 'thread' && trimmedId) {
    params.set('thread_id', trimmedId);
  } else if (scope === 'project_area' && trimmedId) {
    params.set('project_area', trimmedId);
  } else {
    params.set('user_id', 'operator');
  }
  if (actorRole.trim()) {
    params.set('actor_role', actorRole.trim());
  }
  return params.toString();
}

function defaultScopeIdFor(
  scope: MemoryScope,
  ctx: { threadId?: string; botId?: string; projectName?: string | null },
): string {
  switch (scope) {
    case 'user':
      return 'operator';
    case 'thread':
      return ctx.threadId || 'default';
    case 'agent_role':
      return ctx.botId || 'default';
    case 'project_area':
      return ctx.projectName || 'default';
    case 'org_approved':
      return 'default';
  }
}

export function MemoryModal(): React.JSX.Element | null {
  const queryClient = useQueryClient();
  const open = useUiStore((s) => s.memoryOpen);
  const setOpen = useUiStore((s) => s.setMemoryOpen);
  const activeTarget = useUiStore((s) => s.activeTarget);
  const pushToast = useUiStore((s) => s.pushToast);

  // Filters & ACL role
  const [scopeFilter, setScopeFilter] = useState<MemoryScope | ''>('');
  const [kindFilter, setKindFilter] = useState<MemoryKind | ''>('');
  const [scopeIdFilter, setScopeIdFilter] = useState('');
  const [searchQuery, setSearchQuery] = useState('');
  const [includeExpired, setIncludeExpired] = useState(false);
  const [actorRole, setActorRole] = useState<'Operator' | 'Manager'>('Operator');

  // Create form state
  const [createOpen, setCreateOpen] = useState(false);
  const [newScope, setNewScope] = useState<MemoryScope>('user');
  const [newScopeId, setNewScopeId] = useState('operator');
  const [newKind, setNewKind] = useState<MemoryKind>('preference');
  const [newTitle, setNewTitle] = useState('');
  const [newContent, setNewContent] = useState('');
  const [newObservedAt, setNewObservedAt] = useState('');
  const [newValidUntil, setNewValidUntil] = useState('');
  const [newProvenance, setNewProvenance] = useState<MemoryProvenance>('operator');

  // Edit + 409 conflict state
  const [editing, setEditing] = useState<EditingState | null>(null);
  const [conflictError, setConflictError] = useState<string | null>(null);
  const [reloadingConflict, setReloadingConflict] = useState(false);
  const [exporting, setExporting] = useState<'md' | 'json' | null>(null);

  // Resolve active ACL context from UI store & cached roster
  const roster = queryClient.getQueryData<RosterResponse>(['roster']);
  const activeBot = useMemo(() => {
    if (!roster || activeTarget?.kind !== 'bot') return undefined;
    return roster.bots.find((b) => b.id === activeTarget.id);
  }, [roster, activeTarget]);

  const activeThreadId = activeTarget?.threadId;
  const activeAgentRole = activeBot?.id;
  const activeProjectArea = activeBot?.project_name ?? undefined;

  const listParams = useMemo(() => {
    const trimmedScopeId = scopeIdFilter.trim();
    return {
      scope: scopeFilter || undefined,
      scope_id: trimmedScopeId || undefined,
      kind: kindFilter || undefined,
      q: searchQuery.trim() || undefined,
      include_expired: includeExpired,
      actor_role: actorRole,
      user_id: scopeFilter === 'user' && trimmedScopeId ? trimmedScopeId : 'operator',
      thread_id:
        scopeFilter === 'thread'
          ? trimmedScopeId || activeThreadId || 'default'
          : activeThreadId,
      agent_role:
        scopeFilter === 'agent_role'
          ? trimmedScopeId || activeAgentRole || 'default'
          : activeAgentRole,
      project_area:
        scopeFilter === 'project_area'
          ? trimmedScopeId || activeProjectArea || 'default'
          : activeProjectArea,
    };
  }, [
    scopeFilter,
    scopeIdFilter,
    kindFilter,
    searchQuery,
    includeExpired,
    actorRole,
    activeThreadId,
    activeAgentRole,
    activeProjectArea,
  ]);

  const memoryQuery = useQuery({
    queryKey: ['memory', listParams],
    queryFn: () => memoryApi.list(listParams),
    enabled: open,
  });

  const createMutation = useMutation({
    mutationFn: () => {
      const observedAt =
        newObservedAt.trim() ||
        (newKind === 'dated_observation' ? new Date().toISOString() : '');
      const validUntil = newValidUntil.trim();
      const resolvedScopeId =
        newScopeId.trim() ||
        defaultScopeIdFor(newScope, {
          threadId: activeThreadId,
          botId: activeAgentRole,
          projectName: activeProjectArea,
        });
      const aclQuery = buildScopeAclQuery(newScope, resolvedScopeId, actorRole);
      return apiFetch<MemoryItem>(`/api/v1/memory?${aclQuery}`, {
        method: 'POST',
        body: JSON.stringify({
          scope: newScope,
          scope_id: resolvedScopeId,
          kind: newKind,
          title: newTitle.trim(),
          content: newContent.trim(),
          observed_at: observedAt || null,
          valid_until: validUntil || null,
          provenance: newProvenance,
          actor_role: actorRole,
        }),
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['memory'] });
      setNewTitle('');
      setNewContent('');
      setNewObservedAt('');
      setNewValidUntil('');
      setCreateOpen(false);
      pushToast({ tone: 'success', title: 'Memory saved' });
    },
    onError: (err: Error) => {
      pushToast({
        tone: 'error',
        title: 'Could not create memory',
        description: err.message,
      });
    },
  });

  const updateMutation = useMutation({
    mutationFn: (state: EditingState) => {
      const aclQuery = buildScopeAclQuery(state.scope, state.scope_id, actorRole);
      return apiFetch<MemoryItem>(
        `/api/v1/memory/${encodeURIComponent(state.id)}?${aclQuery}`,
        {
          method: 'PATCH',
          body: JSON.stringify({
            revision: state.revision,
            title: state.title.trim(),
            content: state.content.trim(),
            valid_until: state.valid_until.trim() || null,
            actor_role: actorRole,
          }),
        },
      );
    },
    onSuccess: (updated) => {
      setConflictError(null);
      setEditing(null);
      void queryClient.invalidateQueries({ queryKey: ['memory'] });
      pushToast({
        tone: 'success',
        title: `Memory updated (rev ${updated.revision})`,
      });
    },
    onError: (err: Error) => {
      if (err instanceof ApiError && err.status === 409) {
        setConflictError(
          err.detail ||
            'Revision conflict: this memory was modified elsewhere. Reload latest before saving.',
        );
        return;
      }
      pushToast({
        tone: 'error',
        title: 'Could not update memory',
        description: err.message,
      });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (item: Pick<MemoryItem, 'id' | 'scope' | 'scope_id'>) => {
      const aclQuery = buildScopeAclQuery(item.scope, item.scope_id, actorRole);
      return apiFetch<{ deleted: boolean; id?: string }>(
        `/api/v1/memory/${encodeURIComponent(item.id)}?${aclQuery}`,
        { method: 'DELETE' },
      );
    },
    onSuccess: (_res, item) => {
      if (editing?.id === item.id) {
        setEditing(null);
        setConflictError(null);
      }
      void queryClient.invalidateQueries({ queryKey: ['memory'] });
      pushToast({ tone: 'info', title: 'Memory deleted' });
    },
    onError: (err: Error) => {
      pushToast({
        tone: 'error',
        title: 'Could not delete memory',
        description: err.message,
      });
    },
  });

  const handleReloadLatest = async () => {
    if (!editing) return;
    setReloadingConflict(true);
    try {
      const refetched = await memoryQuery.refetch({ throwOnError: true });
      let latest = refetched.data?.items.find((it) => it.id === editing.id);
      if (!latest) {
        const fallbackParams = new URLSearchParams(
          buildScopeAclQuery(editing.scope, editing.scope_id, actorRole),
        );
        fallbackParams.set('scope', editing.scope);
        fallbackParams.set('scope_id', editing.scope_id);
        fallbackParams.set('include_expired', 'true');
        const fallback = await apiFetch<{ items: MemoryItem[] }>(
          `/api/v1/memory?${fallbackParams.toString()}`,
        );
        latest = fallback.items.find((it) => it.id === editing.id);
      }
      if (!latest) {
        setConflictError(null);
        setEditing(null);
        pushToast({
          tone: 'warn',
          title: 'Memory item no longer exists',
          description: 'It may have been deleted in another session.',
        });
        return;
      }
      setEditing({
        id: latest.id,
        scope: latest.scope,
        scope_id: latest.scope_id,
        revision: latest.revision,
        title: latest.title,
        content: latest.content,
        valid_until: latest.valid_until ?? '',
      });
      setConflictError(null);
      pushToast({
        tone: 'info',
        title: `Reloaded revision ${latest.revision}`,
      });
    } catch (err) {
      pushToast({
        tone: 'error',
        title: 'Could not reload latest memory',
        description: err instanceof Error ? err.message : 'Request failed',
      });
    } finally {
      setReloadingConflict(false);
    }
  };

  const handleExport = async (format: 'md' | 'json') => {
    setExporting(format);
    try {
      const params = new URLSearchParams();
      params.set('format', format);
      if (listParams.scope) params.set('scope', listParams.scope);
      if (listParams.scope_id) params.set('scope_id', listParams.scope_id);
      if (listParams.kind) params.set('kind', listParams.kind);
      if (listParams.q) params.set('q', listParams.q);
      if (listParams.include_expired) params.set('include_expired', 'true');
      if (listParams.user_id) params.set('user_id', listParams.user_id);
      if (listParams.actor_role) params.set('actor_role', listParams.actor_role);
      if (listParams.agent_role) params.set('agent_role', listParams.agent_role);
      if (listParams.thread_id) params.set('thread_id', listParams.thread_id);
      if (listParams.project_area) params.set('project_area', listParams.project_area);
      const data = await apiFetch<string | { items: MemoryItem[] }>(
        `/api/v1/memory/export?${params.toString()}`,
      );
      if (format === 'md') {
        const text = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
        downloadTextFile('memory_export.md', text, 'text/markdown;charset=utf-8');
      } else {
        const text = typeof data === 'string' ? data : JSON.stringify(data, null, 2);
        downloadTextFile('memory_export.json', text, 'application/json;charset=utf-8');
      }
      pushToast({
        tone: 'success',
        title: `Exported memory (${format.toUpperCase()})`,
      });
    } catch (err) {
      pushToast({
        tone: 'error',
        title: `Export (${format.toUpperCase()}) failed`,
        description: err instanceof Error ? err.message : 'Request failed',
      });
    } finally {
      setExporting(null);
    }
  };

  const handleOpenCreate = () => {
    setCreateOpen((v) => !v);
    setNewScopeId(
      defaultScopeIdFor(newScope, {
        threadId: activeThreadId,
        botId: activeAgentRole,
        projectName: activeProjectArea,
      }),
    );
  };

  const items: MemoryItem[] = memoryQuery.data?.items ?? [];

  return (
    <Modal
      open={open}
      onClose={() => setOpen(false)}
      title="Memory Browser & Governance"
      subtitle="Compartmentalized ACL scopes, TTL expiration, and optimistic revision locking"
      maxWidthClass="max-w-4xl"
    >
      <div className="p-4 sm:p-5 space-y-4">
        {/* Top Toolbar: Role, Export, New Memory */}
        <div className="flex flex-wrap items-center justify-between gap-2">
          <div className="flex flex-wrap items-center gap-2">
            <label className="inline-flex items-center gap-1.5 text-[12px]">
              <span style={{ color: 'var(--text-secondary)' }}>Actor role:</span>
              <select
                aria-label="Actor role"
                value={actorRole}
                onChange={(e) => setActorRole(e.target.value as 'Operator' | 'Manager')}
                className="px-2 py-1 rounded-lg text-[12px] outline-none"
                style={{
                  backgroundColor: 'var(--bg-sidebar)',
                  border: '1px solid var(--border-strong)',
                  color: 'var(--text-primary)',
                }}
              >
                <option value="Operator">Operator</option>
                <option value="Manager">Manager</option>
              </select>
            </label>

            <label className="inline-flex items-center gap-1.5 text-[12px] cursor-pointer">
              <input
                type="checkbox"
                checked={includeExpired}
                onChange={(e) => setIncludeExpired(e.target.checked)}
              />
              <span style={{ color: 'var(--text-secondary)' }}>Include expired</span>
            </label>
          </div>

          <div className="flex flex-wrap items-center gap-1.5">
            <button
              type="button"
              disabled={exporting !== null}
              onClick={() => void handleExport('md')}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[12px] font-medium hover:bg-[var(--bg-subtle)] disabled:opacity-50"
              style={{
                backgroundColor: 'var(--bg-sidebar)',
                border: '1px solid var(--border-subtle)',
                color: 'var(--text-secondary)',
              }}
            >
              {exporting === 'md' ? (
                <Loader2 size={13} className="animate-spin" />
              ) : (
                <Download size={13} />
              )}
              <span>Export MD</span>
            </button>

            <button
              type="button"
              disabled={exporting !== null}
              onClick={() => void handleExport('json')}
              className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[12px] font-medium hover:bg-[var(--bg-subtle)] disabled:opacity-50"
              style={{
                backgroundColor: 'var(--bg-sidebar)',
                border: '1px solid var(--border-subtle)',
                color: 'var(--text-secondary)',
              }}
            >
              {exporting === 'json' ? (
                <Loader2 size={13} className="animate-spin" />
              ) : (
                <Download size={13} />
              )}
              <span>Export JSON</span>
            </button>

            <button
              type="button"
              onClick={handleOpenCreate}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-medium"
              style={{
                backgroundColor: 'var(--accent-primary)',
                color: 'var(--bg-canvas)',
              }}
            >
              {createOpen ? <X size={13.5} /> : <Plus size={13.5} />}
              <span>{createOpen ? 'Cancel' : 'New memory'}</span>
            </button>
          </div>
        </div>

        {/* Filter Controls */}
        <div
          className="p-3 rounded-xl grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2.5"
          style={{
            backgroundColor: 'var(--bg-sidebar)',
            border: '1px solid var(--border-subtle)',
          }}
        >
          <select
            aria-label="Filter by ACL scope"
            value={scopeFilter}
            onChange={(e) => setScopeFilter(e.target.value as MemoryScope | '')}
            className="px-2.5 py-1.5 rounded-lg text-[12.5px] outline-none"
            style={{
              backgroundColor: 'var(--bg-canvas)',
              border: '1px solid var(--border-strong)',
              color: 'var(--text-primary)',
            }}
          >
            <option value="">All scopes</option>
            {SCOPES.map((s) => (
              <option key={s.id} value={s.id}>
                Scope: {s.label}
              </option>
            ))}
          </select>

          <select
            aria-label="Filter by memory kind"
            value={kindFilter}
            onChange={(e) => setKindFilter(e.target.value as MemoryKind | '')}
            className="px-2.5 py-1.5 rounded-lg text-[12.5px] outline-none"
            style={{
              backgroundColor: 'var(--bg-canvas)',
              border: '1px solid var(--border-strong)',
              color: 'var(--text-primary)',
            }}
          >
            <option value="">All kinds</option>
            {KINDS.map((k) => (
              <option key={k.id} value={k.id}>
                Kind: {k.label}
              </option>
            ))}
          </select>

          <input
            type="text"
            aria-label="Filter by scope ID"
            value={scopeIdFilter}
            onChange={(e) => setScopeIdFilter(e.target.value)}
            placeholder="Scope ID (e.g. operator)"
            className="px-2.5 py-1.5 rounded-lg text-[12.5px] outline-none"
            style={{
              backgroundColor: 'var(--bg-canvas)',
              border: '1px solid var(--border-strong)',
              color: 'var(--text-primary)',
            }}
          />

          <div
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg"
            style={{
              backgroundColor: 'var(--bg-canvas)',
              border: '1px solid var(--border-strong)',
            }}
          >
            <Search size={13.5} style={{ color: 'var(--text-muted)' }} />
            <input
              type="text"
              aria-label="Search memories"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="FTS5 search…"
              className="w-full text-[12.5px] bg-transparent outline-none"
            />
          </div>
        </div>

        {/* Create Memory Form */}
        {createOpen && (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (!newTitle.trim() || !newContent.trim()) {
                pushToast({
                  tone: 'warn',
                  title: 'Title and content are required',
                });
                return;
              }
              if (newKind === 'dated_observation' && !newValidUntil.trim()) {
                pushToast({
                  tone: 'warn',
                  title: 'valid_until is required for dated observations',
                  description: 'Provide an ISO-8601 timestamp (e.g. 2026-12-31T23:59:59Z).',
                });
                return;
              }
              createMutation.mutate();
            }}
            className="p-3.5 rounded-xl space-y-3"
            style={{
              backgroundColor: 'var(--bg-sidebar)',
              border: '1px solid var(--border-strong)',
            }}
          >
            <div className="text-[13px] font-semibold" style={{ color: 'var(--text-primary)' }}>
              Create Memory Item
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-4 gap-2.5">
              <label className="space-y-1 text-[11.5px]">
                <span style={{ color: 'var(--text-muted)' }}>ACL Scope</span>
                <select
                  value={newScope}
                  onChange={(e) => {
                    const next = e.target.value as MemoryScope;
                    setNewScope(next);
                    setNewScopeId(
                      defaultScopeIdFor(next, {
                        threadId: activeThreadId,
                        botId: activeAgentRole,
                        projectName: activeProjectArea,
                      }),
                    );
                  }}
                  className="w-full px-2.5 py-1.5 rounded-lg text-[12.5px] outline-none"
                  style={{
                    backgroundColor: 'var(--bg-canvas)',
                    border: '1px solid var(--border-strong)',
                  }}
                >
                  {SCOPES.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.label}
                    </option>
                  ))}
                </select>
              </label>

              <label className="space-y-1 text-[11.5px]">
                <span style={{ color: 'var(--text-muted)' }}>Scope ID</span>
                <input
                  type="text"
                  value={newScopeId}
                  onChange={(e) => setNewScopeId(e.target.value)}
                  placeholder="operator"
                  required
                  className="w-full px-2.5 py-1.5 rounded-lg text-[12.5px] outline-none"
                  style={{
                    backgroundColor: 'var(--bg-canvas)',
                    border: '1px solid var(--border-strong)',
                  }}
                />
              </label>

              <label className="space-y-1 text-[11.5px]">
                <span style={{ color: 'var(--text-muted)' }}>Kind</span>
                <select
                  value={newKind}
                  onChange={(e) => setNewKind(e.target.value as MemoryKind)}
                  className="w-full px-2.5 py-1.5 rounded-lg text-[12.5px] outline-none"
                  style={{
                    backgroundColor: 'var(--bg-canvas)',
                    border: '1px solid var(--border-strong)',
                  }}
                >
                  {KINDS.map((k) => (
                    <option key={k.id} value={k.id}>
                      {k.label}
                    </option>
                  ))}
                </select>
              </label>

              <label className="space-y-1 text-[11.5px]">
                <span style={{ color: 'var(--text-muted)' }}>Provenance</span>
                <select
                  value={newProvenance}
                  onChange={(e) => setNewProvenance(e.target.value)}
                  className="w-full px-2.5 py-1.5 rounded-lg text-[12.5px] outline-none"
                  style={{
                    backgroundColor: 'var(--bg-canvas)',
                    border: '1px solid var(--border-strong)',
                  }}
                >
                  {PROVENANCES.map((p) => (
                    <option key={p} value={p}>
                      {p}
                    </option>
                  ))}
                </select>
              </label>
            </div>

            {newKind === 'approved_procedure' && actorRole !== 'Manager' && (
              <div
                className="px-2.5 py-1.5 rounded-lg text-[11.5px]"
                style={{
                  backgroundColor: 'var(--status-warn-bg)',
                  color: 'var(--status-warn)',
                }}
              >
                Note: Creating an approved_procedure requires Manager actor role (server enforces 403 for Operator).
              </div>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
              <label className="space-y-1 text-[11.5px] sm:col-span-1">
                <span style={{ color: 'var(--text-muted)' }}>Title</span>
                <input
                  type="text"
                  value={newTitle}
                  onChange={(e) => setNewTitle(e.target.value)}
                  placeholder="Concise memory title"
                  required
                  className="w-full px-2.5 py-1.5 rounded-lg text-[12.5px] outline-none"
                  style={{
                    backgroundColor: 'var(--bg-canvas)',
                    border: '1px solid var(--border-strong)',
                  }}
                />
              </label>

              <label className="space-y-1 text-[11.5px]">
                <span style={{ color: 'var(--text-muted)' }}>
                  Observed at (ISO-8601{newKind === 'dated_observation' ? ', auto if blank' : ', optional'})
                </span>
                <input
                  type="text"
                  value={newObservedAt}
                  onChange={(e) => setNewObservedAt(e.target.value)}
                  placeholder="2026-11-26T09:00:00Z"
                  className="w-full px-2.5 py-1.5 rounded-lg text-[12.5px] outline-none font-mono"
                  style={{
                    backgroundColor: 'var(--bg-canvas)',
                    border: '1px solid var(--border-strong)',
                  }}
                />
              </label>

              <label className="space-y-1 text-[11.5px]">
                <span style={{ color: 'var(--text-muted)' }}>
                  Valid until (ISO-8601{newKind === 'dated_observation' ? ', required' : ', optional'})
                </span>
                <input
                  type="text"
                  value={newValidUntil}
                  onChange={(e) => setNewValidUntil(e.target.value)}
                  placeholder="2026-12-31T23:59:59Z"
                  className="w-full px-2.5 py-1.5 rounded-lg text-[12.5px] outline-none font-mono"
                  style={{
                    backgroundColor: 'var(--bg-canvas)',
                    border: '1px solid var(--border-strong)',
                  }}
                />
              </label>
            </div>

            <label className="block space-y-1 text-[11.5px]">
              <span style={{ color: 'var(--text-muted)' }}>Content</span>
              <textarea
                rows={3}
                value={newContent}
                onChange={(e) => setNewContent(e.target.value)}
                placeholder="Memory fact, preference, or procedure…"
                required
                className="w-full px-2.5 py-1.5 rounded-lg text-[12.5px] outline-none resize-y"
                style={{
                  backgroundColor: 'var(--bg-canvas)',
                  border: '1px solid var(--border-strong)',
                }}
              />
            </label>

            <div className="flex justify-end gap-2">
              <button
                type="submit"
                disabled={createMutation.isPending}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12.5px] font-medium disabled:opacity-50"
                style={{
                  backgroundColor: 'var(--accent-primary)',
                  color: 'var(--bg-canvas)',
                }}
              >
                {createMutation.isPending && <Loader2 size={13} className="animate-spin" />}
                <span>Save memory</span>
              </button>
            </div>
          </form>
        )}

        {/* Inline Editor (with HTTP 409 Conflict Banner + Reload Latest) */}
        {editing && (
          <div
            className="p-3.5 rounded-xl space-y-3"
            style={{
              backgroundColor: 'var(--bg-sidebar)',
              border: '1px solid var(--border-strong)',
            }}
          >
            <div className="flex items-center justify-between">
              <div className="text-[13px] font-semibold" style={{ color: 'var(--text-primary)' }}>
                Edit Memory · <span className="font-mono text-[11.5px]">rev {editing.revision}</span>
              </div>
              <button
                type="button"
                aria-label="Close editor"
                onClick={() => {
                  setEditing(null);
                  setConflictError(null);
                }}
                className="p-1 rounded hover:bg-[var(--bg-subtle)]"
              >
                <X size={14} />
              </button>
            </div>

            {conflictError && (
              <div
                role="alert"
                className="flex flex-wrap items-center justify-between gap-2 px-3 py-2 rounded-lg text-[12px]"
                style={{
                  backgroundColor: 'var(--status-danger-bg)',
                  color: 'var(--status-danger)',
                  border: '1px solid rgba(220, 38, 38, 0.28)',
                }}
              >
                <div className="flex items-start gap-2 min-w-0 flex-1">
                  <AlertTriangle size={14} className="shrink-0 mt-0.5" />
                  <span>{conflictError}</span>
                </div>
                <button
                  type="button"
                  disabled={reloadingConflict}
                  onClick={() => void handleReloadLatest()}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11.5px] font-semibold"
                  style={{
                    backgroundColor: 'var(--bg-canvas)',
                    color: 'var(--text-primary)',
                    border: '1px solid var(--border-strong)',
                  }}
                >
                  {reloadingConflict ? (
                    <Loader2 size={12} className="animate-spin" />
                  ) : (
                    <RefreshCw size={12} />
                  )}
                  <span>Reload latest</span>
                </button>
              </div>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
              <label className="space-y-1 text-[11.5px]">
                <span style={{ color: 'var(--text-muted)' }}>Title</span>
                <input
                  type="text"
                  value={editing.title}
                  onChange={(e) => setEditing({ ...editing, title: e.target.value })}
                  className="w-full px-2.5 py-1.5 rounded-lg text-[12.5px] outline-none"
                  style={{
                    backgroundColor: 'var(--bg-canvas)',
                    border: '1px solid var(--border-strong)',
                  }}
                />
              </label>

              <label className="space-y-1 text-[11.5px]">
                <span style={{ color: 'var(--text-muted)' }}>Valid until (ISO-8601, optional)</span>
                <input
                  type="text"
                  value={editing.valid_until}
                  onChange={(e) => setEditing({ ...editing, valid_until: e.target.value })}
                  placeholder="2026-12-31T23:59:59Z"
                  className="w-full px-2.5 py-1.5 rounded-lg text-[12.5px] outline-none font-mono"
                  style={{
                    backgroundColor: 'var(--bg-canvas)',
                    border: '1px solid var(--border-strong)',
                  }}
                />
              </label>
            </div>

            <label className="block space-y-1 text-[11.5px]">
              <span style={{ color: 'var(--text-muted)' }}>Content</span>
              <textarea
                rows={4}
                value={editing.content}
                onChange={(e) => setEditing({ ...editing, content: e.target.value })}
                className="w-full px-2.5 py-1.5 rounded-lg text-[12.5px] outline-none resize-y"
                style={{
                  backgroundColor: 'var(--bg-canvas)',
                  border: '1px solid var(--border-strong)',
                }}
              />
            </label>

            <div className="flex justify-end gap-2">
              <button
                type="button"
                onClick={() => {
                  setEditing(null);
                  setConflictError(null);
                }}
                className="px-3 py-1.5 rounded-lg text-[12px] hover:bg-[var(--bg-subtle)]"
                style={{ color: 'var(--text-secondary)' }}
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={updateMutation.isPending}
                onClick={() => updateMutation.mutate(editing)}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-medium disabled:opacity-50"
                style={{
                  backgroundColor: 'var(--accent-primary)',
                  color: 'var(--bg-canvas)',
                }}
              >
                {updateMutation.isPending && <Loader2 size={12.5} className="animate-spin" />}
                <span>Save changes</span>
              </button>
            </div>
          </div>
        )}

        {/* Memory List */}
        {memoryQuery.isLoading ? (
          <div className="py-10 text-center text-[13px]" style={{ color: 'var(--text-muted)' }}>
            Loading memory items…
          </div>
        ) : memoryQuery.isError ? (
          <div
            className="p-3.5 rounded-xl text-[12.5px] flex items-center justify-between gap-3"
            style={{
              backgroundColor: 'var(--status-danger-bg)',
              color: 'var(--status-danger)',
              border: '1px solid rgba(220, 38, 38, 0.22)',
            }}
          >
            <span>
              Could not load memory items:{' '}
              {memoryQuery.error instanceof Error ? memoryQuery.error.message : 'Request failed'}
            </span>
            <button
              type="button"
              onClick={() => void memoryQuery.refetch()}
              className="px-2.5 py-1 rounded-lg text-[12px] font-medium"
              style={{
                backgroundColor: 'var(--bg-canvas)',
                color: 'var(--text-primary)',
                border: '1px solid var(--border-strong)',
              }}
            >
              Retry
            </button>
          </div>
        ) : items.length === 0 ? (
          <div className="py-10 text-center space-y-1.5">
            <Database size={20} className="mx-auto" style={{ color: 'var(--text-muted)' }} />
            <div className="text-[13px] font-medium" style={{ color: 'var(--text-secondary)' }}>
              No memory items match the current ACL &amp; search filters
            </div>
            <div className="text-[12px]" style={{ color: 'var(--text-muted)' }}>
              Adjust scope filters or create a new memory item above.
            </div>
          </div>
        ) : (
          <div className="space-y-2">
            {items.map((item) => (
              <div
                key={item.id}
                className="p-3 rounded-xl space-y-1.5"
                style={{
                  backgroundColor: 'var(--bg-canvas)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0 flex-1 space-y-1">
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span
                        className="text-[13px] font-semibold"
                        style={{ color: 'var(--text-primary)' }}
                      >
                        {item.title}
                      </span>
                      <span
                        className="px-1.5 py-0.5 rounded text-[10.5px] font-mono"
                        style={{
                          backgroundColor: 'var(--bg-subtle)',
                          color: 'var(--text-secondary)',
                        }}
                      >
                        {item.scope}:{item.scope_id}
                      </span>
                      <span
                        className="px-1.5 py-0.5 rounded text-[10.5px]"
                        style={{
                          backgroundColor: 'var(--accent-computer-tint)',
                          color: 'var(--accent-computer)',
                        }}
                      >
                        {item.kind}
                      </span>
                      <span
                        className="px-1.5 py-0.5 rounded text-[10.5px] font-mono"
                        style={{
                          backgroundColor: 'var(--bg-subtle)',
                          color: 'var(--text-muted)',
                        }}
                      >
                        rev {item.revision} · {item.provenance}
                      </span>
                    </div>
                    <p
                      className="text-[12.5px] whitespace-pre-wrap leading-relaxed"
                      style={{ color: 'var(--text-secondary)' }}
                    >
                      {item.content}
                    </p>
                    <div
                      className="flex flex-wrap gap-x-3 gap-y-0.5 text-[11px]"
                      style={{ color: 'var(--text-muted)' }}
                    >
                      <span>Updated {formatRelativeTime(item.updated_at)}</span>
                      {item.observed_at && <span>Observed: {item.observed_at}</span>}
                      {item.valid_until && <span>Valid until: {item.valid_until}</span>}
                    </div>
                  </div>

                  <div className="flex items-center gap-1 shrink-0">
                    <button
                      type="button"
                      onClick={() => {
                        setConflictError(null);
                        setEditing({
                          id: item.id,
                          scope: item.scope,
                          scope_id: item.scope_id,
                          revision: item.revision,
                          title: item.title,
                          content: item.content,
                          valid_until: item.valid_until ?? '',
                        });
                      }}
                      title="Edit memory"
                      aria-label={`Edit ${item.title}`}
                      className="p-1.5 rounded-lg hover:bg-[var(--bg-subtle)]"
                      style={{ color: 'var(--text-secondary)' }}
                    >
                      <Edit3 size={14} />
                    </button>
                    <button
                      type="button"
                      disabled={deleteMutation.isPending}
                      onClick={() => deleteMutation.mutate(item)}
                      title="Delete memory"
                      aria-label={`Delete ${item.title}`}
                      className="p-1.5 rounded-lg hover:bg-[var(--status-danger-bg)] disabled:opacity-50"
                      style={{ color: 'var(--status-danger)' }}
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </Modal>
  );
}
