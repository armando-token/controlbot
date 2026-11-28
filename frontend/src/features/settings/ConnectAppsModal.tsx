import React, { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { AlertCircle, Check, Plug, RefreshCw, SlidersHorizontal } from 'lucide-react';
import { Modal } from '../../components/Modal';
import { appsApi } from '../../lib/api';
import type { ConnectedApp } from '../../lib/types';
import { useUiStore } from '../../stores/uiStore';

export const ConnectAppsModal: React.FC = () => {
  const queryClient = useQueryClient();
  const open = useUiStore((s) => s.connectAppsOpen);
  const setOpen = useUiStore((s) => s.setConnectAppsOpen);
  const pushToast = useUiStore((s) => s.pushToast);

  const [pendingAppId, setPendingAppId] = useState<string | null>(null);
  const [expandedAppId, setExpandedAppId] = useState<string | null>(null);
  const [enabledDraft, setEnabledDraft] = useState(true);
  const [labelDraft, setLabelDraft] = useState('');
  const [configDraft, setConfigDraft] = useState('{}');
  const [configError, setConfigError] = useState<string | null>(null);

  const appsQuery = useQuery({
    queryKey: ['apps'],
    queryFn: () => appsApi.list(),
    enabled: open,
  });

  const updateMutation = useMutation({
    mutationFn: ({
      id,
      patch,
    }: {
      id: string;
      patch: Partial<
        Pick<ConnectedApp, 'enabled' | 'connected' | 'status' | 'account_label' | 'config'>
      >;
    }) => {
      setPendingAppId(id);
      return appsApi.update(id, patch);
    },
    onSuccess: (app, vars) => {
      void queryClient.invalidateQueries({ queryKey: ['apps'] });
      if (expandedAppId === app.id && vars.patch.config !== undefined) {
        setExpandedAppId(null);
      }
      pushToast({
        tone: app.connected ? 'success' : 'info',
        title:
          vars.patch.config !== undefined
            ? `Saved ${app.name} settings`
            : app.connected
              ? `Connected ${app.name}`
              : `Disconnected ${app.name}`,
      });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'App update failed', description: err.message });
    },
    onSettled: () => {
      setPendingAppId(null);
    },
  });

  const openConfigure = (app: ConnectedApp) => {
    if (expandedAppId === app.id) {
      setExpandedAppId(null);
      setConfigError(null);
      return;
    }
    setExpandedAppId(app.id);
    setEnabledDraft(app.enabled ?? app.connected);
    setLabelDraft(app.account_label || '');
    setConfigDraft(JSON.stringify(app.config ?? {}, null, 2));
    setConfigError(null);
  };

  const handleSaveConfig = (app: ConnectedApp, e: React.FormEvent) => {
    e.preventDefault();
    let parsed: unknown;
    try {
      parsed = JSON.parse(configDraft.trim() || '{}');
    } catch {
      setConfigError('Config must be valid JSON.');
      return;
    }
    if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
      setConfigError('Config must be a JSON object (e.g. {"workspace": "eng"}).');
      return;
    }
    setConfigError(null);
    updateMutation.mutate({
      id: app.id,
      patch: {
        enabled: enabledDraft,
        connected: enabledDraft,
        account_label: labelDraft.trim(),
        config: parsed as Record<string, unknown>,
      },
    });
  };

  return (
    <Modal
      open={open}
      onClose={() => setOpen(false)}
      title="Connect apps"
      subtitle="Enable tools and external accounts your bots can mention with @ and use safely."
      maxWidthClass="max-w-xl"
    >
      <div className="p-5 space-y-2.5">
        {appsQuery.isLoading ? (
          <div className="text-[13px] py-8 text-center" style={{ color: 'var(--text-muted)' }}>
            Loading connectors…
          </div>
        ) : appsQuery.isError ? (
          <div
            className="p-4 rounded-xl flex items-center justify-between gap-3 text-[13px]"
            style={{
              backgroundColor: 'var(--status-danger-bg)',
              color: 'var(--status-danger)',
            }}
          >
            <span className="inline-flex items-center gap-2 min-w-0">
              <AlertCircle size={16} className="shrink-0" />
              <span className="truncate">
                {appsQuery.error instanceof Error
                  ? appsQuery.error.message
                  : 'Could not load connected apps.'}
              </span>
            </span>
            <button
              type="button"
              onClick={() => void appsQuery.refetch()}
              className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[12px] font-medium shrink-0"
              style={{
                backgroundColor: 'var(--bg-canvas)',
                color: 'var(--text-primary)',
                border: '1px solid var(--border-strong)',
              }}
            >
              <RefreshCw size={12} />
              Retry
            </button>
          </div>
        ) : (
          (appsQuery.data?.apps ?? []).map((app) => {
            const isExpanded = expandedAppId === app.id;
            const isRowPending = pendingAppId === app.id;
            const isEnabled = app.enabled ?? app.connected;
            return (
              <div
                key={app.id}
                className="p-3.5 rounded-xl space-y-3"
                style={{
                  backgroundColor: 'var(--bg-sidebar)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <div className="flex items-center justify-between gap-3">
                  <div className="flex items-start gap-3 min-w-0">
                    <span
                      className="w-9 h-9 rounded-xl flex items-center justify-center shrink-0"
                      style={{
                        backgroundColor: app.connected
                          ? 'var(--accent-computer-tint)'
                          : 'var(--bg-subtle)',
                        color: app.connected
                          ? 'var(--accent-computer)'
                          : 'var(--text-secondary)',
                      }}
                    >
                      <Plug size={16} strokeWidth={1.75} />
                    </span>
                    <div className="min-w-0">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-[13.5px] font-semibold truncate">{app.name}</span>
                        <span
                          className="text-[10.5px] px-1.5 py-0.5 rounded-full"
                          style={{
                            backgroundColor: 'var(--bg-subtle)',
                            color: 'var(--text-muted)',
                          }}
                        >
                          {app.category}
                        </span>
                        {app.account_label && (
                          <span
                            className="text-[10.5px] px-1.5 py-0.5 rounded-full font-mono"
                            style={{
                              backgroundColor: 'var(--bg-canvas)',
                              color: 'var(--text-secondary)',
                              border: '1px solid var(--border-subtle)',
                            }}
                          >
                            {app.account_label}
                          </span>
                        )}
                      </div>
                      <div
                        className="text-[12px] mt-0.5 leading-snug"
                        style={{ color: 'var(--text-secondary)' }}
                      >
                        {app.description}
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center gap-1.5 shrink-0">
                    <button
                      type="button"
                      onClick={() => openConfigure(app)}
                      aria-label={`Configure ${app.name}`}
                      aria-expanded={isExpanded}
                      className="p-1.5 rounded-lg hover:bg-[var(--bg-subtle)] transition-colors"
                      style={{
                        color: isExpanded ? 'var(--text-primary)' : 'var(--text-secondary)',
                        backgroundColor: isExpanded ? 'var(--bg-active)' : 'transparent',
                      }}
                      title={`Configure ${app.name}`}
                    >
                      <SlidersHorizontal size={14} strokeWidth={1.75} />
                    </button>
                    {(() => {
                      const connLabel = app.connected ? 'Connected' : 'Connect';
                      return (
                    <button
                      type="button"
                      aria-label={`${connLabel}`}
                      disabled={isRowPending}
                      onClick={() =>
                        updateMutation.mutate({
                          id: app.id,
                          patch: {
                            enabled: !isEnabled,
                            connected: !app.connected,
                            account_label: app.account_label || 'work',
                          },
                        })
                      }
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12.5px] font-medium shrink-0 transition-colors disabled:opacity-50"
                      style={{
                        backgroundColor: app.connected
                          ? 'var(--status-ok-bg)'
                          : 'var(--accent-primary)',
                        color: app.connected ? 'var(--status-ok)' : 'var(--bg-canvas)',
                        border: app.connected ? '1px solid rgba(21, 128, 61, 0.2)' : 'none',
                      }}
                    >
                      {app.connected && <Check size={13} strokeWidth={2.3} />}
                      {app.connected ? 'Connected' : 'Connect'}
                    </button>
                      );
                    })()}
                  </div>
                </div>

                {isExpanded && (
                  <form
                    onSubmit={(e) => handleSaveConfig(app, e)}
                    className="pt-3 space-y-2.5"
                    style={{ borderTop: '1px solid var(--border-subtle)' }}
                  >
                    <div className="flex items-center justify-between gap-3">
                      <label className="inline-flex items-center gap-2 text-[12.5px] font-medium cursor-pointer">
                        <input
                          type="checkbox"
                          aria-label={`Enable ${app.name}`}
                          checked={enabledDraft}
                          onChange={(e) => setEnabledDraft(e.target.checked)}
                        />
                        <span>Enabled for agent use</span>
                      </label>
                      <span className="text-[11px] font-mono" style={{ color: 'var(--text-muted)' }}>
                        status: {app.status || (app.connected ? 'connected' : 'disabled')}
                      </span>
                    </div>

                    <div>
                      <label
                        className="block text-[11.5px] font-medium mb-1"
                        style={{ color: 'var(--text-secondary)' }}
                      >
                        Account label
                      </label>
                      <input
                        type="text"
                        maxLength={80}
                        aria-label={`Account label for ${app.name}`}
                        value={labelDraft}
                        onChange={(e) => setLabelDraft(e.target.value)}
                        placeholder="e.g. work, ops-prod"
                        className="w-full px-2.5 py-1.5 rounded-lg text-[12.5px] outline-none bg-[var(--bg-canvas)] border border-[var(--border-strong)]"
                      />
                    </div>

                    <div>
                      <label
                        className="block text-[11.5px] font-medium mb-1"
                        style={{ color: 'var(--text-secondary)' }}
                      >
                        Connector config (JSON object)
                      </label>
                      <textarea
                        rows={3}
                        aria-label={`Config JSON for ${app.name}`}
                        value={configDraft}
                        onChange={(e) => {
                          setConfigDraft(e.target.value);
                          if (configError) setConfigError(null);
                        }}
                        className="w-full px-2.5 py-1.5 rounded-lg text-[12px] font-mono outline-none bg-[var(--bg-canvas)] border border-[var(--border-strong)]"
                      />
                      {configError && (
                        <div className="text-[11.5px] mt-1" style={{ color: 'var(--status-danger)' }}>
                          {configError}
                        </div>
                      )}
                    </div>

                    <div className="flex justify-end gap-2">
                      <button
                        type="button"
                        onClick={() => {
                          setExpandedAppId(null);
                          setConfigError(null);
                        }}
                        className="px-3 py-1 rounded-lg text-[12px] hover:bg-[var(--bg-subtle)]"
                        style={{ color: 'var(--text-secondary)' }}
                      >
                        Cancel
                      </button>
                      <button
                        type="submit"
                        aria-label="Save"
                        disabled={isRowPending}
                        className="px-3 py-1 rounded-lg text-[12px] font-medium disabled:opacity-50"
                        style={{
                          backgroundColor: 'var(--accent-primary)',
                          color: 'var(--bg-canvas)',
                        }}
                      >
                        {isRowPending ? 'Saving…' : 'Save'}
                      </button>
                    </div>
                  </form>
                )}
              </div>
            );
          })
        )}
      </div>
    </Modal>
  );
};
