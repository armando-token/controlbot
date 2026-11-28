import React, { useEffect, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  ChevronDown,
  Cpu,
  FilePlus2,
  FolderGit2,
  Hash,
  Monitor,
  PanelRight,
  RefreshCw,
  SlidersHorizontal,
} from 'lucide-react';
import { botsApi, legacyApi, pagesApi, settingsApi } from '../../lib/api';
import type { AppSettings, Bot, Channel, EngineId, ThinkingLevel } from '../../lib/types';
import { useComputerStore } from '../../stores/computerStore';
import { usePresenceStore } from '../../stores/presenceStore';
import { useUiStore } from '../../stores/uiStore';
import { BotAvatar } from '../roster/BotAvatar';

interface ChatHeaderProps {
  bot?: Bot | null;
  channel?: Channel | null;
  allBots: Bot[];
  compact?: boolean;
}

const THINKING_OPTIONS: { id: ThinkingLevel; label: string }[] = [
  { id: 'off', label: 'Off' },
  { id: 'low', label: 'Low' },
  { id: 'medium', label: 'Medium' },
  { id: 'high', label: 'High' },
  { id: 'max', label: 'Max' },
];

export const ChatHeader: React.FC<ChatHeaderProps> = ({
  bot,
  channel,
  allBots,
  compact = false,
}) => {
  const queryClient = useQueryClient();
  const inspectorOpen = useUiStore((s) => s.inspectorOpen);
  const inspectorTab = useUiStore((s) => s.inspectorTab);
  const toggleInspector = useUiStore((s) => s.toggleInspector);
  const openInspectorTab = useUiStore((s) => s.openInspectorTab);
  const setActivePageId = useUiStore((s) => s.setActivePageId);
  const pushToast = useUiStore((s) => s.pushToast);

  const presence = usePresenceStore((s) => (bot ? s.byBotId[bot.id] : undefined));
  const computerStatus = useComputerStore((s) => s.byVmId.default);

  const [pillOpen, setPillOpen] = useState(false);
  const [refreshingModels, setRefreshingModels] = useState(false);
  const [optimisticHydrogen, setOptimisticHydrogen] = useState<boolean | null>(null);
  const pillRef = useRef<HTMLDivElement | null>(null);
  const pillTriggerRef = useRef<HTMLButtonElement | null>(null);
  const pendingHydrogenCountRef = useRef(0);
  const hydrogenSeqRef = useRef(0);

  useEffect(() => {
    const close = (e: MouseEvent) => {
      if (pillRef.current && !pillRef.current.contains(e.target as Node)) {
        setPillOpen(false);
      }
    };
    window.addEventListener('click', close);
    return () => window.removeEventListener('click', close);
  }, []);

  useEffect(() => {
    if (!pillOpen) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !e.isComposing) {
        e.preventDefault();
        e.stopPropagation();
        setPillOpen(false);
        pillTriggerRef.current?.focus();
      }
    };
    window.addEventListener('keydown', onKeyDown, true);
    return () => window.removeEventListener('keydown', onKeyDown, true);
  }, [pillOpen]);

  const systemInfoQuery = useQuery({
    queryKey: ['system-info'],
    queryFn: () => legacyApi.systemInfo(),
    staleTime: 30_000,
  });

  const modelsQuery = useQuery({
    queryKey: ['agy-models'],
    queryFn: () => legacyApi.agyModels(),
    enabled: pillOpen,
    staleTime: 60_000,
  });

  const projectsQuery = useQuery({
    queryKey: ['local-projects'],
    queryFn: () => legacyApi.projects(),
    enabled: pillOpen,
    staleTime: 60_000,
  });

  const settingsQuery = useQuery({
    queryKey: ['settings'],
    queryFn: () => settingsApi.get(),
    staleTime: 60_000,
  });

  const updateBotMutation = useMutation({
    mutationFn: (patch: Partial<Bot>) => {
      if (!bot) throw new Error('No active bot');
      return botsApi.update(bot.id, patch);
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['roster'] });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not update bot settings', description: err.message });
    },
  });

  type HydrogenMutationContext = {
    previous: AppSettings | undefined;
    seq: number;
    allow: boolean;
  };

  const updateHydrogenMutation = useMutation<
    AppSettings,
    Error,
    boolean,
    HydrogenMutationContext
  >({
    mutationFn: (allow) => settingsApi.update({ allow_hydrogen: allow }),
    onMutate: async (allow) => {
      pendingHydrogenCountRef.current += 1;
      const seq = (hydrogenSeqRef.current += 1);
      const previous = queryClient.getQueryData<AppSettings>(['settings']);
      queryClient.setQueryData<AppSettings>(['settings'], (old) =>
        old ? { ...old, allow_hydrogen: allow } : undefined,
      );
      await queryClient.cancelQueries({ queryKey: ['settings'] });
      return { previous, seq, allow };
    },
    onSuccess: (updated, _allow, context) => {
      if (
        pendingHydrogenCountRef.current <= 1 &&
        context?.seq === hydrogenSeqRef.current
      ) {
        queryClient.setQueryData<AppSettings>(['settings'], updated);
      }
    },
    onError: (err, _allow, context) => {
      if (context && context.seq === hydrogenSeqRef.current && context.previous) {
        const prevAllow = context.previous.allow_hydrogen;
        queryClient.setQueryData<AppSettings>(['settings'], (old) =>
          old ? { ...old, allow_hydrogen: prevAllow } : context.previous,
        );
      }
      pushToast({
        tone: 'error',
        title: 'Could not update Hydrogen setting',
        description: err.message,
      });
    },
    onSettled: (_data, _err, _allow, context) => {
      pendingHydrogenCountRef.current = Math.max(
        0,
        pendingHydrogenCountRef.current - 1,
      );
      if (context?.seq === hydrogenSeqRef.current) {
        setOptimisticHydrogen(null);
      }
      if (pendingHydrogenCountRef.current === 0) {
        void queryClient.invalidateQueries({ queryKey: ['settings'] });
      }
    },
  });

  const createPageMutation = useMutation({
    mutationFn: () =>
      pagesApi.create({
        bot_id: bot?.id ?? channel?.bot_ids?.[0] ?? '',
        channel_id: channel?.id ?? null,
        thread_id: bot?.thread_id ?? channel?.thread_id ?? null,
        title: bot ? `${bot.name} Brief` : `${channel?.name || 'Channel'} Brief`,
        content_md: '# Untitled page\n\nStart writing or ask your bot to draft this page.\n',
      }),
    onSuccess: (page) => {
      void queryClient.invalidateQueries({ queryKey: ['library'] });
      setActivePageId(page.id);
      pushToast({ tone: 'success', title: 'Page created' });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not create page', description: err.message });
    },
  });

  const handleRefreshModels = async () => {
    if (refreshingModels) return;
    setRefreshingModels(true);
    try {
      await legacyApi.agyModels(true);
      await queryClient.invalidateQueries({ queryKey: ['agy-models'] });
    } catch (err) {
      pushToast({
        tone: 'error',
        title: 'Could not refresh models',
        description: err instanceof Error ? err.message : 'Request failed',
      });
    } finally {
      setRefreshingModels(false);
    }
  };

  const allowHydrogen =
    optimisticHydrogen ?? Boolean(settingsQuery.data?.allow_hydrogen);
  const allModels = modelsQuery.data?.models ?? [];
  const filteredModels = allowHydrogen
    ? allModels
    : allModels.filter((m) => !m.is_hydrogen);

  const botComputerActive =
    Boolean(presence?.computerActive ?? bot?.computer_active) ||
    Boolean(computerStatus?.browser_running) ||
    computerStatus?.control_owner === 'human_takeover';

  const computerTabActive = inspectorOpen && inspectorTab === 'computer';

  const channelMembers = channel
    ? channel.bot_ids
        .map((id) => allBots.find((b) => b.id === id))
        .filter((b): b is Bot => Boolean(b))
    : [];

  const headerTitle = bot ? bot.name : channel?.name || 'Conversation';
  const pillAriaLabel = bot
    ? `Model and thinking settings: ${bot.model_id}, ${bot.thinking_level}`
    : 'Model and thinking settings';

  const sysInfo = systemInfoQuery.data;
  const runtimeMode = String(sysInfo?.runtime_mode || 'live_runtime');
  const backendMode = String(sysInfo?.backend_mode || 'local_http');
  const llmOrigin = sysInfo?.llm_origin ? String(sysInfo.llm_origin) : '';
  const isEmulated =
    backendMode === 'emulated' || backendMode === 'stub' || runtimeMode === 'stub';
  const isLocalHostOrigin =
    !llmOrigin ||
    /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\]|0\.0\.0\.0)(:\d+)?$/i.test(llmOrigin);
  const originKind = isEmulated ? 'Emulated' : isLocalHostOrigin ? 'Local' : 'Remote';
  const originHost = llmOrigin ? llmOrigin.replace(/^https?:\/\//i, '') : '';
  const badgeText =
    originKind === 'Remote' && originHost
      ? `Remote · ${originHost}`
      : `${originKind} · ${backendMode}`;
  const badgeAriaLabel = `Execution runtime: ${originKind}, backend mode ${backendMode}, runtime mode ${runtimeMode}${llmOrigin ? `, origin ${llmOrigin}` : ''}`;

  return (
    <header
      className="h-13 px-4 flex items-center justify-between gap-3 shrink-0"
      style={{
        backgroundColor: 'var(--bg-canvas)',
        borderBottom: '1px solid var(--border-subtle)',
      }}
    >
      {/* Left: Bot/Channel identity + Model Pill */}
      <div className="flex items-center gap-2.5 min-w-0">
        <div className="flex items-center gap-2.5 min-w-0">
          <button
            type="button"
            onClick={toggleInspector}
            title="Toggle details panel (Cmd+Shift+I)"
            aria-label="Toggle details panel"
            className="py-1 px-1 -ml-1 rounded-xl hover:bg-[var(--bg-subtle)] transition-colors shrink-0"
          >
            {bot ? (
              <BotAvatar
                shape={bot.avatar_shape}
                color={bot.avatar_color}
                eyesLarge={bot.avatar_eyes_large}
                state={presence?.state ?? bot.status_state}
                size={28}
                computerActive={presence?.computerActive ?? bot.computer_active}
              />
            ) : (
              <span
                className="w-7 h-7 rounded-lg flex items-center justify-center"
                style={{ backgroundColor: 'var(--bg-subtle)', color: 'var(--text-secondary)' }}
              >
                <Hash size={15} strokeWidth={1.85} />
              </span>
            )}
          </button>
          <div className="min-w-0 text-left">
            <h1
              className="m-0 text-[14px] font-semibold tracking-tight truncate leading-tight"
              style={{ color: 'var(--text-primary)' }}
            >
              <button
                type="button"
                onClick={toggleInspector}
                title="Toggle details panel (Cmd+Shift+I)"
                aria-label={`${headerTitle}`}
                className="text-left truncate max-w-full hover:underline"
              >
                {headerTitle}
              </button>
            </h1>
            {!compact && (
              <div
                className="text-[11.5px] truncate leading-tight mt-0.5"
                style={{ color: 'var(--text-muted)' }}
              >
                {bot
                  ? presence?.subtext || bot.status_subtext || 'Ready'
                  : `${channelMembers.length} bots · ${channelMembers.map((b) => b.name).join(', ')}`}
              </div>
            )}
          </div>
        </div>

        {/* Discrete Model & Thinking Pill (1:1 bot) */}
        {bot && !compact && (
          <div className="relative" ref={pillRef}>
            <button
              ref={pillTriggerRef}
              type="button"
              aria-expanded={pillOpen}
              aria-haspopup="true"
              aria-label={`${pillAriaLabel}`}
              onClick={(e) => {
                e.stopPropagation();
                setPillOpen((v) => !v);
              }}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-[12px] transition-colors hover:bg-[var(--bg-active)]"
              style={{
                backgroundColor: 'var(--bg-subtle)',
                color: 'var(--text-secondary)',
                border: '1px solid var(--border-subtle)',
              }}
            >
              <Cpu size={12.5} strokeWidth={1.75} />
              <span className="max-w-[150px] truncate">{bot.model_id}</span>
              <span style={{ color: 'var(--text-muted)' }}>·</span>
              <span className="capitalize">{bot.thinking_level}</span>
              <ChevronDown size={12} strokeWidth={1.75} />
            </button>

            {pillOpen && (
              <div
                className="absolute left-0 top-full mt-1.5 w-80 p-3.5 rounded-2xl z-40 space-y-3"
                style={{
                  backgroundColor: 'var(--bg-elevated)',
                  border: '1px solid var(--border-strong)',
                  boxShadow: 'var(--shadow-lg)',
                }}
                onClick={(e) => e.stopPropagation()}
              >
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-1.5 text-[12.5px] font-semibold">
                    <SlidersHorizontal size={13.5} strokeWidth={1.8} />
                    <span>Model &amp; capability</span>
                  </div>
                  <button
                    type="button"
                    onClick={() => void handleRefreshModels()}
                    disabled={refreshingModels}
                    title="Refresh available models"
                    aria-label="Refresh available models"
                    className="p-1 rounded-md hover:bg-[var(--bg-subtle)] disabled:opacity-50"
                    style={{ color: 'var(--text-muted)' }}
                  >
                    <RefreshCw
                      size={12.5}
                      strokeWidth={1.75}
                      className={refreshingModels ? 'animate-spin' : undefined}
                    />
                  </button>
                </div>

                {/* Engine selector */}
                <div>
                  <div className="text-[11.5px] font-medium mb-1" style={{ color: 'var(--text-muted)' }}>
                    Engine
                  </div>
                  <div className="grid grid-cols-2 gap-1.5">
                    {(
                      [
                        { id: 'agy', label: 'Antigravity CLI' },
                        { id: 'controlbot_runtime', label: 'ControlBot Runtime' },
                      ] as { id: EngineId; label: string }[]
                    ).map((eng) => {
                      const active = bot.engine_id === eng.id;
                      return (
                        <button
                          key={eng.id}
                          type="button"
                          aria-label={`${eng.label}`}
                          onClick={() => updateBotMutation.mutate({ engine_id: eng.id })}
                          className="px-2.5 py-1.5 rounded-lg text-[12px] font-medium transition-colors"
                          style={{
                            backgroundColor: active ? 'var(--bg-active)' : 'var(--bg-sidebar)',
                            border: active
                              ? '1px solid var(--border-strong)'
                              : '1px solid var(--border-subtle)',
                            color: 'var(--text-primary)',
                          }}
                        >
                          {eng.label}
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Model dropdown */}
                <div>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-[11.5px] font-medium" style={{ color: 'var(--text-muted)' }}>
                      Model
                    </span>
                    <label className="inline-flex items-center gap-1.5 text-[11px] cursor-pointer">
                      <input
                        type="checkbox"
                        aria-label="Hydrogen opt-in"
                        checked={allowHydrogen}
                        onChange={(e) => {
                          const next = e.target.checked;
                          setOptimisticHydrogen(next);
                          updateHydrogenMutation.mutate(next);
                        }}
                      />
                      <span style={{ color: 'var(--text-muted)' }}>Hydrogen opt-in</span>
                    </label>
                  </div>
                  <select
                    aria-label="Model"
                    value={bot.model_id}
                    onChange={(e) => updateBotMutation.mutate({ model_id: e.target.value })}
                    className="w-full px-2.5 py-1.5 rounded-lg text-[12.5px] outline-none"
                    style={{
                      backgroundColor: 'var(--bg-sidebar)',
                      border: '1px solid var(--border-strong)',
                    }}
                  >
                    {!filteredModels.some((m) => m.id === bot.model_id) && (
                      <option value={bot.model_id}>{bot.model_id}</option>
                    )}
                    {filteredModels.map((m) => (
                      <option key={m.id} value={m.id}>
                        {m.label} {m.is_hydrogen ? '(Hydrogen)' : ''}
                      </option>
                    ))}
                  </select>
                  {modelsQuery.isError && (
                    <div className="text-[11px] mt-1" style={{ color: 'var(--status-danger)' }}>
                      Failed to load model list
                    </div>
                  )}
                </div>

                {/* Thinking effort */}
                <div>
                  <div className="text-[11.5px] font-medium mb-1" style={{ color: 'var(--text-muted)' }}>
                    Thinking effort
                  </div>
                  <div className="grid grid-cols-5 gap-1">
                    {THINKING_OPTIONS.map((t) => {
                      const active = bot.thinking_level === t.id;
                      return (
                        <button
                          key={t.id}
                          type="button"
                          aria-label={`${t.label}`}
                          onClick={() => updateBotMutation.mutate({ thinking_level: t.id })}
                          className="py-1 rounded-lg text-[11.5px] font-medium transition-colors"
                          style={{
                            backgroundColor: active ? 'var(--accent-primary)' : 'var(--bg-sidebar)',
                            color: active ? 'var(--bg-canvas)' : 'var(--text-secondary)',
                          }}
                        >
                          {t.label}
                        </button>
                      );
                    })}
                  </div>
                </div>

                {/* Project workspace */}
                <div>
                  <div className="flex items-center gap-1.5 text-[11.5px] font-medium mb-1" style={{ color: 'var(--text-muted)' }}>
                    <FolderGit2 size={12} />
                    <span>Project folder</span>
                  </div>
                  <select
                    aria-label="Project folder"
                    value={bot.project_name || ''}
                    onChange={(e) =>
                      updateBotMutation.mutate({
                        project_name: e.target.value || null,
                      })
                    }
                    className="w-full px-2.5 py-1.5 rounded-lg text-[12.5px] outline-none"
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
                  {projectsQuery.isError && (
                    <div className="text-[11px] mt-1" style={{ color: 'var(--status-danger)' }}>
                      Failed to load projects
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Right controls: Runtime Origin Badge, New Page, Purple Computer Status Button, Inspector Toggle */}
      <div className="flex items-center gap-1.5 shrink-0">
        {!compact && (
          <div
            role="status"
            data-testid="runtime-origin-badge"
            data-runtime-mode={runtimeMode}
            data-llm-origin={llmOrigin}
            data-backend-mode={backendMode}
            aria-label={`${badgeAriaLabel}`}
            title={`${badgeAriaLabel}`}
            className="inline-flex items-center gap-1.5 px-2 py-1 rounded-full text-[11px] font-medium shrink-0"
            style={{
              backgroundColor: isEmulated
                ? 'var(--status-warn-bg)'
                : originKind === 'Remote'
                  ? 'var(--accent-computer-tint)'
                  : 'var(--bg-subtle)',
              color: isEmulated
                ? 'var(--status-warn)'
                : originKind === 'Remote'
                  ? 'var(--accent-computer)'
                  : 'var(--text-secondary)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            <span
              className="w-1.5 h-1.5 rounded-full shrink-0"
              style={{
                backgroundColor: isEmulated
                  ? 'var(--status-warn)'
                  : originKind === 'Remote'
                    ? 'var(--accent-computer)'
                    : 'var(--status-ok)',
              }}
            />
            <span className="truncate max-w-[140px]">{badgeText}</span>
          </div>
        )}

        <button
          type="button"
          onClick={() => createPageMutation.mutate()}
          disabled={createPageMutation.isPending || (!bot && !channel)}
          title="Create new interactive page"
          aria-label="Create new interactive page"
          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[12.5px] font-medium transition-colors hover:bg-[var(--bg-subtle)] disabled:opacity-45"
          style={{ color: 'var(--text-secondary)' }}
        >
          <FilePlus2 size={15} strokeWidth={1.75} />
          {!compact && <span className="hidden sm:inline">New page</span>}
        </button>

        <button
          type="button"
          onClick={() => {
            const wasActive = computerTabActive;
            openInspectorTab('computer');
            if (wasActive) {
              window.requestAnimationFrame(() => {
                const target =
                  document.querySelector<HTMLElement>(
                    '[role="tablist"][aria-label="Computer view"] button',
                  ) ??
                  document.querySelector<HTMLElement>(
                    '[role="tablist"][aria-label="Inspector tabs"] [role="tab"][aria-selected="true"]',
                  );
                target?.focus();
              });
            }
          }}
          title="Open Bot Computer"
          aria-label="Open Bot Computer"
          aria-pressed={computerTabActive}
          className="inline-flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-[12.5px] font-medium transition-all"
          style={{
            backgroundColor:
              computerStatus?.control_owner === 'human_takeover'
                ? 'var(--accent-takeover-tint)'
                : botComputerActive || computerTabActive
                  ? 'var(--accent-computer-tint)'
                  : 'transparent',
            color:
              computerStatus?.control_owner === 'human_takeover'
                ? 'var(--accent-takeover)'
                : botComputerActive || computerTabActive
                  ? 'var(--accent-computer)'
                  : 'var(--text-secondary)',
            border:
              computerStatus?.control_owner === 'human_takeover'
                ? '1px solid rgba(217, 119, 6, 0.35)'
                : botComputerActive
                  ? '1px solid rgba(124, 58, 237, 0.28)'
                  : '1px solid transparent',
          }}
        >
          <Monitor size={15.5} strokeWidth={1.85} />
          {!compact && (
            <span className="hidden md:inline">
              {computerStatus?.control_owner === 'human_takeover'
                ? 'In control'
                : botComputerActive
                  ? 'Computer active'
                  : 'Computer'}
            </span>
          )}
        </button>

        <button
          type="button"
          onClick={toggleInspector}
          title="Toggle inspector panel (Cmd+Shift+I)"
          aria-label="Toggle inspector panel"
          aria-pressed={inspectorOpen}
          className="p-1.5 rounded-lg transition-colors"
          style={{
            backgroundColor: inspectorOpen ? 'var(--bg-active)' : 'transparent',
            color: inspectorOpen ? 'var(--text-primary)' : 'var(--text-secondary)',
          }}
        >
          <PanelRight size={16.5} strokeWidth={1.75} />
        </button>
      </div>
    </header>
  );
};
