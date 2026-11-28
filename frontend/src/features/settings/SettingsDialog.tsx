import React, { useEffect, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Activity,
  AlertCircle,
  BarChart3,
  Check,
  CheckCircle2,
  Cpu,
  KeyRound,
  Lock,
  Monitor,
  Play,
  Plus,
  RefreshCw,
  Shield,
  Sliders,
  Square,
  Trash2,
  XCircle,
} from 'lucide-react';
import { Modal } from '../../components/Modal';
import {
  computerApi,
  legacyApi,
  settingsApi,
  usageApi,
  vaultApi,
} from '../../lib/api';
import type {
  AccentMode,
  AppSettings,
  AutoReviewRule,
  EngineId,
  ThemeMode,
  ThinkingLevel,
} from '../../lib/types';
import { useComputerStore } from '../../stores/computerStore';
import { useUiStore, type SettingsTabId } from '../../stores/uiStore';

const TABS: {
  id: SettingsTabId;
  label: string;
  icon: React.ComponentType<{ size?: number; strokeWidth?: number }>;
}[] = [
  { id: 'general', label: 'General', icon: Sliders },
  { id: 'computer', label: 'Computer', icon: Monitor },
  { id: 'vault', label: 'Vault', icon: KeyRound },
  { id: 'usage', label: 'Usage', icon: BarChart3 },
  { id: 'system', label: 'System & Tasks', icon: Cpu },
];

const THINKING_LEVELS: { id: ThinkingLevel; label: string }[] = [
  { id: 'off', label: 'Off' },
  { id: 'low', label: 'Low' },
  { id: 'medium', label: 'Medium' },
  { id: 'high', label: 'High' },
  { id: 'max', label: 'Max' },
];

const TIMEZONES = [
  'UTC',
  'America/New_York',
  'America/Chicago',
  'America/Denver',
  'America/Los_Angeles',
  'America/Mexico_City',
  'Europe/London',
  'Europe/Madrid',
  'Europe/Berlin',
  'Asia/Tokyo',
];

type SettingsToggleKey =
  | 'allow_hydrogen'
  | 'include_browser_context'
  | 'notifications_enabled'
  | 'sound_enabled'
  | 'auto_open_computer';

const SETTINGS_TOGGLE_KEYS: readonly SettingsToggleKey[] = [
  'allow_hydrogen',
  'include_browser_context',
  'notifications_enabled',
  'sound_enabled',
  'auto_open_computer',
];

export const SettingsDialog: React.FC = () => {
  const queryClient = useQueryClient();
  const open = useUiStore((s) => s.settingsOpen);
  const close = useUiStore((s) => s.closeSettings);
  const activeTab = useUiStore((s) => s.settingsTab);
  const setTab = useUiStore((s) => s.setSettingsTab);
  const theme = useUiStore((s) => s.theme);
  const setTheme = useUiStore((s) => s.setTheme);
  const accentMode = useUiStore((s) => s.accentMode);
  const setAccentMode = useUiStore((s) => s.setAccentMode);
  const openInspectorTab = useUiStore((s) => s.openInspectorTab);
  const pushToast = useUiStore((s) => s.pushToast);
  const setComputerStatus = useComputerStore((s) => s.setStatus);

  // General settings local drafts
  const [displayNameDraft, setDisplayNameDraft] = useState('');
  const [timezoneDraft, setTimezoneDraft] = useState('UTC');
  const [optimisticToggles, setOptimisticToggles] = useState<
    Partial<Record<SettingsToggleKey, boolean>>
  >({});

  // Optimistic settings mutation coordination
  const pendingSettingsCountRef = useRef(0);
  const mutationSeqRef = useRef(0);
  const lastKeySeqRef = useRef<Record<string, number>>({});
  const lastSyncedDisplayNameRef = useRef<string | null>(null);
  const lastSyncedTimezoneRef = useRef<string | null>(null);
  const wasOpenRef = useRef(open);
  const displayNameDraftRef = useRef(displayNameDraft);
  displayNameDraftRef.current = displayNameDraft;

  // Auto-review rules local editor
  const [rulesDraft, setRulesDraft] = useState<AutoReviewRule[]>([]);
  const [newRuleText, setNewRuleText] = useState('');
  const [newRuleMode, setNewRuleMode] = useState<'allow_auto' | 'ask_first'>('allow_auto');

  // Vault add form
  const [secretName, setSecretName] = useState('');
  const [secretDomain, setSecretDomain] = useState('');
  const [secretUsername, setSecretUsername] = useState('');
  const [secretValue, setSecretValue] = useState('');
  const [secretFields, setSecretFields] = useState<Array<{ key: string; value: string }>>([]);

  // ControlBot Runtime task submit & resume forms
  const [taskQuery, setTaskQuery] = useState('');
  const [taskFacility, setTaskFacility] = useState('facility-a');
  const [resumeInputs, setResumeInputs] = useState<Record<string, string>>({});
  const [computerActionPending, setComputerActionPending] = useState(false);

  const settingsQuery = useQuery({
    queryKey: ['settings'],
    queryFn: () => settingsApi.get(),
    enabled: open,
  });

  const modelsQuery = useQuery({
    queryKey: ['agy-models'],
    queryFn: () => legacyApi.agyModels(),
    enabled: open && activeTab === 'general',
  });

  const projectsQuery = useQuery({
    queryKey: ['local-projects'],
    queryFn: () => legacyApi.projects(),
    enabled: open && activeTab === 'general',
  });

  const commitDisplayName = () => {
    const cachedSettings = queryClient.getQueryData<AppSettings>(['settings']);
    const savedName = cachedSettings?.display_name ?? settingsQuery.data?.display_name ?? '';
    const draft = displayNameDraftRef.current;
    const trimmed = draft.trim();
    if (!trimmed) {
      setDisplayNameDraft(savedName);
      return;
    }
    if (trimmed !== draft) {
      setDisplayNameDraft(trimmed);
    }
    if ((cachedSettings || settingsQuery.data) && trimmed !== savedName) {
      updateSettingsMutation.mutate({ display_name: trimmed });
    }
  };

  const handleClose = () => {
    commitDisplayName();
    close();
  };

  useEffect(() => {
    const wasOpen = wasOpenRef.current;
    wasOpenRef.current = open;
    if (!open) {
      if (wasOpen) {
        commitDisplayName();
      }
      lastSyncedDisplayNameRef.current = null;
      lastSyncedTimezoneRef.current = null;
      return;
    }
    const s = settingsQuery.data;
    if (!s) return;
    const nextName = s.display_name ?? '';
    const nextTz = s.timezone || 'UTC';
    if (lastSyncedDisplayNameRef.current !== nextName) {
      lastSyncedDisplayNameRef.current = nextName;
      setDisplayNameDraft(nextName);
    }
    if (lastSyncedTimezoneRef.current !== nextTz) {
      lastSyncedTimezoneRef.current = nextTz;
      setTimezoneDraft(nextTz);
    }
  }, [open, settingsQuery.data]);

  const autoReviewQuery = useQuery({
    queryKey: ['auto-review'],
    queryFn: () => settingsApi.getAutoReview(),
    enabled: open && activeTab === 'general',
  });

  useEffect(() => {
    if (autoReviewQuery.data?.rules) {
      setRulesDraft(autoReviewQuery.data.rules);
    }
  }, [autoReviewQuery.data]);

  const computerQuery = useQuery({
    queryKey: ['computer-status', 'default'],
    queryFn: () => computerApi.status('default'),
    enabled: open && activeTab === 'computer',
  });

  const vaultQuery = useQuery({
    queryKey: ['vault-secrets'],
    queryFn: () => vaultApi.list(),
    enabled: open && activeTab === 'vault',
  });

  const usageQuery = useQuery({
    queryKey: ['usage-stats'],
    queryFn: () => usageApi.get(),
    enabled: open && activeTab === 'usage',
  });

  const systemInfoQuery = useQuery({
    queryKey: ['system-info'],
    queryFn: () => legacyApi.systemInfo(),
    enabled: open && activeTab === 'system',
  });

  const tasksQuery = useQuery({
    queryKey: ['runtime-tasks'],
    queryFn: () => legacyApi.tasks(),
    enabled: open && activeTab === 'system',
  });

  type SettingsMutationContext = {
    previous: AppSettings | undefined;
    patch: Partial<AppSettings>;
    seq: number;
    prevUiTheme: ThemeMode;
    prevUiAccent: AccentMode;
  };

  const updateSettingsMutation = useMutation<
    AppSettings,
    Error,
    Partial<AppSettings>,
    SettingsMutationContext
  >({
    mutationFn: (patch) => settingsApi.update(patch),
    onMutate: async (patch) => {
      pendingSettingsCountRef.current += 1;
      const seq = (mutationSeqRef.current += 1);
      const prevUiTheme = useUiStore.getState().theme;
      const prevUiAccent = useUiStore.getState().accentMode;

      const normalizedPatch: Partial<AppSettings> = { ...patch };
      if (
        patch.default_engine !== undefined &&
        patch.default_engine_id === undefined
      ) {
        normalizedPatch.default_engine_id = patch.default_engine;
      } else if (
        patch.default_engine_id !== undefined &&
        patch.default_engine === undefined
      ) {
        normalizedPatch.default_engine = patch.default_engine_id;
      }
      if (
        patch.default_model !== undefined &&
        patch.default_model_id === undefined
      ) {
        normalizedPatch.default_model_id = patch.default_model;
      } else if (
        patch.default_model_id !== undefined &&
        patch.default_model === undefined
      ) {
        normalizedPatch.default_model = patch.default_model_id;
      }

      for (const key of Object.keys(normalizedPatch)) {
        lastKeySeqRef.current[key] = seq;
      }

      if (normalizedPatch.theme !== undefined) {
        setTheme(normalizedPatch.theme);
      }
      if (normalizedPatch.accent_mode !== undefined) {
        setAccentMode(normalizedPatch.accent_mode);
      }

      const previous = queryClient.getQueryData<AppSettings>(['settings']);
      queryClient.setQueryData<AppSettings>(['settings'], (old) =>
        old ? { ...old, ...normalizedPatch } : undefined,
      );
      await queryClient.cancelQueries({ queryKey: ['settings'] });

      return {
        previous,
        patch: normalizedPatch,
        seq,
        prevUiTheme,
        prevUiAccent,
      };
    },
    onSuccess: (updated, _patch, context) => {
      if (
        pendingSettingsCountRef.current <= 1 &&
        context?.seq === mutationSeqRef.current
      ) {
        queryClient.setQueryData<AppSettings>(['settings'], updated);
      }
    },
    onError: (err, patch, context) => {
      const rolledBackPatch = context?.patch ?? patch;
      if (context?.previous) {
        const prev = context.previous;
        queryClient.setQueryData<AppSettings>(['settings'], (old) => {
          if (
            pendingSettingsCountRef.current <= 1 &&
            context.seq === mutationSeqRef.current
          ) {
            return prev;
          }
          if (!old) return prev;
          const reverted: Record<string, unknown> = { ...old };
          for (const key of Object.keys(rolledBackPatch)) {
            if (lastKeySeqRef.current[key] !== context.seq) {
              continue;
            }
            if (key in prev) {
              reverted[key] = prev[key];
            } else {
              delete reverted[key];
            }
          }
          return reverted as AppSettings;
        });
      }
      if (
        rolledBackPatch.theme !== undefined &&
        lastKeySeqRef.current.theme === context?.seq
      ) {
        setTheme(context?.previous?.theme ?? context?.prevUiTheme ?? 'light');
      }
      if (
        rolledBackPatch.accent_mode !== undefined &&
        lastKeySeqRef.current.accent_mode === context?.seq
      ) {
        setAccentMode(
          context?.previous?.accent_mode ?? context?.prevUiAccent ?? 'bot_color',
        );
      }
      pushToast({
        tone: 'error',
        title: 'Could not save setting',
        description: err.message,
      });
    },
    onSettled: (_data, _err, patch, context) => {
      pendingSettingsCountRef.current = Math.max(
        0,
        pendingSettingsCountRef.current - 1,
      );
      const settledPatch = context?.patch ?? patch;
      const seq = context?.seq;
      if (seq !== undefined) {
        setOptimisticToggles((prev) => {
          let changed = false;
          const next = { ...prev };
          for (const key of SETTINGS_TOGGLE_KEYS) {
            if (
              settledPatch[key] !== undefined &&
              lastKeySeqRef.current[key] === seq &&
              key in next
            ) {
              delete next[key];
              changed = true;
            }
          }
          return changed ? next : prev;
        });
      }
      if (pendingSettingsCountRef.current === 0) {
        void queryClient.invalidateQueries({ queryKey: ['settings'] });
      }
    },
  });

  const saveRulesMutation = useMutation({
    mutationFn: (rules: AutoReviewRule[]) => settingsApi.putAutoReview(rules),
    onSuccess: (res) => {
      setRulesDraft(res.rules);
      void queryClient.invalidateQueries({ queryKey: ['auto-review'] });
      pushToast({ tone: 'success', title: 'Auto-review rules saved' });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not save rules', description: err.message });
    },
  });

  const buildVaultFields = (): Record<string, string> => {
    const out: Record<string, string> = {};
    for (const row of secretFields) {
      const k = row.key.trim();
      if (k && row.value) {
        out[k] = row.value;
      }
    }
    return out;
  };

  const addSecretMutation = useMutation({
    mutationFn: () => {
      const extraFields = buildVaultFields();
      return vaultApi.create({
        name: secretName.trim(),
        domain: secretDomain.trim(),
        kind: 'credential',
        username: secretUsername.trim(),
        secret_value: secretValue,
        value: secretValue,
        fields: extraFields,
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['vault-secrets'] });
      setSecretName('');
      setSecretDomain('');
      setSecretUsername('');
      setSecretValue('');
      setSecretFields([]);
      pushToast({ tone: 'success', title: 'Secret stored securely' });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not save secret', description: err.message });
    },
  });

  const deleteSecretMutation = useMutation({
    mutationFn: (id: string) => vaultApi.remove(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['vault-secrets'] });
      pushToast({ tone: 'info', title: 'Secret deleted' });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not delete secret', description: err.message });
    },
  });

  const submitTaskMutation = useMutation({
    mutationFn: () =>
      legacyApi.submitTask({
        query: taskQuery.trim(),
        facility_id: taskFacility.trim() || 'facility-a',
      }),
    onSuccess: () => {
      setTaskQuery('');
      void queryClient.invalidateQueries({ queryKey: ['runtime-tasks'] });
      pushToast({ tone: 'success', title: 'Industrial runtime task submitted' });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not submit task', description: err.message });
    },
  });

  const cancelTaskMutation = useMutation({
    mutationFn: (runId: string) => legacyApi.cancelTask(runId),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['runtime-tasks'] });
      pushToast({ tone: 'info', title: 'Task cancelled' });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not cancel task', description: err.message });
    },
  });

  const resumeTaskMutation = useMutation({
    mutationFn: ({ runId, humanInput }: { runId: string; humanInput: Record<string, unknown> }) =>
      legacyApi.resumeTask(runId, humanInput),
    onSuccess: (_res, vars) => {
      setResumeInputs((prev) => {
        const next = { ...prev };
        delete next[vars.runId];
        return next;
      });
      void queryClient.invalidateQueries({ queryKey: ['runtime-tasks'] });
      pushToast({ tone: 'success', title: 'Runtime task resumed' });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not resume task', description: err.message });
    },
  });

  const handleThemeChange = (next: ThemeMode) => {
    updateSettingsMutation.mutate({ theme: next });
  };

  const handleAccentChange = (next: AccentMode) => {
    updateSettingsMutation.mutate({ accent_mode: next });
  };

  const addRule = (e: React.FormEvent) => {
    e.preventDefault();
    if (!newRuleText.trim()) return;
    const next: AutoReviewRule[] = [
      ...rulesDraft,
      {
        id: `rule_${Date.now().toString(36)}`,
        mode: newRuleMode,
        text: newRuleText.trim(),
      },
    ];
    setNewRuleText('');
    saveRulesMutation.mutate(next);
  };

  const removeRule = (id: string) => {
    const next = rulesDraft.filter((r) => r.id !== id);
    saveRulesMutation.mutate(next);
  };

  const computer = computerQuery.data;
  const settings = settingsQuery.data;
  const allowHydrogen =
    optimisticToggles.allow_hydrogen ?? Boolean(settings?.allow_hydrogen);
  const currentEngine = (settings?.default_engine_id ?? settings?.default_engine ?? 'agy') as EngineId;
  const currentModel = settings?.default_model_id ?? settings?.default_model ?? 'gemini-2.5-pro';
  const currentThinking = (settings?.default_thinking_level ?? 'medium') as ThinkingLevel;
  const availableModels = (modelsQuery.data?.models ?? []).filter(
    (m) => allowHydrogen || !m.is_hydrogen,
  );
  const hasCurrentModelOption = availableModels.some((m) => m.id === currentModel);
  const hasVaultPayload = Boolean(
    secretValue ||
      secretUsername.trim() ||
      Object.keys(buildVaultFields()).length > 0,
  );

  return (
    <Modal
      open={open}
      onClose={handleClose}
      title="Settings"
      maxWidthClass="max-w-3xl"
    >
      <div className="flex flex-col sm:flex-row min-h-[460px]">
        {/* Sidebar Tabs */}
        <nav
          className="sm:w-48 p-2.5 flex sm:flex-col gap-1 overflow-x-auto shrink-0"
          style={{
            backgroundColor: 'var(--bg-sidebar)',
            borderRight: '1px solid var(--border-subtle)',
          }}
        >
          {TABS.map((t) => {
            const Icon = t.icon;
            const active = activeTab === t.id;
            return (
              <button
                key={t.id}
                type="button"
                aria-label={`${t.label}`}
                onClick={() => setTab(t.id)}
                className="flex items-center gap-2 px-3 py-2 rounded-xl text-[13px] font-medium whitespace-nowrap transition-colors"
                style={{
                  backgroundColor: active ? 'var(--bg-active)' : 'transparent',
                  color: active ? 'var(--text-primary)' : 'var(--text-secondary)',
                }}
              >
                <Icon size={15} strokeWidth={1.75} />
                <span>{t.label}</span>
              </button>
            );
          })}
        </nav>

        {/* Content Pane */}
        <div className="flex-1 p-5 space-y-6 overflow-y-auto max-h-[70vh]">
          {activeTab === 'general' && (
            <>
              {/* Appearance */}
              <section className="space-y-3">
                <div>
                  <h3 className="text-[14px] font-semibold">Appearance</h3>
                  <p className="text-[12.5px]" style={{ color: 'var(--text-secondary)' }}>
                    Calm Daylight light mode by default, or switch to dark or follow system.
                  </p>
                </div>

                <div className="grid grid-cols-3 gap-2">
                  {(
                    [
                      { id: 'light', label: 'Light' },
                      { id: 'dark', label: 'Dark' },
                      { id: 'system', label: 'Follow system' },
                    ] as const
                  ).map((opt) => (
                    <button
                      key={opt.id}
                      type="button"
                      aria-label={`${opt.label}`}
                      onClick={() => handleThemeChange(opt.id)}
                      className="px-3 py-2 rounded-xl text-[13px] font-medium transition-colors"
                      style={{
                        backgroundColor:
                          theme === opt.id ? 'var(--bg-active)' : 'var(--bg-sidebar)',
                        border:
                          theme === opt.id
                            ? '1.5px solid var(--text-primary)'
                            : '1px solid var(--border-subtle)',
                      }}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>

                <div>
                  <div className="text-[12px] font-medium mb-1.5" style={{ color: 'var(--text-secondary)' }}>
                    Accent color
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    {(
                      [
                        { id: 'bot_color', label: 'Bot color (adaptive)' },
                        { id: 'black', label: 'Black (monochrome)' },
                      ] as const
                    ).map((opt) => (
                      <button
                        key={opt.id}
                        type="button"
                        aria-label={`${opt.label}`}
                        onClick={() => handleAccentChange(opt.id)}
                        className="px-3 py-2 rounded-xl text-[13px] font-medium"
                        style={{
                          backgroundColor:
                            accentMode === opt.id ? 'var(--bg-active)' : 'var(--bg-sidebar)',
                          border:
                            accentMode === opt.id
                              ? '1.5px solid var(--text-primary)'
                              : '1px solid var(--border-subtle)',
                        }}
                      >
                        {opt.label}
                      </button>
                    ))}
                  </div>
                </div>
              </section>

              {/* Workspace & Defaults (all remaining AppSettings fields) */}
              <section
                className="space-y-4 pt-4"
                style={{ borderTop: '1px solid var(--border-subtle)' }}
              >
                <div>
                  <h3 className="text-[14px] font-semibold">Workspace &amp; Defaults</h3>
                  <p className="text-[12.5px]" style={{ color: 'var(--text-secondary)' }}>
                    Operator identity, default model/engine, workspace project, and notifications.
                  </p>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label
                      htmlFor="settings-display-name"
                      className="block text-[12px] font-medium mb-1"
                      style={{ color: 'var(--text-secondary)' }}
                    >
                      Display name
                    </label>
                    <input
                      id="settings-display-name"
                      type="text"
                      maxLength={80}
                      value={displayNameDraft}
                      onChange={(e) => setDisplayNameDraft(e.target.value)}
                      onBlur={commitDisplayName}
                      placeholder="Operator"
                      className="w-full px-3 py-1.5 rounded-lg text-[13px] outline-none"
                      style={{
                        backgroundColor: 'var(--bg-sidebar)',
                        border: '1px solid var(--border-strong)',
                      }}
                    />
                  </div>

                  <div>
                    <label
                      htmlFor="settings-timezone"
                      className="block text-[12px] font-medium mb-1"
                      style={{ color: 'var(--text-secondary)' }}
                    >
                      Timezone
                    </label>
                    <select
                      id="settings-timezone"
                      aria-label="Default timezone"
                      value={timezoneDraft || 'UTC'}
                      onChange={(e) => {
                        const next = e.target.value;
                        setTimezoneDraft(next);
                        if (next.trim()) {
                          updateSettingsMutation.mutate({ timezone: next });
                        }
                      }}
                      className="w-full px-2.5 py-1.5 rounded-lg text-[13px] outline-none"
                      style={{
                        backgroundColor: 'var(--bg-sidebar)',
                        border: '1px solid var(--border-strong)',
                      }}
                    >
                      {timezoneDraft && !TIMEZONES.includes(timezoneDraft) && (
                        <option value={timezoneDraft}>{timezoneDraft}</option>
                      )}
                      {TIMEZONES.map((tz) => (
                        <option key={tz} value={tz}>
                          {tz}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label
                      htmlFor="settings-default-engine"
                      className="block text-[12px] font-medium mb-1"
                      style={{ color: 'var(--text-secondary)' }}
                    >
                      Default engine
                    </label>
                    <select
                      id="settings-default-engine"
                      aria-label="Default engine"
                      value={currentEngine}
                      onChange={(e) => {
                        const val = e.target.value as EngineId;
                        updateSettingsMutation.mutate({
                          default_engine: val,
                          default_engine_id: val,
                        });
                      }}
                      className="w-full px-2.5 py-1.5 rounded-lg text-[13px] outline-none"
                      style={{
                        backgroundColor: 'var(--bg-sidebar)',
                        border: '1px solid var(--border-strong)',
                      }}
                    >
                      <option value="agy">AGY Assistant</option>
                      <option value="controlbot_runtime">ControlBot Runtime</option>
                    </select>
                  </div>

                  <div>
                    <label
                      htmlFor="settings-default-model"
                      className="block text-[12px] font-medium mb-1"
                      style={{ color: 'var(--text-secondary)' }}
                    >
                      Default model
                    </label>
                    <select
                      id="settings-default-model"
                      aria-label="Default model"
                      value={currentModel}
                      onChange={(e) => {
                        const val = e.target.value;
                        updateSettingsMutation.mutate({
                          default_model: val,
                          default_model_id: val,
                        });
                      }}
                      className="w-full px-2.5 py-1.5 rounded-lg text-[13px] outline-none"
                      style={{
                        backgroundColor: 'var(--bg-sidebar)',
                        border: '1px solid var(--border-strong)',
                      }}
                    >
                      {!hasCurrentModelOption && (
                        <option value={currentModel}>{currentModel}</option>
                      )}
                      {availableModels.map((m) => (
                        <option key={m.id} value={m.id}>
                          {m.label || m.id}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label
                      htmlFor="settings-default-thinking"
                      className="block text-[12px] font-medium mb-1"
                      style={{ color: 'var(--text-secondary)' }}
                    >
                      Default thinking level
                    </label>
                    <select
                      id="settings-default-thinking"
                      aria-label="Default thinking level"
                      value={currentThinking}
                      onChange={(e) =>
                        updateSettingsMutation.mutate({
                          default_thinking_level: e.target.value as ThinkingLevel,
                        })
                      }
                      className="w-full px-2.5 py-1.5 rounded-lg text-[13px] outline-none"
                      style={{
                        backgroundColor: 'var(--bg-sidebar)',
                        border: '1px solid var(--border-strong)',
                      }}
                    >
                      {THINKING_LEVELS.map((lvl) => (
                        <option key={lvl.id} value={lvl.id}>
                          {lvl.label}
                        </option>
                      ))}
                    </select>
                  </div>

                  <div>
                    <label
                      htmlFor="settings-default-project"
                      className="block text-[12px] font-medium mb-1"
                      style={{ color: 'var(--text-secondary)' }}
                    >
                      Default project workspace
                    </label>
                    <select
                      id="settings-default-project"
                      aria-label="Default project workspace"
                      value={settings?.default_project_name ?? ''}
                      onChange={(e) =>
                        updateSettingsMutation.mutate({
                          default_project_name: e.target.value || null,
                        })
                      }
                      className="w-full px-2.5 py-1.5 rounded-lg text-[13px] outline-none"
                      style={{
                        backgroundColor: 'var(--bg-sidebar)',
                        border: '1px solid var(--border-strong)',
                      }}
                    >
                      <option value="">Default workspace</option>
                      {settings?.default_project_name &&
                        !(projectsQuery.data?.projects ?? []).some(
                          (p) => p.name === settings.default_project_name,
                        ) && (
                          <option value={settings.default_project_name}>
                            {settings.default_project_name}
                          </option>
                        )}
                      {(projectsQuery.data?.projects ?? []).map((p) => (
                        <option key={p.name} value={p.name}>
                          {p.name}
                        </option>
                      ))}
                    </select>
                  </div>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5 pt-1">
                  {(
                    [
                      {
                        key: 'allow_hydrogen',
                        label: 'Allow Hydrogen models',
                        checked:
                          optimisticToggles.allow_hydrogen ??
                          Boolean(settings?.allow_hydrogen),
                      },
                      {
                        key: 'include_browser_context',
                        label: 'Include browser context by default',
                        checked:
                          optimisticToggles.include_browser_context ??
                          Boolean(settings?.include_browser_context),
                      },
                      {
                        key: 'notifications_enabled',
                        label: 'Desktop notifications enabled',
                        checked:
                          optimisticToggles.notifications_enabled ??
                          settings?.notifications_enabled ??
                          true,
                      },
                      {
                        key: 'sound_enabled',
                        label: 'Notification sounds enabled',
                        checked:
                          optimisticToggles.sound_enabled ??
                          settings?.sound_enabled ??
                          true,
                      },
                      {
                        key: 'auto_open_computer',
                        label: 'Auto-open Computer panel on activity',
                        checked:
                          optimisticToggles.auto_open_computer ??
                          Boolean(settings?.auto_open_computer),
                      },
                    ] as const
                  ).map((toggle) => (
                    <label
                      key={toggle.key}
                      className="flex items-center justify-between gap-2 px-3 py-2 rounded-xl text-[12.5px] cursor-pointer"
                      style={{
                        backgroundColor: 'var(--bg-sidebar)',
                        border: '1px solid var(--border-subtle)',
                      }}
                    >
                      <span>{toggle.label}</span>
                      <input
                        type="checkbox"
                        aria-label={`${toggle.label}`}
                        checked={toggle.checked}
                        onChange={(e) => {
                          const next = e.target.checked;
                          setOptimisticToggles((prev) => ({
                            ...prev,
                            [toggle.key]: next,
                          }));
                          updateSettingsMutation.mutate({ [toggle.key]: next });
                        }}
                      />
                    </label>
                  ))}
                </div>
              </section>

              {/* Auto-Review Rules */}
              <section
                className="space-y-3 pt-4"
                style={{ borderTop: '1px solid var(--border-subtle)' }}
              >
                <div className="flex items-center gap-2">
                  <Shield size={15} style={{ color: 'var(--accent-computer)' }} />
                  <h3 className="text-[14px] font-semibold">Auto-review rules</h3>
                </div>
                <p className="text-[12.5px]" style={{ color: 'var(--text-secondary)' }}>
                  Natural-language policies for actions bots can run automatically or must ask first.
                </p>

                <form onSubmit={addRule} className="flex flex-col sm:flex-row gap-2">
                  <select
                    aria-label="Auto-review rule mode"
                    value={newRuleMode}
                    onChange={(e) =>
                      setNewRuleMode(e.target.value as 'allow_auto' | 'ask_first')
                    }
                    className="px-2.5 py-2 rounded-lg text-[12.5px] outline-none"
                    style={{
                      backgroundColor: 'var(--bg-sidebar)',
                      border: '1px solid var(--border-strong)',
                    }}
                  >
                    <option value="allow_auto">Allow automatically</option>
                    <option value="ask_first">Ask first</option>
                  </select>
                  <input
                    type="text"
                    aria-label="New auto-review rule pattern"
                    value={newRuleText}
                    onChange={(e) => setNewRuleText(e.target.value)}
                    placeholder="e.g. Allow read-only git status and log checks"
                    className="flex-1 px-3 py-2 rounded-lg text-[13px] outline-none"
                    style={{
                      backgroundColor: 'var(--bg-sidebar)',
                      border: '1px solid var(--border-strong)',
                    }}
                  />
                  <button
                    type="submit"
                    disabled={!newRuleText.trim() || saveRulesMutation.isPending}
                    className="inline-flex items-center justify-center gap-1 px-3.5 py-2 rounded-lg text-[12.5px] font-medium disabled:opacity-45"
                    style={{
                      backgroundColor: 'var(--accent-primary)',
                      color: 'var(--bg-canvas)',
                    }}
                  >
                    <Plus size={14} />
                    Add
                  </button>
                </form>

                <div className="space-y-1.5">
                  {rulesDraft.length === 0 ? (
                    <div className="text-[12.5px] py-3" style={{ color: 'var(--text-muted)' }}>
                      No custom auto-review rules configured yet.
                    </div>
                  ) : (
                    rulesDraft.map((rule) => (
                      <div
                        key={rule.id}
                        className="flex items-center justify-between gap-3 px-3 py-2 rounded-xl"
                        style={{
                          backgroundColor: 'var(--bg-sidebar)',
                          border: '1px solid var(--border-subtle)',
                        }}
                      >
                        <div className="min-w-0 flex items-center gap-2">
                          <span
                            className="px-2 py-0.5 rounded-full text-[11px] font-medium shrink-0"
                            style={{
                              backgroundColor:
                                rule.mode === 'allow_auto'
                                  ? 'var(--status-ok-bg)'
                                  : 'var(--status-warn-bg)',
                              color:
                                rule.mode === 'allow_auto'
                                  ? 'var(--status-ok)'
                                  : 'var(--status-warn)',
                            }}
                          >
                            {rule.mode === 'allow_auto' ? 'Allow auto' : 'Ask first'}
                          </span>
                          <span className="text-[13px] truncate">{rule.text}</span>
                        </div>
                        {rule.locked_by_admin ? (
                          <span
                            className="inline-flex items-center gap-1 text-[11px] shrink-0"
                            style={{ color: 'var(--text-muted)' }}
                          >
                            <Lock size={11} />
                            Admin
                          </span>
                        ) : (
                          <button
                            type="button"
                            onClick={() => removeRule(rule.id)}
                            title="Delete rule"
                            aria-label={`Delete rule ${rule.text}`}
                            className="p-1 rounded hover:bg-[var(--status-danger-bg)] shrink-0"
                            style={{ color: 'var(--status-danger)' }}
                          >
                            <Trash2 size={13.5} />
                          </button>
                        )}
                      </div>
                    ))
                  )}
                </div>
              </section>
            </>
          )}

          {activeTab === 'computer' && (
            <section className="space-y-4">
              <div>
                <h3 className="text-[14px] font-semibold">Bot Computer</h3>
                <p className="text-[12.5px]" style={{ color: 'var(--text-secondary)' }}>
                  Manage VM Desktop (noVNC), Live Browser (Playwright), and Takeover locks.
                </p>
              </div>

              <div
                className="p-4 rounded-xl space-y-3"
                style={{
                  backgroundColor: 'var(--bg-sidebar)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <div className="grid grid-cols-2 gap-3 text-[13px]">
                  <div>
                    <div className="text-[11.5px]" style={{ color: 'var(--text-muted)' }}>
                      VM status
                    </div>
                    <div className="font-medium capitalize">{computer?.status || 'ready'}</div>
                  </div>
                  <div>
                    <div className="text-[11.5px]" style={{ color: 'var(--text-muted)' }}>
                      Control owner
                    </div>
                    <div className="font-medium">
                      {computer?.control_owner === 'human_takeover'
                        ? 'Human takeover active'
                        : 'Agent'}
                    </div>
                  </div>
                  <div>
                    <div className="text-[11.5px]" style={{ color: 'var(--text-muted)' }}>
                      VNC desktop
                    </div>
                    <div className="font-medium">
                      {computer?.vnc_available ? 'Available' : 'Offline'}
                    </div>
                  </div>
                  <div>
                    <div className="text-[11.5px]" style={{ color: 'var(--text-muted)' }}>
                      Live Browser (Playwright)
                    </div>
                    <div className="font-medium">
                      {computer?.browser_running ? 'Running' : 'Stopped'}
                    </div>
                  </div>
                </div>

                <div className="flex flex-wrap gap-2 pt-2" style={{ borderTop: '1px solid var(--border-subtle)' }}>
                  <button
                    type="button"
                    onClick={() => {
                      openInspectorTab('computer');
                      handleClose();
                    }}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12.5px] font-medium text-white"
                    style={{ backgroundColor: 'var(--accent-computer)' }}
                  >
                    <Monitor size={14} />
                    Open Computer panel
                  </button>

                  {computer?.browser_running ? (
                    <button
                      type="button"
                      disabled={computerActionPending}
                      onClick={async () => {
                        setComputerActionPending(true);
                        try {
                          const res = await computerApi.action('default', { type: 'stop' });
                          setComputerStatus(res.status);
                          void queryClient.invalidateQueries({ queryKey: ['computer-status'] });
                          pushToast({ tone: 'info', title: 'Live Browser stopped' });
                        } catch (err) {
                          pushToast({
                            tone: 'error',
                            title: 'Could not stop browser',
                            description: err instanceof Error ? err.message : 'Request failed',
                          });
                        } finally {
                          setComputerActionPending(false);
                        }
                      }}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12.5px] font-medium disabled:opacity-50"
                      style={{
                        backgroundColor: 'var(--bg-canvas)',
                        border: '1px solid var(--border-strong)',
                      }}
                    >
                      <Square size={12} />
                      Stop browser
                    </button>
                  ) : (
                    <button
                      type="button"
                      disabled={computerActionPending}
                      onClick={async () => {
                        setComputerActionPending(true);
                        try {
                          const res = await computerApi.action('default', { type: 'start' });
                          setComputerStatus(res.status);
                          void queryClient.invalidateQueries({ queryKey: ['computer-status'] });
                          pushToast({ tone: 'success', title: 'Live Browser started' });
                        } catch (err) {
                          pushToast({
                            tone: 'error',
                            title: 'Could not start browser',
                            description: err instanceof Error ? err.message : 'Request failed',
                          });
                        } finally {
                          setComputerActionPending(false);
                        }
                      }}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12.5px] font-medium disabled:opacity-50"
                      style={{
                        backgroundColor: 'var(--bg-canvas)',
                        border: '1px solid var(--border-strong)',
                      }}
                    >
                      <Play size={12} />
                      Start browser
                    </button>
                  )}

                  {computer?.control_owner === 'human_takeover' && (
                    <button
                      type="button"
                      disabled={computerActionPending}
                      onClick={async () => {
                        setComputerActionPending(true);
                        try {
                          const st = await computerApi.handback('default');
                          setComputerStatus(st);
                          void queryClient.invalidateQueries({ queryKey: ['computer-status'] });
                          pushToast({ tone: 'success', title: 'Handed back to agent' });
                        } catch (err) {
                          pushToast({
                            tone: 'error',
                            title: 'Handback failed',
                            description: err instanceof Error ? err.message : 'Request failed',
                          });
                        } finally {
                          setComputerActionPending(false);
                        }
                      }}
                      className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12.5px] font-medium text-white disabled:opacity-50"
                      style={{ backgroundColor: '#15803D' }}
                    >
                      <CheckCircle2 size={13.5} />
                      Force handback
                    </button>
                  )}
                </div>
              </div>
            </section>
          )}

          {activeTab === 'vault' && (
            <section className="space-y-4">
              <div>
                <h3 className="text-[14px] font-semibold">Vault</h3>
                <p className="text-[12.5px]" style={{ color: 'var(--text-secondary)' }}>
                  Encrypted credentials injected directly into forms — plaintext values are never returned or shown to models.
                </p>
              </div>

              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  if (secretName.trim() && hasVaultPayload) addSecretMutation.mutate();
                }}
                className="p-3.5 rounded-xl space-y-2.5"
                style={{
                  backgroundColor: 'var(--bg-sidebar)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  <input
                    type="text"
                    required
                    aria-label="Secret label"
                    value={secretName}
                    onChange={(e) => setSecretName(e.target.value)}
                    placeholder="Label (e.g. Stripe API Key)"
                    className="px-3 py-1.5 rounded-lg text-[13px] outline-none bg-[var(--bg-canvas)] border border-[var(--border-strong)]"
                  />
                  <input
                    type="text"
                    aria-label="Secret domain"
                    value={secretDomain}
                    onChange={(e) => setSecretDomain(e.target.value)}
                    placeholder="Domain (optional)"
                    className="px-3 py-1.5 rounded-lg text-[13px] outline-none bg-[var(--bg-canvas)] border border-[var(--border-strong)]"
                  />
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  <input
                    type="text"
                    aria-label="Secret username"
                    value={secretUsername}
                    onChange={(e) => setSecretUsername(e.target.value)}
                    placeholder="Username / email (optional)"
                    className="px-3 py-1.5 rounded-lg text-[13px] outline-none bg-[var(--bg-canvas)] border border-[var(--border-strong)]"
                  />
                  <input
                    type="password"
                    autoComplete="off"
                    aria-label="Secret value"
                    value={secretValue}
                    onChange={(e) => setSecretValue(e.target.value)}
                    placeholder="Secret / password"
                    className="px-3 py-1.5 rounded-lg text-[13px] outline-none bg-[var(--bg-canvas)] border border-[var(--border-strong)]"
                  />
                </div>

                {secretFields.length > 0 && (
                  <div className="space-y-1.5 pt-1">
                    {secretFields.map((row, idx) => (
                      <div key={idx} className="flex gap-2 items-center">
                        <input
                          type="text"
                          aria-label={`Extra field name ${idx + 1}`}
                          value={row.key}
                          onChange={(e) =>
                            setSecretFields((prev) =>
                              prev.map((item, i) =>
                                i === idx ? { ...item, key: e.target.value } : item,
                              ),
                            )
                          }
                          placeholder="Field key (e.g. api_token)"
                          className="w-1/2 px-2.5 py-1 rounded-lg text-[12px] outline-none bg-[var(--bg-canvas)] border border-[var(--border-strong)]"
                        />
                        <input
                          type="password"
                          autoComplete="off"
                          aria-label={`Extra field value ${idx + 1}`}
                          value={row.value}
                          onChange={(e) =>
                            setSecretFields((prev) =>
                              prev.map((item, i) =>
                                i === idx ? { ...item, value: e.target.value } : item,
                              ),
                            )
                          }
                          placeholder="Field value"
                          className="w-1/2 px-2.5 py-1 rounded-lg text-[12px] outline-none bg-[var(--bg-canvas)] border border-[var(--border-strong)]"
                        />
                        <button
                          type="button"
                          aria-label={`Remove field ${idx + 1}`}
                          onClick={() =>
                            setSecretFields((prev) => prev.filter((_, i) => i !== idx))
                          }
                          className="p-1 rounded hover:bg-[var(--status-danger-bg)] shrink-0"
                          style={{ color: 'var(--status-danger)' }}
                        >
                          <Trash2 size={13} />
                        </button>
                      </div>
                    ))}
                  </div>
                )}

                <div className="flex items-center justify-between gap-2 pt-1">
                  <button
                    type="button"
                    onClick={() =>
                      setSecretFields((prev) => [...prev, { key: '', value: '' }])
                    }
                    className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[12px] font-medium hover:bg-[var(--bg-subtle)]"
                    style={{ color: 'var(--text-secondary)' }}
                  >
                    <Plus size={13} />
                    Add custom field
                  </button>
                  <button
                    type="submit"
                    disabled={!secretName.trim() || !hasVaultPayload || addSecretMutation.isPending}
                    className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-[12.5px] font-medium text-white disabled:opacity-45"
                    style={{ backgroundColor: 'var(--accent-computer)' }}
                  >
                    <Check size={14} />
                    Store
                  </button>
                </div>
              </form>

              <div className="space-y-1.5">
                {vaultQuery.isError ? (
                  <div
                    className="p-3 rounded-xl flex items-center justify-between gap-2 text-[12.5px]"
                    style={{
                      backgroundColor: 'var(--status-danger-bg)',
                      color: 'var(--status-danger)',
                    }}
                  >
                    <span className="inline-flex items-center gap-2">
                      <AlertCircle size={14} />
                      {vaultQuery.error instanceof Error
                        ? vaultQuery.error.message
                        : 'Could not load vault secrets.'}
                    </span>
                    <button
                      type="button"
                      onClick={() => void vaultQuery.refetch()}
                      className="px-2 py-0.5 rounded text-[11.5px] font-medium"
                      style={{
                        backgroundColor: 'var(--bg-canvas)',
                        color: 'var(--text-primary)',
                      }}
                    >
                      Retry
                    </button>
                  </div>
                ) : (vaultQuery.data?.secrets ?? []).length === 0 ? (
                  <div className="text-[12.5px] py-4 text-center" style={{ color: 'var(--text-muted)' }}>
                    No secrets stored yet.
                  </div>
                ) : (
                  (vaultQuery.data?.secrets ?? []).map((sec) => (
                    <div
                      key={sec.id}
                      className="flex items-center justify-between gap-3 px-3 py-2 rounded-xl"
                      style={{
                        backgroundColor: 'var(--bg-sidebar)',
                        border: '1px solid var(--border-subtle)',
                      }}
                    >
                      <div className="min-w-0">
                        <div className="text-[13px] font-medium truncate">{sec.name}</div>
                        <div className="text-[11.5px] truncate" style={{ color: 'var(--text-muted)' }}>
                          {sec.domain || 'Global'} · {sec.kind}
                          {sec.username_hint ? ` · user: ${sec.username_hint}` : ''}
                          {sec.field_names && sec.field_names.length > 0
                            ? ` · fields: ${sec.field_names.join(', ')}`
                            : ''}
                          {' · ••••••••'}
                        </div>
                      </div>
                      <button
                        type="button"
                        aria-label={`Delete secret ${sec.name}`}
                        title="Delete secret"
                        onClick={() => deleteSecretMutation.mutate(sec.id)}
                        className="p-1.5 rounded hover:bg-[var(--status-danger-bg)] shrink-0"
                        style={{ color: 'var(--status-danger)' }}
                      >
                        <Trash2 size={14} />
                      </button>
                    </div>
                  ))
                )}
              </div>
            </section>
          )}

          {activeTab === 'usage' && (
            <section className="space-y-4">
              <div>
                <h3 className="text-[14px] font-semibold">Workspace usage</h3>
                <p className="text-[12.5px]" style={{ color: 'var(--text-secondary)' }}>
                  Live telemetry across your bots, threads, interactive Pages, and routines.
                </p>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                {[
                  { label: 'Bots', value: usageQuery.data?.bots_count ?? 0 },
                  { label: 'Group chats', value: usageQuery.data?.channels_count ?? 0 },
                  { label: 'Messages', value: usageQuery.data?.messages_count ?? 0 },
                  { label: 'Pages', value: usageQuery.data?.pages_count ?? 0 },
                  { label: 'Routines', value: usageQuery.data?.routines_count ?? 0 },
                  { label: 'Routine runs', value: usageQuery.data?.routine_runs_count ?? 0 },
                  { label: 'Approvals', value: usageQuery.data?.approvals_count ?? 0 },
                  { label: 'Active turns', value: usageQuery.data?.active_turns ?? 0 },
                ].map((stat) => (
                  <div
                    key={stat.label}
                    className="p-3 rounded-xl"
                    style={{
                      backgroundColor: 'var(--bg-sidebar)',
                      border: '1px solid var(--border-subtle)',
                    }}
                  >
                    <div className="text-[11.5px]" style={{ color: 'var(--text-muted)' }}>
                      {stat.label}
                    </div>
                    <div className="text-[20px] font-semibold tabular-nums mt-0.5">
                      {stat.value}
                    </div>
                  </div>
                ))}
              </div>
            </section>
          )}

          {activeTab === 'system' && (
            <section className="space-y-5">
              <div>
                <h3 className="text-[14px] font-semibold">System &amp; Industrial Runtime</h3>
                <p className="text-[12.5px]" style={{ color: 'var(--text-secondary)' }}>
                  Host diagnostics and ControlBot industrial runtime task queue.
                </p>
              </div>

              {systemInfoQuery.isError ? (
                <div
                  className="p-3 rounded-xl flex items-center justify-between gap-2 text-[12.5px]"
                  style={{
                    backgroundColor: 'var(--status-danger-bg)',
                    color: 'var(--status-danger)',
                  }}
                >
                  <span className="inline-flex items-center gap-2">
                    <AlertCircle size={14} />
                    {systemInfoQuery.error instanceof Error
                      ? systemInfoQuery.error.message
                      : 'Could not load system info.'}
                  </span>
                  <button
                    type="button"
                    onClick={() => void systemInfoQuery.refetch()}
                    className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11.5px] font-medium"
                    style={{
                      backgroundColor: 'var(--bg-canvas)',
                      color: 'var(--text-primary)',
                    }}
                  >
                    <RefreshCw size={11} />
                    Retry
                  </button>
                </div>
              ) : (
                <div
                  className="p-3.5 rounded-xl text-[12px] font-mono space-y-1"
                  style={{
                    backgroundColor: 'var(--bg-sidebar)',
                    border: '1px solid var(--border-subtle)',
                  }}
                >
                  {(
                    [
                      ['service', systemInfoQuery.data?.service],
                      ['runtime_mode', systemInfoQuery.data?.runtime_mode],
                      ['backend_mode', systemInfoQuery.data?.backend_mode],
                      ['llm_origin', systemInfoQuery.data?.llm_origin],
                      ['llm_model_id', systemInfoQuery.data?.llm_model_id],
                      ['db_path', systemInfoQuery.data?.db_path],
                      ['facility', systemInfoQuery.data?.facility],
                    ] as Array<[string, unknown]>
                  )
                    .filter(([, v]) => v !== undefined && v !== null)
                    .map(([k, v]) => (
                      <div key={k} className="flex justify-between gap-4">
                        <span style={{ color: 'var(--text-muted)' }}>{k}</span>
                        <span className="truncate max-w-[320px]">
                          {typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean'
                            ? String(v)
                            : JSON.stringify(v)}
                        </span>
                      </div>
                    ))}
                </div>
              )}

              {/* Submit Runtime Task */}
              <form
                onSubmit={(e) => {
                  e.preventDefault();
                  if (taskQuery.trim()) submitTaskMutation.mutate();
                }}
                className="space-y-2"
              >
                <div className="flex items-center gap-1.5 text-[13px] font-medium">
                  <Activity size={14} />
                  <span>Submit runtime task</span>
                </div>
                <div className="flex flex-col sm:flex-row gap-2">
                  <input
                    type="text"
                    aria-label="Facility ID"
                    value={taskFacility}
                    onChange={(e) => setTaskFacility(e.target.value)}
                    placeholder="facility-a"
                    className="sm:w-36 px-3 py-1.5 rounded-lg text-[13px] outline-none bg-[var(--bg-sidebar)] border border-[var(--border-strong)]"
                  />
                  <input
                    type="text"
                    aria-label="Runtime task query"
                    value={taskQuery}
                    onChange={(e) => setTaskQuery(e.target.value)}
                    placeholder="Task query for ControlBot runtime…"
                    className="flex-1 px-3 py-1.5 rounded-lg text-[13px] outline-none bg-[var(--bg-sidebar)] border border-[var(--border-strong)]"
                  />
                  <button
                    type="submit"
                    disabled={!taskQuery.trim() || submitTaskMutation.isPending}
                    className="px-3.5 py-1.5 rounded-lg text-[12.5px] font-medium disabled:opacity-45"
                    style={{
                      backgroundColor: 'var(--accent-primary)',
                      color: 'var(--bg-canvas)',
                    }}
                  >
                    Run task
                  </button>
                </div>
              </form>

              {/* Active / Recent Tasks */}
              <div className="space-y-1.5">
                <div className="text-[12px] font-medium" style={{ color: 'var(--text-secondary)' }}>
                  Runtime tasks ({(tasksQuery.data?.tasks ?? []).length})
                </div>
                {tasksQuery.isError ? (
                  <div
                    className="p-3 rounded-xl flex items-center justify-between gap-2 text-[12.5px]"
                    style={{
                      backgroundColor: 'var(--status-danger-bg)',
                      color: 'var(--status-danger)',
                    }}
                  >
                    <span className="inline-flex items-center gap-2">
                      <AlertCircle size={14} />
                      {tasksQuery.error instanceof Error
                        ? tasksQuery.error.message
                        : 'Could not load runtime tasks.'}
                    </span>
                    <button
                      type="button"
                      onClick={() => void tasksQuery.refetch()}
                      className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11.5px] font-medium"
                      style={{
                        backgroundColor: 'var(--bg-canvas)',
                        color: 'var(--text-primary)',
                      }}
                    >
                      <RefreshCw size={11} />
                      Retry
                    </button>
                  </div>
                ) : (tasksQuery.data?.tasks ?? []).length === 0 ? (
                  <div className="text-[12.5px] py-3" style={{ color: 'var(--text-muted)' }}>
                    No runtime tasks submitted yet.
                  </div>
                ) : (
                  (tasksQuery.data?.tasks ?? []).map((snap) => {
                    const statusUpper = (snap.status || '').toUpperCase();
                    const terminal = ['SUCCEEDED', 'PARTIAL', 'FAILED', 'CANCELLED'].includes(
                      statusUpper,
                    );
                    const waitingInput = statusUpper === 'WAITING_FOR_INPUT';
                    const requiredAction = snap.required_action ?? snap.run.required_action;
                    const transitionReason = snap.transition_reason ?? snap.run.transition_reason;
                    const resumeDraft = resumeInputs[snap.run.run_id] ?? '';

                    return (
                      <div
                        key={snap.run.run_id}
                        className="p-3 rounded-xl text-[12.5px] space-y-2"
                        style={{
                          backgroundColor: 'var(--bg-sidebar)',
                          border: '1px solid var(--border-subtle)',
                        }}
                      >
                        <div className="flex items-center justify-between gap-2">
                          <div className="min-w-0">
                            <div className="font-medium truncate">{snap.task.query}</div>
                            <div className="text-[11px] font-mono" style={{ color: 'var(--text-muted)' }}>
                              {snap.run.run_id} · {snap.status}
                            </div>
                          </div>
                          {!terminal && (
                            <button
                              type="button"
                              onClick={() => cancelTaskMutation.mutate(snap.run.run_id)}
                              disabled={cancelTaskMutation.isPending}
                              className="inline-flex items-center gap-1 px-2 py-1 rounded-lg text-[11.5px] hover:bg-[var(--status-danger-bg)] shrink-0 disabled:opacity-50"
                              style={{ color: 'var(--status-danger)' }}
                            >
                              <XCircle size={13} />
                              Cancel
                            </button>
                          )}
                        </div>

                        {waitingInput && (
                          <div
                            className="pt-2 space-y-2"
                            style={{ borderTop: '1px solid var(--border-subtle)' }}
                          >
                            {(requiredAction || transitionReason) && (
                              <div className="text-[11.5px]" style={{ color: 'var(--status-warn)' }}>
                                {requiredAction || transitionReason}
                              </div>
                            )}
                            <form
                              onSubmit={(e) => {
                                e.preventDefault();
                                const raw = resumeDraft.trim();
                                if (!raw) return;
                                let humanInput: Record<string, unknown> = { choice: raw };
                                if (raw.startsWith('{')) {
                                  try {
                                    const parsed = JSON.parse(raw);
                                    if (
                                      parsed !== null &&
                                      typeof parsed === 'object' &&
                                      !Array.isArray(parsed)
                                    ) {
                                      humanInput = parsed as Record<string, unknown>;
                                    }
                                  } catch {
                                    pushToast({
                                      tone: 'error',
                                      title: 'Invalid JSON input',
                                      description: 'Enter a valid JSON object or plain text choice.',
                                    });
                                    return;
                                  }
                                }
                                resumeTaskMutation.mutate({
                                  runId: snap.run.run_id,
                                  humanInput,
                                });
                              }}
                              className="flex gap-2"
                            >
                              <input
                                type="text"
                                aria-label={`Resume input for ${snap.run.run_id}`}
                                value={resumeDraft}
                                onChange={(e) =>
                                  setResumeInputs((prev) => ({
                                    ...prev,
                                    [snap.run.run_id]: e.target.value,
                                  }))
                                }
                                placeholder='Choice or JSON (e.g. {"choice":"confirm"})'
                                className="flex-1 px-2.5 py-1 rounded-lg text-[12px] outline-none bg-[var(--bg-canvas)] border border-[var(--border-strong)]"
                              />
                              <button
                                type="submit"
                                disabled={!resumeDraft.trim() || resumeTaskMutation.isPending}
                                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[12px] font-medium disabled:opacity-45"
                                style={{
                                  backgroundColor: 'var(--accent-primary)',
                                  color: 'var(--bg-canvas)',
                                }}
                              >
                                <Play size={11} />
                                Resume
                              </button>
                            </form>
                          </div>
                        )}
                      </div>
                    );
                  })
                )}
              </div>
            </section>
          )}
        </div>
      </div>
    </Modal>
  );
};
