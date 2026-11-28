import React, { useEffect, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  BookOpen,
  CalendarClock,
  Check,
  Clock,
  Copy,
  Eye,
  KeyRound,
  MessageSquare,
  Pencil,
  Play,
  Plus,
  Share2,
  Trash2,
  Users,
  Webhook,
} from 'lucide-react';
import { MarkdownRenderer } from '../../components/MarkdownRenderer';
import { Modal } from '../../components/Modal';
import {
  botsApi,
  channelsApi,
  routinesApi,
  skillsApi,
  vaultApi,
} from '../../lib/api';
import { copyToClipboard } from '../../lib/markdown';
import type {
  AvatarShape,
  Bot,
  Channel,
  RosterResponse,
  Routine,
  Skill,
} from '../../lib/types';
import { useUiStore } from '../../stores/uiStore';
import { AVATAR_COLORS, AVATAR_SHAPES, BotAvatar } from '../roster/BotAvatar';
import { CreateRoutineModal, RoutineDetailModal } from './RoutineModals';

interface BotDetailsTabProps {
  bot?: Bot | null;
  channel?: Channel | null;
  allBots: Bot[];
}

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

export const BotDetailsTab: React.FC<BotDetailsTabProps> = ({
  bot,
  channel,
  allBots,
}) => {
  const queryClient = useQueryClient();
  const appendComposerText = useUiStore((s) => s.appendComposerText);
  const setActiveTarget = useUiStore((s) => s.setActiveTarget);
  const setActivePageId = useUiStore((s) => s.setActivePageId);
  const pushToast = useUiStore((s) => s.pushToast);

  const [avatarEditorOpen, setAvatarEditorOpen] = useState(false);
  const [roleDraft, setRoleDraft] = useState(bot?.role_prompt ?? '');
  const [aboutDraft, setAboutDraft] = useState(bot?.about ?? '');
  const [createRoutineOpen, setCreateRoutineOpen] = useState(false);
  const [selectedRoutineId, setSelectedRoutineId] = useState<string | null>(null);
  const [routineEditInitial, setRoutineEditInitial] = useState(false);

  const [addingSkill, setAddingSkill] = useState(false);
  const [skillName, setSkillName] = useState('');
  const [skillDesc, setSkillDesc] = useState('');
  const [skillMd, setSkillMd] = useState('');
  const [viewingSkill, setViewingSkill] = useState<Skill | null>(null);

  const [addingSecret, setAddingSecret] = useState(false);
  const [secretName, setSecretName] = useState('');
  const [secretDomain, setSecretDomain] = useState('');
  const [secretUsername, setSecretUsername] = useState('');
  const [secretVal, setSecretVal] = useState('');
  const [secretFields, setSecretFields] = useState<Array<{ key: string; value: string }>>([]);

  const [optimisticBotToggles, setOptimisticBotToggles] = useState<
    Record<string, Partial<Pick<Bot, 'avatar_eyes_large' | 'drafts_enabled'>>>
  >({});
  const [optimisticRoutines, setOptimisticRoutines] = useState<Record<string, boolean>>({});
  const pendingBotCountRef = useRef(0);
  const botSeqRef = useRef(0);
  const lastBotFieldSeqRef = useRef<Record<string, number>>({});
  const pendingRoutineCountRef = useRef(0);
  const routineSeqRef = useRef(0);
  const lastRoutineSeqRef = useRef<Record<string, number>>({});

  useEffect(() => {
    setRoleDraft(bot?.role_prompt ?? '');
    setAboutDraft(bot?.about ?? '');
    setAvatarEditorOpen(false);
    setSelectedRoutineId(null);
    setRoutineEditInitial(false);
    setViewingSkill(null);
  }, [bot?.id, bot?.role_prompt, bot?.about]);

  const routinesQuery = useQuery({
    queryKey: ['routines', bot?.id],
    queryFn: () => routinesApi.list(bot!.id),
    enabled: Boolean(bot),
  });

  const skillsQuery = useQuery({
    queryKey: ['skills', bot?.id],
    queryFn: () => skillsApi.list(bot!.id),
    enabled: Boolean(bot),
  });

  const vaultQuery = useQuery({
    queryKey: ['vault-secrets', bot?.id],
    queryFn: () => vaultApi.list(bot!.id),
    enabled: Boolean(bot),
  });

  type BotMutationVariables = { botId: string; patch: Partial<Bot> };
  type BotMutationContext = {
    previous: RosterResponse | undefined;
    botId: string;
    patch: Partial<Bot>;
    seq: number;
  };

  const updateBotMutation = useMutation<
    Bot,
    Error,
    BotMutationVariables,
    BotMutationContext
  >({
    mutationFn: ({ botId, patch }) => botsApi.update(botId, patch),
    onMutate: async ({ botId, patch }) => {
      pendingBotCountRef.current += 1;
      const seq = (botSeqRef.current += 1);
      for (const key of Object.keys(patch)) {
        lastBotFieldSeqRef.current[`${botId}:${key}`] = seq;
      }
      const previous = queryClient.getQueryData<RosterResponse>(['roster']);
      queryClient.setQueryData<RosterResponse>(['roster'], (old) =>
        old
          ? {
              ...old,
              bots: old.bots.map((b) => (b.id === botId ? { ...b, ...patch } : b)),
            }
          : undefined,
      );
      await queryClient.cancelQueries({ queryKey: ['roster'] });
      return { previous, botId, patch, seq };
    },
    onSuccess: (updatedBot, _vars, context) => {
      if (context) {
        queryClient.setQueryData<RosterResponse>(['roster'], (old) => {
          if (!old) return undefined;
          return {
            ...old,
            bots: old.bots.map((b) => {
              if (b.id !== context.botId) return b;
              if (
                pendingBotCountRef.current <= 1 &&
                context.seq === botSeqRef.current
              ) {
                return updatedBot;
              }
              const merged: Record<string, unknown> = { ...b };
              const updatedRec = updatedBot as unknown as Record<string, unknown>;
              for (const key of Object.keys(context.patch)) {
                if (
                  lastBotFieldSeqRef.current[`${context.botId}:${key}`] ===
                  context.seq
                ) {
                  merged[key] = updatedRec[key];
                }
              }
              return merged as unknown as Bot;
            }),
          };
        });
      }
      pushToast({ tone: 'success', title: 'Bot updated' });
    },
    onError: (err, _vars, context) => {
      if (context?.previous) {
        const prevBot = context.previous.bots.find((b) => b.id === context.botId);
        if (prevBot) {
          const prevRec = prevBot as unknown as Record<string, unknown>;
          queryClient.setQueryData<RosterResponse>(['roster'], (old) => {
            if (!old) return context.previous;
            return {
              ...old,
              bots: old.bots.map((b) => {
                if (b.id !== context.botId) return b;
                const reverted: Record<string, unknown> = { ...b };
                for (const key of Object.keys(context.patch)) {
                  if (
                    lastBotFieldSeqRef.current[`${context.botId}:${key}`] ===
                    context.seq
                  ) {
                    reverted[key] = prevRec[key];
                  }
                }
                return reverted as unknown as Bot;
              }),
            };
          });
        }
      }
      pushToast({ tone: 'error', title: 'Update failed', description: err.message });
    },
    onSettled: (_data, _err, _vars, context) => {
      pendingBotCountRef.current = Math.max(0, pendingBotCountRef.current - 1);
      if (context) {
        setOptimisticBotToggles((prev) => {
          const current = prev[context.botId];
          if (!current) return prev;
          const nextBot = { ...current };
          let changed = false;
          if (
            context.patch.avatar_eyes_large !== undefined &&
            lastBotFieldSeqRef.current[`${context.botId}:avatar_eyes_large`] ===
              context.seq &&
            'avatar_eyes_large' in nextBot
          ) {
            delete nextBot.avatar_eyes_large;
            changed = true;
          }
          if (
            context.patch.drafts_enabled !== undefined &&
            lastBotFieldSeqRef.current[`${context.botId}:drafts_enabled`] ===
              context.seq &&
            'drafts_enabled' in nextBot
          ) {
            delete nextBot.drafts_enabled;
            changed = true;
          }
          if (!changed) return prev;
          const next = { ...prev };
          if (Object.keys(nextBot).length === 0) {
            delete next[context.botId];
          } else {
            next[context.botId] = nextBot;
          }
          return next;
        });
      }
      if (pendingBotCountRef.current === 0) {
        void queryClient.invalidateQueries({ queryKey: ['roster'] });
      }
    },
  });

  const mutateBot = (patch: Partial<Bot>) => {
    if (!bot) return;
    updateBotMutation.mutate({ botId: bot.id, patch });
  };

  const cloneTemplateMutation = useMutation({
    mutationFn: () => botsApi.cloneTemplate(bot!.id),
    onSuccess: ({ artifact }) => {
      void queryClient.invalidateQueries({ queryKey: ['thread-messages', bot?.thread_id] });
      void queryClient.invalidateQueries({ queryKey: ['library'] });
      if (artifact?.id) setActivePageId(artifact.id);
      pushToast({ tone: 'success', title: 'Template copy created in chat' });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not create template', description: err.message });
    },
  });

  type RoutineToggleVars = { id: string; enabled: boolean };
  type RoutineToggleContext = {
    previous: { routines: Routine[] } | undefined;
    botId: string | undefined;
    id: string;
    seq: number;
  };

  const toggleRoutineMutation = useMutation<
    Routine,
    Error,
    RoutineToggleVars,
    RoutineToggleContext
  >({
    mutationFn: ({ id, enabled }) => routinesApi.update(id, { enabled }),
    onMutate: async ({ id, enabled }) => {
      const botId = bot?.id;
      pendingRoutineCountRef.current += 1;
      const seq = (routineSeqRef.current += 1);
      lastRoutineSeqRef.current[id] = seq;
      const previous = botId
        ? queryClient.getQueryData<{ routines: Routine[] }>(['routines', botId])
        : undefined;
      if (botId) {
        queryClient.setQueryData<{ routines: Routine[] }>(
          ['routines', botId],
          (old) =>
            old
              ? {
                  routines: old.routines.map((r) =>
                    r.id === id ? { ...r, enabled } : r,
                  ),
                }
              : undefined,
        );
        await queryClient.cancelQueries({ queryKey: ['routines', botId] });
      }
      return { previous, botId, id, seq };
    },
    onSuccess: (updatedRoutine, _vars, context) => {
      if (
        context?.botId &&
        lastRoutineSeqRef.current[context.id] === context.seq
      ) {
        queryClient.setQueryData<{ routines: Routine[] }>(
          ['routines', context.botId],
          (old) =>
            old
              ? {
                  routines: old.routines.map((r) =>
                    r.id === context.id ? updatedRoutine : r,
                  ),
                }
              : undefined,
        );
      }
    },
    onError: (err, _vars, context) => {
      if (
        context?.botId &&
        context.previous &&
        lastRoutineSeqRef.current[context.id] === context.seq
      ) {
        const prevRoutine = context.previous.routines.find(
          (r) => r.id === context.id,
        );
        if (prevRoutine) {
          queryClient.setQueryData<{ routines: Routine[] }>(
            ['routines', context.botId],
            (old) =>
              old
                ? {
                    routines: old.routines.map((r) =>
                      r.id === context.id ? { ...r, enabled: prevRoutine.enabled } : r,
                    ),
                  }
                : undefined,
          );
        }
      }
      pushToast({ tone: 'error', title: 'Could not update routine', description: err.message });
    },
    onSettled: (_data, _err, _vars, context) => {
      pendingRoutineCountRef.current = Math.max(
        0,
        pendingRoutineCountRef.current - 1,
      );
      if (context && lastRoutineSeqRef.current[context.id] === context.seq) {
        setOptimisticRoutines((prev) => {
          if (!(context.id in prev)) return prev;
          const next = { ...prev };
          delete next[context.id];
          return next;
        });
      }
      if (pendingRoutineCountRef.current === 0 && context?.botId) {
        void queryClient.invalidateQueries({ queryKey: ['routines', context.botId] });
      }
    },
  });

  const testRoutineMutation = useMutation({
    mutationFn: (id: string) => routinesApi.test(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['routines', bot?.id] });
      pushToast({ tone: 'success', title: 'Routine test run queued' });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not run routine', description: err.message });
    },
  });

  const deleteRoutineMutation = useMutation({
    mutationFn: (id: string) => routinesApi.remove(id),
    onSuccess: (_res, id) => {
      if (selectedRoutineId === id) {
        setSelectedRoutineId(null);
      }
      void queryClient.invalidateQueries({ queryKey: ['routines', bot?.id] });
      pushToast({ tone: 'info', title: 'Routine deleted' });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not delete routine', description: err.message });
    },
  });

  const createSkillMutation = useMutation({
    mutationFn: () => {
      const content = skillMd.trim() || skillDesc.trim();
      return skillsApi.create({
        bot_id: bot!.id,
        name: skillName.trim(),
        description: skillDesc.trim() || 'Custom bot skill',
        content_md: content,
        instruction_md: content,
      });
    },
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['skills', bot?.id] });
      setSkillName('');
      setSkillDesc('');
      setSkillMd('');
      setAddingSkill(false);
      pushToast({ tone: 'success', title: 'Skill saved' });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not save skill', description: err.message });
    },
  });

  const deleteSkillMutation = useMutation({
    mutationFn: (id: string) => skillsApi.remove(id),
    onSuccess: (_res, id) => {
      if (viewingSkill?.id === id) {
        setViewingSkill(null);
      }
      void queryClient.invalidateQueries({ queryKey: ['skills', bot?.id] });
      pushToast({ tone: 'info', title: 'Skill deleted' });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not delete skill', description: err.message });
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
    mutationFn: () =>
      vaultApi.create({
        bot_id: bot!.id,
        name: secretName.trim(),
        domain: secretDomain.trim(),
        kind: 'credential',
        username: secretUsername.trim(),
        secret_value: secretVal,
        value: secretVal,
        fields: buildVaultFields(),
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['vault-secrets', bot?.id] });
      void queryClient.invalidateQueries({ queryKey: ['vault-secrets'] });
      setSecretName('');
      setSecretDomain('');
      setSecretUsername('');
      setSecretVal('');
      setSecretFields([]);
      setAddingSecret(false);
      pushToast({ tone: 'success', title: 'Stored securely in vault' });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not save secret', description: err.message });
    },
  });

  const deleteSecretMutation = useMutation({
    mutationFn: (id: string) => vaultApi.remove(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['vault-secrets', bot?.id] });
      void queryClient.invalidateQueries({ queryKey: ['vault-secrets'] });
      pushToast({ tone: 'info', title: 'Secret deleted' });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not delete secret', description: err.message });
    },
  });

  const updateChannelMutation = useMutation({
    mutationFn: (patch: Partial<Channel>) => channelsApi.update(channel!.id, patch),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['roster'] });
      pushToast({ tone: 'success', title: 'Group chat updated' });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not update group chat', description: err.message });
    },
  });

  // Group Channel Details
  if (!bot && channel) {
    const members = channel.bot_ids
      .map((id) => allBots.find((b) => b.id === id))
      .filter((b): b is Bot => Boolean(b));
    const nonMembers = allBots.filter(
      (b) => !b.hidden && !channel.bot_ids.includes(b.id),
    );

    return (
      <div className="p-4 space-y-5 overflow-y-auto h-full">
        <div>
          <div className="flex items-center gap-2 text-[14px] font-semibold">
            <Users size={16} />
            <span>#{channel.name}</span>
          </div>
          <p className="text-[12px] mt-1" style={{ color: 'var(--text-muted)' }}>
            Shared group workspace with {members.length} bots. Use @name in chat to route work.
          </p>
        </div>

        <div className="space-y-2">
          <div className="text-[11.5px] font-medium uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
            Members ({members.length} / 6)
          </div>
          {members.map((m) => (
            <div
              key={m.id}
              className="flex items-center justify-between gap-2 p-2 rounded-xl"
              style={{
                backgroundColor: 'var(--bg-sidebar)',
                border: '1px solid var(--border-subtle)',
              }}
            >
              <button
                type="button"
                aria-label={`${m.name}`}
                onClick={() =>
                  setActiveTarget({ kind: 'bot', id: m.id, threadId: m.thread_id })
                }
                className="flex items-center gap-2.5 min-w-0 text-left"
              >
                <BotAvatar
                  shape={m.avatar_shape}
                  color={m.avatar_color}
                  eyesLarge={m.avatar_eyes_large}
                  size={26}
                />
                <div className="min-w-0">
                  <div className="text-[13px] font-medium truncate">{m.name}</div>
                  <div className="text-[11px] truncate" style={{ color: 'var(--text-muted)' }}>
                    {m.status_subtext}
                  </div>
                </div>
              </button>
              {members.length > 2 && (
                <button
                  type="button"
                  onClick={() =>
                    updateChannelMutation.mutate({
                      bot_ids: channel.bot_ids.filter((id) => id !== m.id),
                    })
                  }
                  title="Remove from channel"
                  aria-label={`Remove ${m.name} from channel`}
                  className="p-1 rounded hover:bg-[var(--status-danger-bg)]"
                  style={{ color: 'var(--status-danger)' }}
                >
                  <Trash2 size={13} />
                </button>
              )}
            </div>
          ))}
        </div>

        {nonMembers.length > 0 && channel.bot_ids.length < 6 && (
          <div className="space-y-1.5">
            <div className="text-[11.5px] font-medium uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
              Add bot to channel
            </div>
            {nonMembers.map((candidate) => (
              <button
                key={candidate.id}
                type="button"
                aria-label={`Add ${candidate.name} to channel`}
                onClick={() =>
                  updateChannelMutation.mutate({
                    bot_ids: [...channel.bot_ids, candidate.id],
                  })
                }
                className="w-full flex items-center justify-between gap-2 p-2 rounded-xl hover:bg-[var(--bg-subtle)]"
                style={{ border: '1px solid var(--border-subtle)' }}
              >
                <span className="inline-flex items-center gap-2 text-[13px]">
                  <BotAvatar
                    shape={candidate.avatar_shape}
                    color={candidate.avatar_color}
                    size={22}
                  />
                  <span>{candidate.name}</span>
                </span>
                <Plus size={14} style={{ color: 'var(--text-secondary)' }} />
              </button>
            ))}
          </div>
        )}
      </div>
    );
  }

  if (!bot) {
    return (
      <div className="p-5 text-[13px]" style={{ color: 'var(--text-muted)' }}>
        Select a bot to view its details, routines, skills, and vault.
      </div>
    );
  }

  const selectedRoutine =
    (routinesQuery.data?.routines ?? []).find((r) => r.id === selectedRoutineId) ?? null;
  const effectiveEyesLarge =
    optimisticBotToggles[bot.id]?.avatar_eyes_large ?? bot.avatar_eyes_large;
  const effectiveDraftsEnabled =
    optimisticBotToggles[bot.id]?.drafts_enabled ?? bot.drafts_enabled;
  const hasVaultPayload = Boolean(
    secretVal || secretUsername.trim() || Object.keys(buildVaultFields()).length > 0,
  );
  const canSubmitSkill = Boolean(skillName.trim() && (skillMd.trim() || skillDesc.trim()));
  const avatarBtnLabel = avatarEditorOpen ? 'Done editing avatar' : 'Customize avatar';

  return (
    <div className="h-full overflow-y-auto p-4 space-y-5">
      {/* Profile & Avatar */}
      <div className="space-y-3">
        <div className="flex items-center gap-3">
          <button
            type="button"
            onClick={() => setAvatarEditorOpen((v) => !v)}
            title="Edit avatar"
            aria-label="Edit avatar"
            className="p-2 rounded-2xl transition-colors hover:bg-[var(--bg-active)]"
            style={{
              backgroundColor: 'var(--bg-sidebar)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            <BotAvatar
              shape={bot.avatar_shape}
              color={bot.avatar_color}
              eyesLarge={effectiveEyesLarge}
              size={40}
            />
          </button>
          <div className="min-w-0 flex-1">
            <div className="text-[14.5px] font-semibold truncate">{bot.name}</div>
            <div className="text-[12px] truncate" style={{ color: 'var(--text-muted)' }}>
              {bot.model_id} · {bot.thinking_level}
            </div>
            <button
              type="button"
              aria-label={`${avatarBtnLabel}`}
              onClick={() => setAvatarEditorOpen((v) => !v)}
              className="text-[11.5px] mt-0.5 hover:underline"
              style={{ color: 'var(--accent-computer)' }}
            >
              {avatarEditorOpen ? 'Done editing avatar' : 'Customize avatar'}
            </button>
          </div>
        </div>

        {avatarEditorOpen && (
          <div
            className="p-3 rounded-xl space-y-3"
            style={{
              backgroundColor: 'var(--bg-sidebar)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            <div className="grid grid-cols-7 gap-1">
              {AVATAR_SHAPES.map((s) => (
                <button
                  key={s.id}
                  type="button"
                  aria-label={`Select ${s.label} avatar shape`}
                  onClick={() => mutateBot({ avatar_shape: s.id as AvatarShape })}
                  className="p-1.5 rounded-lg flex items-center justify-center"
                  style={{
                    backgroundColor:
                      bot.avatar_shape === s.id ? 'var(--bg-active)' : 'transparent',
                  }}
                >
                  <BotAvatar shape={s.id} color={bot.avatar_color} eyesLarge={effectiveEyesLarge} size={22} />
                </button>
              ))}
            </div>
            <div className="flex flex-wrap items-center gap-1.5">
              {AVATAR_COLORS.map((c) => (
                <button
                  key={c}
                  type="button"
                  aria-label={`Select avatar color ${c}`}
                  onClick={() => mutateBot({ avatar_color: c })}
                  className="w-5 h-5 rounded-full"
                  style={{
                    backgroundColor: c,
                    boxShadow:
                      bot.avatar_color === c
                        ? `0 0 0 2px var(--bg-sidebar), 0 0 0 3.5px ${c}`
                        : 'none',
                  }}
                />
              ))}
            </div>
            <label className="inline-flex items-center gap-2 text-[12px] cursor-pointer">
              <input
                type="checkbox"
                aria-label="Larger expressive eyes"
                checked={effectiveEyesLarge}
                onChange={(e) => {
                  const next = e.target.checked;
                  setOptimisticBotToggles((prev) => ({
                    ...prev,
                    [bot.id]: { ...prev[bot.id], avatar_eyes_large: next },
                  }));
                  mutateBot({ avatar_eyes_large: next });
                }}
              />
              <span>Larger expressive eyes</span>
            </label>
          </div>
        )}

        {/* Role / About instructions */}
        <div className="space-y-1.5">
          <label className="block text-[11.5px] font-medium" style={{ color: 'var(--text-muted)' }}>
            Role instructions
          </label>
          <textarea
            rows={3}
            value={roleDraft}
            onChange={(e) => setRoleDraft(e.target.value)}
            onBlur={() => {
              if (roleDraft !== bot.role_prompt) {
                mutateBot({ role_prompt: roleDraft });
              }
            }}
            placeholder="Describe what this bot owns and how it should communicate…"
            className="w-full px-2.5 py-2 rounded-xl text-[12.5px] outline-none resize-y"
            style={{
              backgroundColor: 'var(--bg-sidebar)',
              border: '1px solid var(--border-subtle)',
            }}
          />
          {bot.is_team_bot && (
            <textarea
              rows={2}
              value={aboutDraft}
              onChange={(e) => setAboutDraft(e.target.value)}
              onBlur={() => {
                if (aboutDraft !== bot.about) {
                  mutateBot({ about: aboutDraft });
                }
              }}
              placeholder="About (Team Bot)…"
              className="w-full px-2.5 py-1.5 rounded-xl text-[12.5px] outline-none resize-y"
              style={{
                backgroundColor: 'var(--bg-sidebar)',
                border: '1px solid var(--border-subtle)',
              }}
            />
          )}
        </div>

        {/* Timezone & Drafts */}
        <div className="grid grid-cols-1 gap-2">
          <div className="flex items-center justify-between gap-2">
            <span className="inline-flex items-center gap-1.5 text-[12px]" style={{ color: 'var(--text-secondary)' }}>
              <Clock size={13} />
              Timezone
            </span>
            <select
              aria-label="Bot timezone"
              value={bot.timezone || 'UTC'}
              onChange={(e) => mutateBot({ timezone: e.target.value })}
              className="px-2 py-1 rounded-lg text-[12px] outline-none"
              style={{
                backgroundColor: 'var(--bg-sidebar)',
                border: '1px solid var(--border-subtle)',
              }}
            >
              {!TIMEZONES.includes(bot.timezone || 'UTC') && (
                <option value={bot.timezone}>{bot.timezone}</option>
              )}
              {TIMEZONES.map((tz) => (
                <option key={tz} value={tz}>
                  {tz}
                </option>
              ))}
            </select>
          </div>

          <label className="flex items-center justify-between text-[12px] cursor-pointer">
            <span style={{ color: 'var(--text-secondary)' }}>Hold outbound drafts for approval</span>
            <input
              type="checkbox"
              aria-label="Hold outbound drafts for approval"
              checked={effectiveDraftsEnabled}
              onChange={(e) => {
                const next = e.target.checked;
                setOptimisticBotToggles((prev) => ({
                  ...prev,
                  [bot.id]: { ...prev[bot.id], drafts_enabled: next },
                }));
                mutateBot({ drafts_enabled: next });
              }}
            />
          </label>
        </div>
      </div>

      {/* Routines Section */}
      <div className="space-y-2 pt-3" style={{ borderTop: '1px solid var(--border-subtle)' }}>
        <div className="flex items-center justify-between">
          <span className="inline-flex items-center gap-1.5 text-[12px] font-semibold">
            <CalendarClock size={14} strokeWidth={1.75} />
            Routines
          </span>
          <button
            type="button"
            onClick={() => setCreateRoutineOpen(true)}
            className="inline-flex items-center gap-1 px-2 py-1 rounded-lg text-[11.5px] font-medium hover:bg-[var(--bg-subtle)]"
            style={{ color: 'var(--text-secondary)' }}
          >
            <Plus size={12.5} />
            Add
          </button>
        </div>

        {(routinesQuery.data?.routines ?? []).length === 0 ? (
          <div className="text-[12px] py-2" style={{ color: 'var(--text-muted)' }}>
            No routines yet. Schedule recurring jobs or webhook triggers.
          </div>
        ) : (
          <div className="space-y-1.5">
            {(routinesQuery.data?.routines ?? []).map((rtn) => {
              const effectiveEnabled = optimisticRoutines[rtn.id] ?? rtn.enabled;
              const toggleAria = effectiveEnabled
                ? `Pause routine ${rtn.name}`
                : `Resume routine ${rtn.name}`;
              const toggleTitle = effectiveEnabled ? 'Pause routine' : 'Resume routine';
              return (
              <div
                key={rtn.id}
                className="p-2.5 rounded-xl space-y-2"
                style={{
                  backgroundColor: 'var(--bg-sidebar)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <div className="flex items-start justify-between gap-2">
                  <button
                    type="button"
                    aria-label={`Inspect routine ${rtn.name}`}
                    onClick={() => {
                      setRoutineEditInitial(false);
                      setSelectedRoutineId(rtn.id);
                    }}
                    className="min-w-0 text-left flex-1"
                  >
                    <div className="flex items-center gap-1.5 min-w-0">
                      <span className="text-[13px] font-medium truncate hover:underline">
                        {rtn.name}
                      </span>
                      <span
                        className="text-[10px] px-1.5 py-0.5 rounded-full shrink-0"
                        style={{
                          backgroundColor: 'var(--bg-subtle)',
                          color: 'var(--text-muted)',
                        }}
                      >
                        {rtn.visibility === 'team' ? 'Team' : 'Only me'}
                      </span>
                    </div>
                    <div className="text-[11.5px] flex items-center gap-1 mt-0.5" style={{ color: 'var(--text-muted)' }}>
                      {rtn.schedule_type === 'webhook' ? (
                        <Webhook size={11} />
                      ) : (
                        <Clock size={11} />
                      )}
                      <span>
                        {!effectiveEnabled
                          ? 'Paused'
                          : rtn.schedule_type === 'webhook'
                            ? 'Webhook'
                            : rtn.schedule_type === 'manual'
                              ? 'Manual'
                              : rtn.cron_expr || 'Scheduled'}
                      </span>
                    </div>
                  </button>

                  <input
                    type="checkbox"
                    aria-label={`${toggleAria}`}
                    checked={effectiveEnabled}
                    onChange={(e) => {
                      const next = e.target.checked;
                      setOptimisticRoutines((prev) => ({ ...prev, [rtn.id]: next }));
                      toggleRoutineMutation.mutate({ id: rtn.id, enabled: next });
                    }}
                    title={`${toggleTitle}`}
                    className="mt-1 cursor-pointer"
                  />
                </div>

                <div className="flex items-center flex-wrap gap-1 pt-1" style={{ borderTop: '1px solid var(--border-subtle)' }}>
                  <button
                    type="button"
                    onClick={() => testRoutineMutation.mutate(rtn.id)}
                    className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11.5px] hover:bg-[var(--bg-active)]"
                    style={{ color: 'var(--text-secondary)' }}
                  >
                    <Play size={11} />
                    Test
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setRoutineEditInitial(true);
                      setSelectedRoutineId(rtn.id);
                    }}
                    className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11.5px] hover:bg-[var(--bg-active)]"
                    style={{ color: 'var(--text-secondary)' }}
                  >
                    <Pencil size={11} />
                    Edit
                  </button>
                  <button
                    type="button"
                    onClick={() =>
                      appendComposerText(bot.thread_id, `Edit your routine: ${rtn.name} — `)
                    }
                    className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11.5px] hover:bg-[var(--bg-active)]"
                    style={{ color: 'var(--text-secondary)' }}
                  >
                    <MessageSquare size={11} />
                    Edit in chat
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      setRoutineEditInitial(false);
                      setSelectedRoutineId(rtn.id);
                    }}
                    className="px-2 py-0.5 rounded text-[11.5px] hover:bg-[var(--bg-active)]"
                    style={{ color: 'var(--text-secondary)' }}
                  >
                    Runs
                  </button>
                  <button
                    type="button"
                    onClick={() => deleteRoutineMutation.mutate(rtn.id)}
                    title="Delete routine"
                    aria-label={`Delete routine ${rtn.name}`}
                    className="ml-auto p-1 rounded hover:bg-[var(--status-danger-bg)]"
                    style={{ color: 'var(--status-danger)' }}
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
              </div>
              );
            })}
          </div>
        )}
      </div>

      {/* Skills Section */}
      <div className="space-y-2 pt-3" style={{ borderTop: '1px solid var(--border-subtle)' }}>
        <div className="flex items-center justify-between">
          <span className="inline-flex items-center gap-1.5 text-[12px] font-semibold">
            <BookOpen size={14} strokeWidth={1.75} />
            Skills
          </span>
          <button
            type="button"
            onClick={() => setAddingSkill((v) => !v)}
            className="inline-flex items-center gap-1 px-2 py-1 rounded-lg text-[11.5px] font-medium hover:bg-[var(--bg-subtle)]"
            style={{ color: 'var(--text-secondary)' }}
          >
            <Plus size={12.5} />
            Add
          </button>
        </div>

        {addingSkill && (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (canSubmitSkill) createSkillMutation.mutate();
            }}
            className="p-2.5 rounded-xl space-y-2"
            style={{
              backgroundColor: 'var(--bg-sidebar)',
              border: '1px solid var(--border-strong)',
            }}
          >
            <input
              type="text"
              required
              aria-label="Skill name"
              value={skillName}
              onChange={(e) => setSkillName(e.target.value)}
              placeholder="Skill name"
              className="w-full px-2.5 py-1.5 rounded-lg text-[12.5px] outline-none bg-[var(--bg-canvas)] border border-[var(--border-subtle)]"
            />
            <input
              type="text"
              aria-label="Skill description"
              value={skillDesc}
              onChange={(e) => setSkillDesc(e.target.value)}
              placeholder="One-line description"
              className="w-full px-2.5 py-1.5 rounded-lg text-[12px] outline-none bg-[var(--bg-canvas)] border border-[var(--border-subtle)]"
            />
            <textarea
              rows={3}
              aria-label="Skill markdown instructions"
              value={skillMd}
              onChange={(e) => setSkillMd(e.target.value)}
              placeholder="Markdown playbook steps (required if description is empty)…"
              className="w-full px-2.5 py-1.5 rounded-lg text-[12px] outline-none bg-[var(--bg-canvas)] border border-[var(--border-subtle)]"
            />
            <div className="flex justify-end gap-1.5">
              <button
                type="button"
                onClick={() => setAddingSkill(false)}
                className="px-2.5 py-1 rounded-lg text-[12px]"
                style={{ color: 'var(--text-secondary)' }}
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={!canSubmitSkill || createSkillMutation.isPending}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[12px] font-medium disabled:opacity-45"
                style={{ backgroundColor: 'var(--accent-primary)', color: 'var(--bg-canvas)' }}
              >
                <Check size={12} />
                Save
              </button>
            </div>
          </form>
        )}

        {(skillsQuery.data?.skills ?? []).length === 0 ? (
          <div className="text-[12px]" style={{ color: 'var(--text-muted)' }}>
            No skills saved yet. Add one or use Teach a task in Computer.
          </div>
        ) : (
          <div className="space-y-1">
            {(skillsQuery.data?.skills ?? []).map((sk) => (
              <div
                key={sk.id}
                className="group flex items-center justify-between gap-2 px-2.5 py-2 rounded-xl hover:bg-[var(--bg-subtle)]"
                style={{ border: '1px solid var(--border-subtle)' }}
              >
                <button
                  type="button"
                  onClick={() => appendComposerText(bot.thread_id, `@${sk.slug || sk.name} `)}
                  title="Insert @skill into composer"
                  className="flex items-start gap-2 min-w-0 text-left flex-1"
                >
                  <BookOpen size={14} className="mt-0.5 shrink-0" style={{ color: 'var(--accent-computer)' }} />
                  <div className="min-w-0">
                    <div className="text-[12.5px] font-medium truncate">{sk.name}</div>
                    <div className="text-[11.5px] truncate" style={{ color: 'var(--text-muted)' }}>
                      {sk.description}
                    </div>
                  </div>
                </button>
                <div className="flex items-center gap-0.5 shrink-0">
                  <button
                    type="button"
                    onClick={() => setViewingSkill(sk)}
                    title="View skill instructions"
                    aria-label={`View skill ${sk.name}`}
                    className="opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 focus-visible:opacity-100 p-1 rounded hover:bg-[var(--bg-active)]"
                    style={{ color: 'var(--text-secondary)' }}
                  >
                    <Eye size={12} />
                  </button>
                  <button
                    type="button"
                    onClick={() => deleteSkillMutation.mutate(sk.id)}
                    title="Delete skill"
                    aria-label={`Delete skill ${sk.name}`}
                    className="opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 focus-visible:opacity-100 p-1 rounded hover:bg-[var(--status-danger-bg)]"
                    style={{ color: 'var(--status-danger)' }}
                  >
                    <Trash2 size={12} />
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Bot Vault Section */}
      <div className="space-y-2 pt-3" style={{ borderTop: '1px solid var(--border-subtle)' }}>
        <div className="flex items-center justify-between">
          <span className="inline-flex items-center gap-1.5 text-[12px] font-semibold">
            <KeyRound size={14} strokeWidth={1.75} />
            Bot vault
          </span>
          <button
            type="button"
            onClick={() => setAddingSecret((v) => !v)}
            className="inline-flex items-center gap-1 px-2 py-1 rounded-lg text-[11.5px] font-medium hover:bg-[var(--bg-subtle)]"
            style={{ color: 'var(--text-secondary)' }}
          >
            <Plus size={12.5} />
            Add secret
          </button>
        </div>

        {addingSecret && (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (secretName.trim() && hasVaultPayload) addSecretMutation.mutate();
            }}
            className="p-2.5 rounded-xl space-y-2"
            style={{
              backgroundColor: 'var(--bg-sidebar)',
              border: '1px solid var(--border-strong)',
            }}
          >
            <input
              type="text"
              required
              aria-label="Secret label"
              value={secretName}
              onChange={(e) => setSecretName(e.target.value)}
              placeholder="Secret label (e.g. CRM API Key)"
              className="w-full px-2.5 py-1.5 rounded-lg text-[12.5px] outline-none bg-[var(--bg-canvas)] border border-[var(--border-subtle)]"
            />
            <input
              type="text"
              aria-label="Secret domain"
              value={secretDomain}
              onChange={(e) => setSecretDomain(e.target.value)}
              placeholder="Domain (optional)"
              className="w-full px-2.5 py-1.5 rounded-lg text-[12px] outline-none bg-[var(--bg-canvas)] border border-[var(--border-subtle)]"
            />
            <input
              type="text"
              aria-label="Secret username"
              value={secretUsername}
              onChange={(e) => setSecretUsername(e.target.value)}
              placeholder="Username / email (optional)"
              className="w-full px-2.5 py-1.5 rounded-lg text-[12px] outline-none bg-[var(--bg-canvas)] border border-[var(--border-subtle)]"
            />
            <input
              type="password"
              autoComplete="off"
              aria-label="Secret value"
              value={secretVal}
              onChange={(e) => setSecretVal(e.target.value)}
              placeholder="Secret value (never shown again)"
              className="w-full px-2.5 py-1.5 rounded-lg text-[12px] outline-none bg-[var(--bg-canvas)] border border-[var(--border-subtle)]"
            />
            {secretFields.length > 0 && (
              <div className="space-y-1.5">
                {secretFields.map((row, idx) => (
                  <div key={idx} className="flex gap-1.5 items-center">
                    <input
                      type="text"
                      aria-label={`Secret field key ${idx + 1}`}
                      value={row.key}
                      onChange={(e) =>
                        setSecretFields((prev) =>
                          prev.map((item, i) =>
                            i === idx ? { ...item, key: e.target.value } : item,
                          ),
                        )
                      }
                      placeholder="Field key"
                      className="w-1/2 px-2 py-1 rounded-lg text-[11.5px] outline-none bg-[var(--bg-canvas)] border border-[var(--border-subtle)]"
                    />
                    <input
                      type="password"
                      autoComplete="off"
                      aria-label={`Secret field value ${idx + 1}`}
                      value={row.value}
                      onChange={(e) =>
                        setSecretFields((prev) =>
                          prev.map((item, i) =>
                            i === idx ? { ...item, value: e.target.value } : item,
                          ),
                        )
                      }
                      placeholder="Value"
                      className="w-1/2 px-2 py-1 rounded-lg text-[11.5px] outline-none bg-[var(--bg-canvas)] border border-[var(--border-subtle)]"
                    />
                    <button
                      type="button"
                      aria-label={`Remove secret field ${idx + 1}`}
                      onClick={() =>
                        setSecretFields((prev) => prev.filter((_, i) => i !== idx))
                      }
                      className="p-1 rounded hover:bg-[var(--status-danger-bg)] shrink-0"
                      style={{ color: 'var(--status-danger)' }}
                    >
                      <Trash2 size={12} />
                    </button>
                  </div>
                ))}
              </div>
            )}
            <div className="flex items-center justify-between gap-1.5">
              <button
                type="button"
                onClick={() =>
                  setSecretFields((prev) => [...prev, { key: '', value: '' }])
                }
                className="inline-flex items-center gap-1 px-2 py-1 rounded-lg text-[11.5px] hover:bg-[var(--bg-subtle)]"
                style={{ color: 'var(--text-secondary)' }}
              >
                <Plus size={11.5} />
                Field
              </button>
              <div className="flex gap-1.5">
                <button
                  type="button"
                  onClick={() => setAddingSecret(false)}
                  className="px-2.5 py-1 rounded-lg text-[12px]"
                  style={{ color: 'var(--text-secondary)' }}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={!secretName.trim() || !hasVaultPayload || addSecretMutation.isPending}
                  className="px-2.5 py-1 rounded-lg text-[12px] font-medium text-white disabled:opacity-45"
                  style={{ backgroundColor: 'var(--accent-computer)' }}
                >
                  Save securely
                </button>
              </div>
            </div>
          </form>
        )}

        {(vaultQuery.data?.secrets ?? []).length === 0 ? (
          <div className="text-[12px]" style={{ color: 'var(--text-muted)' }}>
            No secrets stored for this bot.
          </div>
        ) : (
          <div className="space-y-1">
            {(vaultQuery.data?.secrets ?? []).map((sec) => (
              <div
                key={sec.id}
                className="flex items-center justify-between gap-2 px-2.5 py-1.5 rounded-xl"
                style={{
                  backgroundColor: 'var(--bg-sidebar)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <div className="min-w-0">
                  <div className="text-[12.5px] font-medium truncate">{sec.name}</div>
                  <div className="text-[11px] truncate" style={{ color: 'var(--text-muted)' }}>
                    {sec.domain || sec.kind}
                    {sec.username_hint ? ` · user: ${sec.username_hint}` : ''}
                    {sec.field_names && sec.field_names.length > 0
                      ? ` · fields: ${sec.field_names.join(', ')}`
                      : ''}
                    {' · ••••••••'}
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => deleteSecretMutation.mutate(sec.id)}
                  title="Delete secret"
                  aria-label={`Delete secret ${sec.name}`}
                  className="p-1 rounded hover:bg-[var(--status-danger-bg)] shrink-0"
                  style={{ color: 'var(--status-danger)' }}
                >
                  <Trash2 size={12.5} />
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Share / Template Copy */}
      <div className="pt-3" style={{ borderTop: '1px solid var(--border-subtle)' }}>
        <button
          type="button"
          aria-label="Share and create template copy"
          onClick={() => cloneTemplateMutation.mutate()}
          disabled={cloneTemplateMutation.isPending}
          className="w-full inline-flex items-center justify-center gap-2 px-3 py-2 rounded-xl text-[12.5px] font-medium transition-colors hover:bg-[var(--bg-active)]"
          style={{
            backgroundColor: 'var(--bg-subtle)',
            color: 'var(--text-primary)',
          }}
        >
          <Share2 size={14} strokeWidth={1.75} />
          {cloneTemplateMutation.isPending ? 'Creating template…' : 'Share → Create template copy'}
        </button>
      </div>

      <CreateRoutineModal
        open={createRoutineOpen}
        onClose={() => setCreateRoutineOpen(false)}
        botId={bot.id}
        defaultTimezone={bot.timezone || 'UTC'}
      />

      <RoutineDetailModal
        routine={selectedRoutine}
        initialEditing={routineEditInitial}
        onClose={() => {
          setSelectedRoutineId(null);
          setRoutineEditInitial(false);
        }}
      />

      <Modal
        open={Boolean(viewingSkill)}
        onClose={() => setViewingSkill(null)}
        title={viewingSkill?.name}
        subtitle={
          viewingSkill
            ? `@${viewingSkill.slug || viewingSkill.name}${viewingSkill.source ? ` · ${viewingSkill.source}` : ''}`
            : undefined
        }
        maxWidthClass="max-w-xl"
      >
        {viewingSkill && (
          <div className="p-5 space-y-4">
            {viewingSkill.description && (
              <div className="text-[13px]" style={{ color: 'var(--text-secondary)' }}>
                {viewingSkill.description}
              </div>
            )}
            <div
              className="p-3.5 rounded-xl text-[13px] max-h-[50vh] overflow-y-auto"
              style={{
                backgroundColor: 'var(--bg-sidebar)',
                border: '1px solid var(--border-subtle)',
              }}
            >
              <MarkdownRenderer
                content={viewingSkill.content_md || viewingSkill.instruction_md || '_No instructions recorded._'}
              />
            </div>
            <div className="flex items-center justify-end gap-2">
              <button
                type="button"
                onClick={async () => {
                  const ok = await copyToClipboard(
                    viewingSkill.content_md || viewingSkill.instruction_md || '',
                  );
                  if (ok) {
                    pushToast({ tone: 'success', title: 'Skill markdown copied' });
                  }
                }}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12.5px] font-medium hover:bg-[var(--bg-subtle)]"
                style={{
                  border: '1px solid var(--border-subtle)',
                  color: 'var(--text-primary)',
                }}
              >
                <Copy size={13} />
                Copy markdown
              </button>
              <button
                type="button"
                onClick={() => {
                  appendComposerText(
                    bot.thread_id,
                    `@${viewingSkill.slug || viewingSkill.name} `,
                  );
                  setViewingSkill(null);
                }}
                className="px-3.5 py-1.5 rounded-lg text-[12.5px] font-medium"
                style={{
                  backgroundColor: 'var(--accent-primary)',
                  color: 'var(--bg-canvas)',
                }}
              >
                Insert @{viewingSkill.slug || viewingSkill.name}
              </button>
            </div>
          </div>
        )}
      </Modal>
    </div>
  );
};
