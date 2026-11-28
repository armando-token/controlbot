import React, { useEffect, useMemo, useRef, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  ArrowUp,
  BookOpen,
  CalendarClock,
  Globe,
  Hash,
  Loader2,
  Mic,
  MicOff,
  Paperclip,
  Plug,
  Square,
  X,
} from 'lucide-react';
import {
  appsApi,
  attachmentsApi,
  legacyApi,
  routinesApi,
  settingsApi,
  skillsApi,
  threadsApi,
} from '../../lib/api';
import { formatBytes } from '../../lib/markdown';
import type { Attachment, Bot, Channel, ThinkingLevel } from '../../lib/types';
import { useChatStreamStore } from '../../stores/chatStreamStore';
import { useUiStore } from '../../stores/uiStore';
import { BotAvatar } from '../roster/BotAvatar';

interface ComposerBoxProps {
  threadId: string;
  bot?: Bot | null;
  channel?: Channel | null;
  allBots: Bot[];
  allChannels: Channel[];
  pageContextTitle?: string | null;
  pageContextId?: string | null;
}

interface MentionCandidate {
  id: string;
  label: string;
  insertText: string;
  category: 'Bot' | 'Channel' | 'Skill' | 'Routine' | 'App';
  subtext?: string;
  bot?: Bot;
}

interface BrowserSpeechRecognition extends EventTarget {
  continuous: boolean;
  interimResults: boolean;
  lang: string;
  start: () => void;
  stop: () => void;
  onresult: ((ev: { results: ArrayLike<ArrayLike<{ transcript: string }>> }) => void) | null;
  onerror: ((ev: { error?: string }) => void) | null;
  onend: (() => void) | null;
}

const EMPTY_ATTACHMENTS: Attachment[] = [];

const THINKING_LEVELS: { id: ThinkingLevel; label: string }[] = [
  { id: 'off', label: 'Off' },
  { id: 'low', label: 'Low' },
  { id: 'medium', label: 'Medium' },
  { id: 'high', label: 'High' },
  { id: 'max', label: 'Max' },
];

function toMentionSlug(raw: string): string {
  const cleaned = raw
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
  return cleaned || raw.trim().replace(/\s+/g, '-');
}

export const ComposerBox: React.FC<ComposerBoxProps> = ({
  threadId,
  bot,
  channel,
  allBots,
  allChannels,
  pageContextTitle,
  pageContextId,
}) => {
  const queryClient = useQueryClient();
  const draft = useUiStore((s) => s.composerDraftByThread[threadId] ?? '');
  const setComposerDraft = useUiStore((s) => s.setComposerDraft);
  const attachments = useUiStore(
    (s) => s.composerAttachmentsByThread[threadId] ?? EMPTY_ATTACHMENTS,
  );
  const addComposerAttachment = useUiStore((s) => s.addComposerAttachment);
  const removeComposerAttachment = useUiStore((s) => s.removeComposerAttachment);
  const clearComposerAttachments = useUiStore((s) => s.clearComposerAttachments);
  const replyTo = useUiStore((s) => s.replyToByThread[threadId] ?? null);
  const setReplyTo = useUiStore((s) => s.setReplyTo);
  const composerFocusNonce = useUiStore((s) => s.composerFocusNonce);
  const dictationToggleNonce = useUiStore((s) => s.dictationToggleNonce);
  const pushToast = useUiStore((s) => s.pushToast);

  const activeTurn = useChatStreamStore((s) => s.activeTurnByThread[threadId]);

  const textareaRef = useRef<HTMLTextAreaElement | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const recognitionRef = useRef<BrowserSpeechRecognition | null>(null);
  const sendAbortRef = useRef<AbortController | null>(null);
  const prevDictationNonceRef = useRef(dictationToggleNonce);

  const [uploading, setUploading] = useState(false);
  const [dictating, setDictating] = useState(false);
  const [stoppingPendingSend, setStoppingPendingSend] = useState(false);
  const [mentionQuery, setMentionQuery] = useState<string | null>(null);
  const [mentionIdx, setMentionIdx] = useState(0);
  const [overrideModelId, setOverrideModelId] = useState<string>('');
  const [overrideThinkingLevel, setOverrideThinkingLevel] = useState<ThinkingLevel | ''>('');
  const [includeBrowserContext, setIncludeBrowserContext] = useState<boolean | null>(null);

  const skillsQuery = useQuery({
    queryKey: ['skills', bot?.id || 'all'],
    queryFn: () => skillsApi.list(bot?.id),
    staleTime: 60_000,
  });

  const routinesQuery = useQuery({
    queryKey: ['routines', bot?.id],
    queryFn: () =>
      bot ? routinesApi.list(bot.id) : Promise.resolve({ routines: [] }),
    enabled: Boolean(bot?.id),
    staleTime: 60_000,
  });

  const appsQuery = useQuery({
    queryKey: ['apps'],
    queryFn: () => appsApi.list(),
    staleTime: 120_000,
  });

  const settingsQuery = useQuery({
    queryKey: ['settings'],
    queryFn: () => settingsApi.get(),
    staleTime: 60_000,
  });

  const modelsQuery = useQuery({
    queryKey: ['agy-models'],
    queryFn: () => legacyApi.agyModels(),
    staleTime: 60_000,
  });

  const allowHydrogen = Boolean(settingsQuery.data?.allow_hydrogen);
  const allModels = useMemo(() => modelsQuery.data?.models ?? [], [modelsQuery.data?.models]);
  const filteredModels = useMemo(
    () => (allowHydrogen ? allModels : allModels.filter((m) => !m.is_hydrogen)),
    [allowHydrogen, allModels],
  );

  // Reset per-turn overrides when switching threads
  useEffect(() => {
    setOverrideModelId('');
    setOverrideThinkingLevel('');
    setIncludeBrowserContext(null);
  }, [threadId]);

  // Clear selected Hydrogen override if allow_hydrogen becomes false
  useEffect(() => {
    if (!allowHydrogen && overrideModelId) {
      const matched = allModels.find((m) => m.id === overrideModelId);
      if (matched?.is_hydrogen || /hydrogen/i.test(overrideModelId)) {
        setOverrideModelId('');
      }
    }
  }, [allowHydrogen, overrideModelId, allModels]);

  // Focus composer on shortcut
  useEffect(() => {
    if (composerFocusNonce > 0) {
      textareaRef.current?.focus();
    }
  }, [composerFocusNonce]);

  // Auto-resize textarea
  useEffect(() => {
    const el = textareaRef.current;
    if (!el) return;
    el.style.height = 'auto';
    el.style.height = `${Math.min(el.scrollHeight, 200)}px`;
  }, [draft]);

  // Voice dictation (Web Speech API)
  const toggleDictation = () => {
    const win = window as unknown as {
      SpeechRecognition?: new () => BrowserSpeechRecognition;
      webkitSpeechRecognition?: new () => BrowserSpeechRecognition;
    };
    const SpeechRec = win.SpeechRecognition || win.webkitSpeechRecognition;
    if (!SpeechRec) {
      pushToast({
        tone: 'info',
        title: 'Voice dictation unavailable',
        description: 'This browser does not expose the Web Speech API.',
      });
      return;
    }

    if (dictating && recognitionRef.current) {
      recognitionRef.current.stop();
      setDictating(false);
      return;
    }

    const rec = new SpeechRec();
    rec.continuous = true;
    rec.interimResults = false;
    rec.lang = navigator.language || 'en-US';
    rec.onresult = (ev) => {
      let transcript = '';
      for (let i = 0; i < ev.results.length; i += 1) {
        const res = ev.results[i];
        const firstAlt = res?.[0];
        if (firstAlt?.transcript) {
          transcript += `${firstAlt.transcript} `;
        }
      }
      const cleaned = transcript.trim();
      if (cleaned) {
        const current = useUiStore.getState().composerDraftByThread[threadId] ?? '';
        setComposerDraft(threadId, current ? `${current} ${cleaned}` : cleaned);
      }
    };
    rec.onerror = (ev) => {
      setDictating(false);
      pushToast({
        tone: 'warn',
        title: 'Dictation stopped',
        description: ev.error || 'Microphone permission was declined.',
      });
    };
    rec.onend = () => {
      setDictating(false);
    };
    recognitionRef.current = rec;
    try {
      rec.start();
      setDictating(true);
    } catch {
      setDictating(false);
    }
  };

  useEffect(() => {
    if (dictationToggleNonce !== prevDictationNonceRef.current) {
      prevDictationNonceRef.current = dictationToggleNonce;
      if (dictationToggleNonce > 0) {
        toggleDictation();
      }
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dictationToggleNonce]);

  useEffect(() => {
    return () => {
      recognitionRef.current?.stop();
    };
  }, []);

  // Mention candidates
  const mentionCandidates: MentionCandidate[] = useMemo(() => {
    if (mentionQuery === null) return [];
    const q = mentionQuery.toLowerCase();
    const list: MentionCandidate[] = [];

    for (const b of allBots.filter((x) => !x.hidden)) {
      list.push({
        id: `bot:${b.id}`,
        label: b.name,
        insertText: `@${toMentionSlug(b.name)} `,
        category: 'Bot',
        subtext: b.status_subtext,
        bot: b,
      });
    }
    for (const ch of allChannels.filter((x) => !x.hidden)) {
      list.push({
        id: `ch:${ch.id}`,
        label: `#${ch.name}`,
        insertText: `@${toMentionSlug(ch.name)} `,
        category: 'Channel',
        subtext: `${ch.bot_ids.length} bots`,
      });
    }
    for (const sk of skillsQuery.data?.skills ?? []) {
      list.push({
        id: `skill:${sk.id}`,
        label: sk.name,
        insertText: `@${toMentionSlug(sk.slug || sk.name)} `,
        category: 'Skill',
        subtext: sk.description,
      });
    }
    for (const r of routinesQuery.data?.routines ?? []) {
      list.push({
        id: `routine:${r.id}`,
        label: r.name,
        insertText: `@${toMentionSlug(r.name)} `,
        category: 'Routine',
        subtext: r.schedule_type === 'cron' ? r.cron_expr || 'Scheduled' : 'Webhook',
      });
    }
    for (const app of (appsQuery.data?.apps ?? []).filter((a) => a.connected)) {
      list.push({
        id: `app:${app.id}`,
        label: app.name,
        insertText: `@${toMentionSlug(app.name)} `,
        category: 'App',
        subtext: app.account_label || 'Connected',
      });
    }

    return list
      .filter(
        (item) =>
          !q ||
          item.label.toLowerCase().includes(q) ||
          item.category.toLowerCase().includes(q),
      )
      .slice(0, 8);
  }, [mentionQuery, allBots, allChannels, skillsQuery.data, routinesQuery.data, appsQuery.data]);

  const sendMutation = useMutation({
    mutationFn: ({
      payload,
      signal,
    }: {
      payload: {
        content: string;
        reply_to_id: string | null;
        mentions: string[];
        attachment_ids: string[];
        page_context_id: string | null;
        override_model_id?: string | null;
        override_thinking_level?: string | null;
        include_browser_context?: boolean | null;
      };
      signal?: AbortSignal;
    }) => threadsApi.send(threadId, payload, { signal }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['thread-messages', threadId] });
      void queryClient.invalidateQueries({ queryKey: ['roster'] });
    },
    onError: (err: Error) => {
      if (err.name === 'AbortError') return;
      pushToast({ tone: 'error', title: 'Could not send message', description: err.message });
    },
    onSettled: () => {
      sendAbortRef.current = null;
      setStoppingPendingSend(false);
    },
  });

  const interruptMutation = useMutation({
    mutationFn: () => threadsApi.interrupt(threadId),
    onSuccess: () => {
      useChatStreamStore.getState().completeTurn(threadId);
      void queryClient.invalidateQueries({ queryKey: ['thread-messages', threadId] });
      pushToast({ tone: 'info', title: 'Stopped current run' });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not stop run', description: err.message });
    },
  });

  const handleFilesSelected = async (files: FileList | null) => {
    if (!files || files.length === 0) return;
    setUploading(true);
    try {
      for (const file of Array.from(files)) {
        const uploaded = await attachmentsApi.upload(file, threadId);
        addComposerAttachment(threadId, uploaded);
      }
    } catch (err) {
      pushToast({
        tone: 'error',
        title: 'Attachment upload failed',
        description: err instanceof Error ? err.message : 'Upload error',
      });
    } finally {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = '';
    }
  };

  const insertMention = (candidate: MentionCandidate) => {
    const el = textareaRef.current;
    const pos = el?.selectionStart ?? draft.length;
    const before = draft.slice(0, pos);
    const after = draft.slice(pos);
    const replaced = before.replace(/@([^\s@]*)$/, candidate.insertText);
    setComposerDraft(threadId, replaced + after);
    setMentionQuery(null);
    setMentionIdx(0);
    window.requestAnimationFrame(() => {
      el?.focus();
    });
  };

  const handleTextChange = (val: string) => {
    setComposerDraft(threadId, val);
    const el = textareaRef.current;
    const pos = el?.selectionStart ?? val.length;
    const before = val.slice(0, pos);
    const match = before.match(/(?:^|\s)@([^\s@]*)$/);
    if (match) {
      setMentionQuery(match[1] ?? '');
      setMentionIdx(0);
    } else {
      setMentionQuery(null);
    }
  };

  const handleSend = () => {
    const trimmed = draft.trim();
    if ((!trimmed && attachments.length === 0) || sendMutation.isPending) return;
    const mentions = Array.from(trimmed.matchAll(/@([A-Za-z0-9_#.-]+)/g))
      .map((m) => m[1])
      .filter((v): v is string => Boolean(v));
    const attachmentIds = attachments.map((a) => a.id);
    const replyId = replyTo?.id ?? null;

    setComposerDraft(threadId, '');
    clearComposerAttachments(threadId);
    setReplyTo(threadId, null);
    setMentionQuery(null);

    const controller = new AbortController();
    sendAbortRef.current = controller;

    sendMutation.mutate({
      payload: {
        content: trimmed || '(Attachment)',
        reply_to_id: replyId,
        mentions,
        attachment_ids: attachmentIds,
        page_context_id: pageContextId ?? null,
        ...(overrideModelId ? { override_model_id: overrideModelId } : {}),
        ...(overrideThinkingLevel ? { override_thinking_level: overrideThinkingLevel } : {}),
        ...(includeBrowserContext !== null
          ? { include_browser_context: includeBrowserContext }
          : {}),
      },
      signal: controller.signal,
    });
  };

  const handleStop = () => {
    if (sendMutation.isPending) {
      setStoppingPendingSend(true);
      sendAbortRef.current?.abort();
      interruptMutation.mutate();
      return;
    }
    interruptMutation.mutate();
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (mentionQuery !== null && mentionCandidates.length > 0) {
      if (e.key === 'ArrowDown') {
        e.preventDefault();
        setMentionIdx((i) => (i + 1) % mentionCandidates.length);
        return;
      }
      if (e.key === 'ArrowUp') {
        e.preventDefault();
        setMentionIdx((i) => (i - 1 + mentionCandidates.length) % mentionCandidates.length);
        return;
      }
      if (e.key === 'Enter' || e.key === 'Tab') {
        e.preventDefault();
        const selected = mentionCandidates[mentionIdx];
        if (selected) {
          insertMention(selected);
        }
        return;
      }
      if (e.key === 'Escape') {
        e.preventDefault();
        setMentionQuery(null);
        return;
      }
    }

    if (e.key === 'Enter' && (!e.shiftKey || e.metaKey || e.ctrlKey)) {
      e.preventDefault();
      handleSend();
    }
  };

  const placeholder = pageContextTitle
    ? `Message about ${pageContextTitle}`
    : bot
      ? `Message ${bot.name}`
      : channel
        ? `Message #${channel.name} (use @ to mention bots)`
        : 'Send a message…';

  const canSend = draft.trim().length > 0 || attachments.length > 0;
  const isRunning = Boolean(activeTurn) || sendMutation.isPending;
  const dictationTitle = dictating
    ? 'Stop voice dictation (Cmd/Ctrl+D)'
    : 'Voice dictation (Cmd/Ctrl+D)';
  const dictationLabel = dictating ? 'Stop voice dictation' : 'Start voice dictation';

  return (
    <div className="px-4 sm:px-6 pb-4 pt-2 shrink-0">
      <div className="max-w-[780px] mx-auto relative">
        {/* Inline @ Mention Popover */}
        {mentionQuery !== null && mentionCandidates.length > 0 && (
          <div
            className="absolute bottom-full left-0 mb-2 w-72 py-1.5 rounded-2xl z-30 max-h-64 overflow-y-auto"
            style={{
              backgroundColor: 'var(--bg-elevated)',
              border: '1px solid var(--border-strong)',
              boxShadow: 'var(--shadow-lg)',
            }}
          >
            <div
              className="px-3 py-1 text-[11px] font-medium uppercase tracking-wider"
              style={{ color: 'var(--text-muted)' }}
            >
              Mention
            </div>
            {mentionCandidates.map((item, idx) => (
              <button
                key={item.id}
                type="button"
                aria-label={`${item.label}`}
                onMouseDown={(e) => {
                  e.preventDefault();
                  insertMention(item);
                }}
                className="w-full flex items-center gap-2.5 px-3 py-1.5 text-left transition-colors"
                style={{
                  backgroundColor: idx === mentionIdx ? 'var(--bg-active)' : 'transparent',
                }}
              >
                {item.bot ? (
                  <BotAvatar
                    shape={item.bot.avatar_shape}
                    color={item.bot.avatar_color}
                    eyesLarge={item.bot.avatar_eyes_large}
                    size={22}
                  />
                ) : item.category === 'Channel' ? (
                  <Hash size={15} style={{ color: 'var(--text-secondary)' }} />
                ) : item.category === 'Skill' ? (
                  <BookOpen size={15} style={{ color: 'var(--accent-computer)' }} />
                ) : item.category === 'Routine' ? (
                  <CalendarClock size={15} style={{ color: 'var(--text-secondary)' }} />
                ) : (
                  <Plug size={15} style={{ color: 'var(--text-secondary)' }} />
                )}
                <div className="min-w-0 flex-1">
                  <div
                    className="text-[13px] font-medium truncate"
                    style={{ color: 'var(--text-primary)' }}
                  >
                    {item.label}
                  </div>
                  {item.subtext && (
                    <div className="text-[11px] truncate" style={{ color: 'var(--text-muted)' }}>
                      {item.subtext}
                    </div>
                  )}
                </div>
                <span
                  className="text-[10.5px] px-1.5 py-0.5 rounded"
                  style={{ backgroundColor: 'var(--bg-subtle)', color: 'var(--text-muted)' }}
                >
                  {item.category}
                </span>
              </button>
            ))}
          </div>
        )}

        {/* Composer Card */}
        <div
          className="rounded-2xl transition-shadow focus-within:shadow-sm"
          style={{
            backgroundColor: 'var(--bg-canvas)',
            border: '1px solid var(--border-strong)',
            boxShadow: 'var(--shadow-sm)',
          }}
        >
          {/* Reply-to banner */}
          {replyTo && (
            <div
              className="flex items-center justify-between gap-2 px-3.5 py-2 text-[12px]"
              style={{
                backgroundColor: 'var(--bg-sidebar)',
                borderBottom: '1px solid var(--border-subtle)',
                borderTopLeftRadius: '15px',
                borderTopRightRadius: '15px',
              }}
            >
              <div className="truncate" style={{ color: 'var(--text-secondary)' }}>
                Replying to <span className="font-medium">{replyTo.sender_name}</span>:{' '}
                {replyTo.content.slice(0, 80)}
              </div>
              <button
                type="button"
                onClick={() => setReplyTo(threadId, null)}
                aria-label="Cancel reply"
                className="p-0.5 rounded hover:bg-[var(--bg-subtle)]"
                style={{ color: 'var(--text-muted)' }}
              >
                <X size={13.5} />
              </button>
            </div>
          )}

          {/* Queued attachments */}
          {attachments.length > 0 && (
            <div className="flex flex-wrap gap-1.5 px-3.5 pt-2.5">
              {attachments.map((att) => (
                <span
                  key={att.id}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[12px]"
                  style={{
                    backgroundColor: 'var(--bg-subtle)',
                    border: '1px solid var(--border-subtle)',
                    color: 'var(--text-primary)',
                  }}
                >
                  <Paperclip size={12} style={{ color: 'var(--text-secondary)' }} />
                  <span className="max-w-[160px] truncate">{att.filename}</span>
                  <span className="text-[11px]" style={{ color: 'var(--text-muted)' }}>
                    {formatBytes(att.size_bytes)}
                  </span>
                  <button
                    type="button"
                    onClick={() => removeComposerAttachment(threadId, att.id)}
                    aria-label={`Remove ${att.filename}`}
                    className="p-0.5 rounded hover:bg-[var(--bg-active)]"
                  >
                    <X size={12} />
                  </button>
                </span>
              ))}
            </div>
          )}

          {/* Textarea */}
          <textarea
            ref={textareaRef}
            rows={1}
            value={draft}
            onChange={(e) => handleTextChange(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={placeholder}
            aria-label="Message composer"
            className="w-full px-4 pt-3 pb-1.5 text-[14px] bg-transparent outline-none resize-none leading-relaxed"
            style={{ color: 'var(--text-primary)' }}
          />

          {/* Bottom Controls */}
          <div className="flex items-center justify-between gap-1.5 px-2.5 pb-2.5 pt-1">
            <div className="flex items-center gap-0.5 xl:gap-1 min-w-0 flex-1 overflow-hidden">
              <input
                ref={fileInputRef}
                type="file"
                multiple
                className="hidden"
                onChange={(e) => void handleFilesSelected(e.target.files)}
              />
              <button
                type="button"
                disabled={uploading}
                onClick={() => fileInputRef.current?.click()}
                title="Attach files"
                aria-label="Attach files"
                className="shrink-0 p-1 xl:p-1.5 rounded-lg transition-colors hover:bg-[var(--bg-subtle)] disabled:opacity-50"
                style={{ color: 'var(--text-secondary)' }}
              >
                {uploading ? (
                  <Loader2 size={16} className="animate-spin" />
                ) : (
                  <Paperclip size={16} strokeWidth={1.75} />
                )}
              </button>

              <button
                type="button"
                onClick={toggleDictation}
                title={`${dictationTitle}`}
                aria-label={`${dictationLabel}`}
                aria-pressed={dictating}
                className="shrink-0 p-1 xl:p-1.5 rounded-lg transition-colors hover:bg-[var(--bg-subtle)]"
                style={{
                  backgroundColor: dictating ? 'var(--status-danger-bg)' : 'transparent',
                  color: dictating ? 'var(--status-danger)' : 'var(--text-secondary)',
                }}
              >
                {dictating ? (
                  <MicOff size={16} strokeWidth={1.85} />
                ) : (
                  <Mic size={16} strokeWidth={1.75} />
                )}
              </button>

              {/* Per-turn overrides */}
              <select
                aria-label="Turn model override"
                title="Per-turn model override"
                value={overrideModelId}
                onChange={(e) => setOverrideModelId(e.target.value)}
                className="min-w-0 shrink max-w-[74px] xl:max-w-[116px] px-1 xl:px-1.5 py-1 rounded-lg text-[11.5px] outline-none cursor-pointer truncate"
                style={{
                  backgroundColor: overrideModelId ? 'var(--bg-active)' : 'var(--bg-subtle)',
                  color: overrideModelId ? 'var(--text-primary)' : 'var(--text-secondary)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <option value="">Model: Default</option>
                {filteredModels.map((m) => (
                  <option key={m.id} value={m.id}>
                    {m.label} {m.is_hydrogen ? '(Hydrogen)' : ''}
                  </option>
                ))}
              </select>

              <select
                aria-label="Turn thinking level override"
                title="Per-turn thinking level override"
                value={overrideThinkingLevel}
                onChange={(e) => setOverrideThinkingLevel(e.target.value as ThinkingLevel | '')}
                className="min-w-0 shrink max-w-[74px] xl:max-w-[112px] px-1 xl:px-1.5 py-1 rounded-lg text-[11.5px] outline-none cursor-pointer truncate"
                style={{
                  backgroundColor: overrideThinkingLevel ? 'var(--bg-active)' : 'var(--bg-subtle)',
                  color: overrideThinkingLevel ? 'var(--text-primary)' : 'var(--text-secondary)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <option value="">Thinking: Default</option>
                {THINKING_LEVELS.map((t) => (
                  <option key={t.id} value={t.id}>
                    Thinking: {t.label}
                  </option>
                ))}
              </select>

              <div
                className="inline-flex items-center gap-0.5 xl:gap-1 px-1 xl:px-1.5 py-1 rounded-lg text-[11.5px] min-w-0 shrink max-w-[92px] xl:max-w-none"
                style={{
                  backgroundColor:
                    includeBrowserContext === true
                      ? 'var(--accent-computer-tint)'
                      : includeBrowserContext === false
                        ? 'var(--bg-active)'
                        : 'var(--bg-subtle)',
                  color:
                    includeBrowserContext === true
                      ? 'var(--accent-computer)'
                      : 'var(--text-secondary)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <Globe size={12} strokeWidth={1.75} className="shrink-0" />
                <select
                  aria-label="Include browser context for this message"
                  title="Per-turn browser context"
                  value={
                    includeBrowserContext === null
                      ? 'default'
                      : includeBrowserContext
                        ? 'on'
                        : 'off'
                  }
                  onChange={(e) => {
                    const val = e.target.value;
                    setIncludeBrowserContext(
                      val === 'default' ? null : val === 'on',
                    );
                  }}
                  className="min-w-0 w-full max-w-[68px] xl:max-w-[106px] bg-transparent outline-none cursor-pointer text-[11.5px] truncate"
                >
                  <option value="default">Browser: Default</option>
                  <option value="on">Browser: On</option>
                  <option value="off">Browser: Off</option>
                </select>
              </div>

              <span
                className="text-[11.5px] hidden 2xl:inline ml-0.5 shrink-0"
                style={{ color: 'var(--text-muted)' }}
              >
                @ to mention
              </span>
            </div>

            <div className="flex items-center gap-1.5 shrink-0">
              {isRunning && (
                <button
                  type="button"
                  onClick={handleStop}
                  disabled={interruptMutation.isPending || stoppingPendingSend}
                  title="Stop current generation"
                  aria-label="Stop current generation"
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[12.5px] font-medium transition-opacity hover:opacity-90"
                  style={{
                    backgroundColor: 'var(--status-danger-bg)',
                    color: 'var(--status-danger)',
                    border: '1px solid rgba(220, 38, 38, 0.2)',
                  }}
                >
                  <Square size={11} fill="currentColor" />
                  <span>Stop</span>
                </button>
              )}

              <button
                type="button"
                disabled={!canSend || sendMutation.isPending}
                onClick={handleSend}
                title="Send message (Enter)"
                aria-label="Send message"
                className="w-8 h-8 rounded-full flex items-center justify-center transition-opacity disabled:opacity-35"
                style={{
                  backgroundColor: 'var(--accent-primary)',
                  color: 'var(--bg-canvas)',
                }}
              >
                {sendMutation.isPending ? (
                  <Loader2 size={15} className="animate-spin" />
                ) : (
                  <ArrowUp size={16} strokeWidth={2.2} />
                )}
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
