import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import {
  ArrowDown,
  Check,
  Copy,
  Download,
  FilePlus2,
  Loader2,
  Paperclip,
  Reply,
} from 'lucide-react';
import { MarkdownRenderer } from '../../components/MarkdownRenderer';
import { attachmentsApi, threadsApi } from '../../lib/api';
import {
  copyToClipboard,
  downloadTextFile,
  formatBytes,
  formatClockTime,
} from '../../lib/markdown';
import type {
  ApprovalCard as ApprovalCardType,
  Bot,
  DraftCard,
  Message,
  SecureFormCard as SecureFormCardType,
} from '../../lib/types';
import { useChatStreamStore } from '../../stores/chatStreamStore';
import { useHitlStore } from '../../stores/hitlStore';
import { useUiStore } from '../../stores/uiStore';
import { PageChatCard } from '../artifacts/PageChatCard';
import { ApprovalCard } from '../hitl/ApprovalCard';
import { EditableDraftCard } from '../hitl/EditableDraftCard';
import { MemoryDiffChip } from '../hitl/MemoryDiffChip';
import { SecureFormCard } from '../hitl/SecureFormCard';
import { BotAvatar } from '../roster/BotAvatar';
import { ThinkingAccordion } from './ThinkingAccordion';
import { ToolCallCard } from './ToolCallCard';
import { VerdictCard } from './VerdictCard';

interface TranscriptViewportProps {
  threadId: string;
  messages: Message[];
  approvals: ApprovalCardType[];
  drafts: DraftCard[];
  secureForms: SecureFormCardType[];
  hasMore: boolean;
  loadingMore: boolean;
  onLoadMore: () => void;
  bot?: Bot | null;
  allBots: Bot[];
  isGroupChannel: boolean;
  compact?: boolean;
}

type TimelineItem =
  | { kind: 'message'; id: string; createdAt: string; data: Message }
  | { kind: 'approval'; id: string; createdAt: string; data: ApprovalCardType }
  | { kind: 'draft'; id: string; createdAt: string; data: DraftCard }
  | { kind: 'secure_form'; id: string; createdAt: string; data: SecureFormCardType };

const REACTIONS = ['👍', '✅', '🔥'];

export const TranscriptViewport: React.FC<TranscriptViewportProps> = ({
  threadId,
  messages,
  approvals,
  drafts,
  secureForms,
  hasMore,
  loadingMore,
  onLoadMore,
  bot,
  allBots,
  isGroupChannel,
  compact = false,
}) => {
  const queryClient = useQueryClient();
  const accentMode = useUiStore((s) => s.accentMode);
  const setReplyTo = useUiStore((s) => s.setReplyTo);
  const setActivePageId = useUiStore((s) => s.setActivePageId);
  const pushToast = useUiStore((s) => s.pushToast);

  const activeTurn = useChatStreamStore((s) => s.activeTurnByThread[threadId]);
  const liveApprovals = useHitlStore((s) => s.approvalsByThread[threadId]);
  const liveDrafts = useHitlStore((s) => s.draftsByThread[threadId]);
  const liveSecureForms = useHitlStore((s) => s.secureFormsByThread[threadId]);

  const scrollRef = useRef<HTMLDivElement | null>(null);
  const [autoFollow, setAutoFollow] = useState(true);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const mergedApprovals = useMemo(() => {
    const map = new Map<string, ApprovalCardType>();
    for (const a of approvals) map.set(a.id, a);
    for (const a of liveApprovals ?? []) map.set(a.id, a);
    return Array.from(map.values());
  }, [approvals, liveApprovals]);

  const mergedDrafts = useMemo(() => {
    const map = new Map<string, DraftCard>();
    for (const d of drafts) map.set(d.id, d);
    for (const d of liveDrafts ?? []) map.set(d.id, d);
    return Array.from(map.values());
  }, [drafts, liveDrafts]);

  const mergedSecureForms = useMemo(() => {
    const map = new Map<string, SecureFormCardType>();
    for (const f of secureForms) map.set(f.id, f);
    for (const f of liveSecureForms ?? []) map.set(f.id, f);
    return Array.from(map.values());
  }, [secureForms, liveSecureForms]);

  const timeline: TimelineItem[] = useMemo(() => {
    const items: TimelineItem[] = [
      ...messages.map((m) => ({
        kind: 'message' as const,
        id: `m_${m.id}`,
        createdAt: m.created_at,
        data: m,
      })),
      ...mergedApprovals.map((a) => ({
        kind: 'approval' as const,
        id: `a_${a.id}`,
        createdAt: a.created_at,
        data: a,
      })),
      ...mergedDrafts.map((d) => ({
        kind: 'draft' as const,
        id: `d_${d.id}`,
        createdAt: d.created_at,
        data: d,
      })),
      ...mergedSecureForms.map((f) => ({
        kind: 'secure_form' as const,
        id: `f_${f.id}`,
        createdAt: f.created_at,
        data: f,
      })),
    ];
    items.sort((a, b) => a.createdAt.localeCompare(b.createdAt));
    return items;
  }, [messages, mergedApprovals, mergedDrafts, mergedSecureForms]);

  const messagesById = useMemo(() => {
    const m = new Map<string, Message>();
    for (const msg of messages) m.set(msg.id, msg);
    return m;
  }, [messages]);

  const botsById = useMemo(() => {
    const m = new Map<string, Bot>();
    for (const b of allBots) m.set(b.id, b);
    return m;
  }, [allBots]);

  const scrollToBottom = useCallback((smooth = true) => {
    const el = scrollRef.current;
    if (!el) return;
    el.scrollTo({
      top: el.scrollHeight,
      behavior: smooth ? 'smooth' : 'auto',
    });
    setAutoFollow(true);
  }, []);

  // Keep pinned to bottom when autoFollow is active
  useEffect(() => {
    if (!autoFollow) return;
    const el = scrollRef.current;
    if (!el) return;
    el.scrollTop = el.scrollHeight;
  }, [
    autoFollow,
    timeline.length,
    activeTurn?.rawText,
    activeTurn?.thinkingText,
    activeTurn?.toolCalls,
  ]);

  // Reset autoFollow when switching threads
  useEffect(() => {
    setAutoFollow(true);
    const id = window.requestAnimationFrame(() => scrollToBottom(false));
    return () => window.cancelAnimationFrame(id);
  }, [threadId, scrollToBottom]);

  const handleScroll = () => {
    const el = scrollRef.current;
    if (!el) return;
    const distanceFromBottom = el.scrollHeight - el.scrollTop - el.clientHeight;
    setAutoFollow(distanceFromBottom < 72);
  };

  const reactMutation = useMutation({
    mutationFn: ({ messageId, emoji }: { messageId: string; emoji: string }) =>
      threadsApi.react(messageId, emoji),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['thread-messages', threadId] });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not update reaction', description: err.message });
    },
  });

  const toPageMutation = useMutation({
    mutationFn: (messageId: string) => threadsApi.toPage(messageId),
    onSuccess: ({ page }) => {
      void queryClient.invalidateQueries({ queryKey: ['thread-messages', threadId] });
      void queryClient.invalidateQueries({ queryKey: ['library'] });
      setActivePageId(page.id);
      pushToast({ tone: 'success', title: 'Saved as interactive Page' });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not save as Page', description: err.message });
    },
  });

  const userBubbleBg =
    accentMode === 'bot_color' && bot && !isGroupChannel
      ? `${bot.avatar_color}14`
      : 'var(--bg-subtle)';
  const userBubbleBorder =
    accentMode === 'bot_color' && bot && !isGroupChannel
      ? `${bot.avatar_color}2E`
      : 'var(--border-subtle)';

  return (
    <div className="relative flex-1 min-h-0 flex flex-col">
      <div
        ref={scrollRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto px-4 sm:px-6 py-5"
      >
        <div className={`${compact ? 'max-w-full' : 'max-w-[780px]'} mx-auto space-y-5`}>
          {hasMore && (
            <div className="flex justify-center">
              <button
                type="button"
                onClick={onLoadMore}
                disabled={loadingMore}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[12px] font-medium hover:bg-[var(--bg-active)] transition-colors"
                style={{
                  backgroundColor: 'var(--bg-subtle)',
                  color: 'var(--text-secondary)',
                }}
              >
                {loadingMore && <Loader2 size={12} className="animate-spin" />}
                Load earlier messages
              </button>
            </div>
          )}

          {timeline.length === 0 && !activeTurn && (
            <div className="py-16 text-center space-y-3">
              {bot && (
                <div className="flex justify-center">
                  <BotAvatar
                    shape={bot.avatar_shape}
                    color={bot.avatar_color}
                    eyesLarge={bot.avatar_eyes_large}
                    size={52}
                  />
                </div>
              )}
              <div
                className="text-[16px] font-semibold tracking-tight"
                style={{ color: 'var(--text-primary)' }}
              >
                {bot ? `Say hello to ${bot.name}` : 'Start collaborating'}
              </div>
              <p
                className="text-[13.5px] max-w-md mx-auto"
                style={{ color: 'var(--text-secondary)' }}
              >
                {bot
                  ? 'Describe their role, paste files anywhere on the window, or ask them to use their computer.'
                  : 'Mention bots with @ to delegate work, produce interactive Pages, and coordinate handoffs.'}
              </p>
            </div>
          )}

          {timeline.map((item) => {
            if (item.kind === 'approval') {
              return (
                <ApprovalCard
                  key={item.id}
                  card={item.data}
                  isGroupChannel={isGroupChannel}
                />
              );
            }
            if (item.kind === 'draft') {
              return <EditableDraftCard key={item.id} card={item.data} />;
            }
            if (item.kind === 'secure_form') {
              return <SecureFormCard key={item.id} card={item.data} />;
            }

            const msg = item.data;
            const isUser = msg.sender_type === 'user';
            const isSystem = msg.sender_type === 'system';
            const senderBot = msg.sender_bot_id ? botsById.get(msg.sender_bot_id) : bot;
            const replyTarget = msg.reply_to_id ? messagesById.get(msg.reply_to_id) : null;

            if (isSystem) {
              return (
                <div
                  key={item.id}
                  className="flex justify-center py-1"
                >
                  <span
                    className="px-3 py-1 rounded-full text-[12px]"
                    style={{
                      backgroundColor: 'var(--bg-subtle)',
                      color: 'var(--text-secondary)',
                    }}
                  >
                    {msg.content}
                  </span>
                </div>
              );
            }

            if (isUser) {
              return (
                <div key={item.id} className="group flex flex-col items-end">
                  {replyTarget && (
                    <div
                      className="mb-1 px-2.5 py-1 rounded-lg text-[11.5px] max-w-[80%] truncate"
                      style={{
                        backgroundColor: 'var(--bg-sidebar)',
                        color: 'var(--text-muted)',
                        borderLeft: '2px solid var(--border-strong)',
                      }}
                    >
                      Replying to {replyTarget.sender_name}: {replyTarget.content.slice(0, 90)}
                    </div>
                  )}

                  <div
                    className="max-w-[85%] px-4 py-2.5 rounded-2xl rounded-tr-sm"
                    style={{
                      backgroundColor: userBubbleBg,
                      border: `1px solid ${userBubbleBorder}`,
                      color: 'var(--text-primary)',
                    }}
                  >
                    <div className="whitespace-pre-wrap text-[14px] leading-relaxed">
                      {msg.content}
                    </div>

                    {msg.attachments && msg.attachments.length > 0 && (
                      <div className="flex flex-wrap gap-1.5 mt-2">
                        {msg.attachments.map((att) => (
                          <a
                            key={att.id}
                            href={attachmentsApi.downloadUrl(att.id)}
                            target="_blank"
                            rel="noopener noreferrer"
                            aria-label={`Download ${att.filename}`}
                            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[12px] hover:underline"
                            style={{
                              backgroundColor: 'var(--bg-canvas)',
                              border: '1px solid var(--border-subtle)',
                              color: 'var(--text-secondary)',
                            }}
                          >
                            <Paperclip size={12} />
                            <span className="truncate max-w-[180px]">{att.filename}</span>
                            <span className="text-[11px]" style={{ color: 'var(--text-muted)' }}>
                              {formatBytes(att.size_bytes)}
                            </span>
                          </a>
                        ))}
                      </div>
                    )}
                  </div>

                  <div className="mt-1 flex items-center gap-2 text-[11px]" style={{ color: 'var(--text-muted)' }}>
                    <span className="tabular-nums">{formatClockTime(msg.created_at)}</span>
                    <div className="opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 flex items-center gap-1 transition-opacity">
                      <button
                        type="button"
                        onClick={() => setReplyTo(threadId, msg)}
                        title="Reply"
                        aria-label="Reply to message"
                        className="p-1 rounded hover:bg-[var(--bg-subtle)]"
                      >
                        <Reply size={12.5} />
                      </button>
                      <button
                        type="button"
                        onClick={async () => {
                          await copyToClipboard(msg.content);
                          setCopiedId(msg.id);
                          window.setTimeout(() => setCopiedId(null), 1400);
                        }}
                        title="Copy message"
                        aria-label="Copy message"
                        className="p-1 rounded hover:bg-[var(--bg-subtle)]"
                      >
                        {copiedId === msg.id ? <Check size={12.5} /> : <Copy size={12.5} />}
                      </button>
                    </div>
                  </div>
                </div>
              );
            }

            // Bot Message
            const reactionEntries = Object.entries(msg.reactions || {}).filter(
              ([, count]) => count > 0,
            );

            return (
              <div key={item.id} className="group flex items-start gap-3">
                <div className="pt-0.5 shrink-0">
                  <BotAvatar
                    shape={senderBot?.avatar_shape ?? 'sparkle'}
                    color={senderBot?.avatar_color ?? '#7C3AED'}
                    eyesLarge={senderBot?.avatar_eyes_large}
                    size={28}
                  />
                </div>

                <div className="min-w-0 flex-1">
                  <div className="flex items-baseline gap-2 mb-1">
                    <span
                      className="text-[13px] font-semibold"
                      style={{ color: 'var(--text-primary)' }}
                    >
                      {msg.sender_name || senderBot?.name || 'Bot'}
                    </span>
                    <span className="text-[11px] tabular-nums" style={{ color: 'var(--text-muted)' }}>
                      {formatClockTime(msg.created_at)}
                    </span>
                    {msg.model_id && (
                      <span
                        className="text-[10.5px] font-mono hidden sm:inline"
                        style={{ color: 'var(--text-muted)' }}
                      >
                        {msg.model_id}
                      </span>
                    )}
                  </div>

                  {replyTarget && (
                    <div
                      className="mb-1.5 px-2.5 py-1 rounded-lg text-[11.5px] truncate"
                      style={{
                        backgroundColor: 'var(--bg-sidebar)',
                        color: 'var(--text-muted)',
                        borderLeft: '2px solid var(--border-strong)',
                      }}
                    >
                      {replyTarget.sender_name}: {replyTarget.content.slice(0, 100)}
                    </div>
                  )}

                  {msg.thinking_text && <ThinkingAccordion text={msg.thinking_text} />}

                  {msg.tool_calls && msg.tool_calls.length > 0 && (
                    <div className="mb-2">
                      {msg.tool_calls.map((tc) => (
                        <ToolCallCard key={tc.call_id} call={tc} />
                      ))}
                    </div>
                  )}

                  <MarkdownRenderer content={msg.content} />

                  <VerdictCard threadId={threadId} message={msg} />

                  {msg.attachments && msg.attachments.length > 0 && (
                    <div className="flex flex-wrap gap-1.5 mt-2">
                      {msg.attachments.map((att) => (
                        <a
                          key={att.id}
                          href={attachmentsApi.downloadUrl(att.id)}
                          target="_blank"
                          rel="noopener noreferrer"
                          aria-label={`Download ${att.filename}`}
                          className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[12px] hover:underline"
                          style={{
                            backgroundColor: 'var(--bg-sidebar)',
                            border: '1px solid var(--border-subtle)',
                            color: 'var(--text-secondary)',
                          }}
                        >
                          <Paperclip size={12} />
                          <span>{att.filename}</span>
                        </a>
                      ))}
                    </div>
                  )}

                  {msg.artifacts && msg.artifacts.length > 0 && (
                    <div className="space-y-1.5">
                      {msg.artifacts.map((art) => (
                        <PageChatCard key={art.id} artifact={art} />
                      ))}
                    </div>
                  )}

                  <MemoryDiffChip diffs={msg.memory_diffs} />

                  {/* Reactions + Hover action bar */}
                  <div className="mt-2 flex flex-wrap items-center gap-1.5">
                    {reactionEntries.map(([emoji, count]) => (
                      <button
                        key={emoji}
                        type="button"
                        aria-label={`React ${emoji} (${count})`}
                        onClick={() => reactMutation.mutate({ messageId: msg.id, emoji })}
                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11.5px] tabular-nums transition-colors hover:bg-[var(--bg-active)]"
                        style={{
                          backgroundColor: 'var(--bg-subtle)',
                          border: '1px solid var(--border-subtle)',
                        }}
                      >
                        <span>{emoji}</span>
                        <span style={{ color: 'var(--text-secondary)' }}>{count}</span>
                      </button>
                    ))}

                    <div className="opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 inline-flex items-center gap-0.5 transition-opacity">
                      {REACTIONS.map((emoji) => (
                        <button
                          key={emoji}
                          type="button"
                          onClick={() => reactMutation.mutate({ messageId: msg.id, emoji })}
                          title={`React ${emoji}`}
                          aria-label={`React ${emoji}`}
                          className="px-1.5 py-0.5 rounded-md text-[12px] hover:bg-[var(--bg-subtle)]"
                        >
                          {emoji}
                        </button>
                      ))}
                      <button
                        type="button"
                        onClick={() => setReplyTo(threadId, msg)}
                        title="Reply"
                        aria-label="Reply to message"
                        className="p-1 rounded-md hover:bg-[var(--bg-subtle)]"
                        style={{ color: 'var(--text-muted)' }}
                      >
                        <Reply size={13.5} strokeWidth={1.75} />
                      </button>
                      <button
                        type="button"
                        onClick={async () => {
                          await copyToClipboard(msg.content);
                          setCopiedId(msg.id);
                          window.setTimeout(() => setCopiedId(null), 1400);
                        }}
                        title="Copy markdown"
                        aria-label="Copy markdown"
                        className="p-1 rounded-md hover:bg-[var(--bg-subtle)]"
                        style={{ color: 'var(--text-muted)' }}
                      >
                        {copiedId === msg.id ? (
                          <Check size={13.5} style={{ color: 'var(--status-ok)' }} />
                        ) : (
                          <Copy size={13.5} strokeWidth={1.75} />
                        )}
                      </button>
                      <button
                        type="button"
                        onClick={() => toPageMutation.mutate(msg.id)}
                        disabled={toPageMutation.isPending}
                        title="Save as interactive Page"
                        aria-label="Save as interactive Page"
                        className="p-1 rounded-md hover:bg-[var(--bg-subtle)]"
                        style={{ color: 'var(--text-muted)' }}
                      >
                        <FilePlus2 size={13.5} strokeWidth={1.75} />
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          downloadTextFile(
                            `${(msg.sender_name || 'bot').toLowerCase().replace(/\s+/g, '-')}-${msg.id.slice(-6)}.md`,
                            msg.content,
                          )
                        }
                        title="Download markdown"
                        aria-label="Download markdown"
                        className="p-1 rounded-md hover:bg-[var(--bg-subtle)]"
                        style={{ color: 'var(--text-muted)' }}
                      >
                        <Download size={13.5} strokeWidth={1.75} />
                      </button>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}

          {/* Live Streaming Draft Bubble */}
          {activeTurn && (
            <div className="flex items-start gap-3">
              <div className="pt-0.5 shrink-0">
                <BotAvatar
                  shape={
                    (activeTurn.senderBotId && botsById.get(activeTurn.senderBotId)?.avatar_shape) ||
                    bot?.avatar_shape ||
                    'sparkle'
                  }
                  color={
                    (activeTurn.senderBotId && botsById.get(activeTurn.senderBotId)?.avatar_color) ||
                    bot?.avatar_color ||
                    '#7C3AED'
                  }
                  eyesLarge={Boolean(
                    (activeTurn.senderBotId
                      ? botsById.get(activeTurn.senderBotId)?.avatar_eyes_large
                      : undefined) ?? bot?.avatar_eyes_large,
                  )}
                  state={activeTurn.status === 'awaiting_hitl' ? 'waiting_human' : 'working'}
                  size={28}
                />
              </div>

              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 mb-1">
                  <span
                    className="text-[13px] font-semibold"
                    style={{ color: 'var(--text-primary)' }}
                  >
                    {activeTurn.senderName || bot?.name || 'Bot'}
                  </span>
                  <span
                    className="inline-flex items-center gap-1 text-[11.5px]"
                    style={{ color: 'var(--accent-computer)' }}
                  >
                    <Loader2 size={11.5} className="animate-spin" />
                    {activeTurn.status === 'tool_running'
                      ? 'Using tool…'
                      : activeTurn.status === 'awaiting_hitl'
                        ? 'Waiting for approval…'
                        : 'Working…'}
                  </span>
                </div>

                {activeTurn.thinkingText && (
                  <ThinkingAccordion
                    text={activeTurn.thinkingText}
                    summary={activeTurn.thinkingSummary}
                    streaming
                  />
                )}

                {Object.values(activeTurn.toolCalls).length > 0 && (
                  <div className="mb-2">
                    {Object.values(activeTurn.toolCalls).map((tc) => (
                      <ToolCallCard key={tc.call_id} call={tc} />
                    ))}
                  </div>
                )}

                {activeTurn.rawText ? (
                  <MarkdownRenderer content={activeTurn.rawText} streaming />
                ) : (
                  <div className="text-[13px]" style={{ color: 'var(--text-muted)' }}>
                    Drafting response…
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Floating Scroll-to-bottom pill */}
      {!autoFollow && (
        <div className="pointer-events-none absolute bottom-3 left-0 right-0 flex justify-center z-10">
          <button
            type="button"
            onClick={() => scrollToBottom(true)}
            className="pointer-events-auto inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-[12px] font-medium transition-transform hover:scale-[1.02]"
            style={{
              backgroundColor: 'var(--bg-elevated)',
              border: '1px solid var(--border-strong)',
              color: 'var(--text-primary)',
              boxShadow: 'var(--shadow-md)',
            }}
          >
            <ArrowDown size={13.5} strokeWidth={2} />
            Scroll to bottom
          </button>
        </div>
      )}
    </div>
  );
};
