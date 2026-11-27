import type { QueryClient } from '@tanstack/react-query';
import { withAuthToken } from './api';
import { reportClientError } from './diagnostics';
import type {
  ApprovalCard,
  ComputerStatus,
  DraftCard,
  Message,
  SecureFormCard,
  ServerSseEnvelope,
  ThreadMessagesResponse,
  ToolCallItem,
} from './types';
import { useChatStreamStore } from '../stores/chatStreamStore';
import { usePresenceStore } from '../stores/presenceStore';
import { useHitlStore } from '../stores/hitlStore';
import { useComputerStore } from '../stores/computerStore';
import { useUiStore } from '../stores/uiStore';

export function parseSseEventId(raw: string): {
  epoch: string | null;
  seq: number | null;
} {
  const trimmed = raw.trim();
  if (!trimmed) return { epoch: null, seq: null };
  const evtEpochMatch = /^evt_0*(\d+)_([A-Za-z0-9_-]+)$/.exec(trimmed);
  if (evtEpochMatch && evtEpochMatch[1] !== undefined && evtEpochMatch[2] !== undefined) {
    return { epoch: evtEpochMatch[2], seq: Number(evtEpochMatch[1]) };
  }
  const colonIdx = trimmed.indexOf(':');
  if (colonIdx !== -1) {
    const epoch = trimmed.slice(0, colonIdx).trim() || null;
    const seqPart = trimmed.slice(colonIdx + 1).trim();
    if (!/^\d+$/.test(seqPart)) {
      return { epoch, seq: null };
    }
    return { epoch, seq: Number(seqPart) };
  }
  const match = /^evt_0*(\d+)$/.exec(trimmed);
  if (match && match[1] !== undefined) {
    return { epoch: null, seq: Number(match[1]) };
  }
  if (/^\d+$/.test(trimmed)) {
    return { epoch: null, seq: Number(trimmed) };
  }
  return { epoch: null, seq: null };
}

export function startSseBridge(queryClient: QueryClient): () => void {
  let es: EventSource | null = null;
  let closed = false;
  let reconnectTimer: number | null = null;
  let attempt = 0;

  const dispatchEnvelope = (env: ServerSseEnvelope) => {
    const streamStore = useChatStreamStore.getState();
    const presenceStore = usePresenceStore.getState();
    const hitlStore = useHitlStore.getState();
    const computerStore = useComputerStore.getState();
    const uiStore = useUiStore.getState();

    if (env.id) {
      streamStore.setLastEventId(env.id);
    }

    const threadId = env.thread_id || '';
    const botId = env.bot_id || '';
    const payload = env.payload || {};

    switch (env.type) {
      case 'bot.presence': {
        if (botId) {
          presenceStore.updatePresence(botId, {
            state: (payload.state as 'idle' | 'acknowledging' | 'working' | 'waiting_human' | 'error') || 'idle',
            step_label: typeof payload.step_label === 'string' ? payload.step_label : undefined,
            subtext: typeof payload.subtext === 'string' ? payload.subtext : 'Ready',
            computer_active: Boolean(payload.computer_active),
          });
        }
        break;
      }

      case 'turn.started': {
        if (threadId) {
          streamStore.startTurn(threadId, {
            turnId: String(payload.turn_id || env.turn_id || `trn_${Date.now()}`),
            messageId: String(payload.message_id || `msg_${Date.now()}`),
            senderBotId: typeof payload.sender_bot_id === 'string' ? payload.sender_bot_id : botId || null,
            senderName: typeof payload.sender_name === 'string' ? payload.sender_name : 'Bot',
            modelId: typeof payload.model_id === 'string' ? payload.model_id : null,
            engineId: typeof payload.engine_id === 'string' ? payload.engine_id : null,
          });
        }
        break;
      }

      case 'thinking.delta': {
        if (threadId) {
          streamStore.appendThinkingDelta(
            threadId,
            String(payload.message_id || ''),
            String(payload.text_delta || ''),
            typeof payload.collapsed_summary === 'string' ? payload.collapsed_summary : undefined,
          );
        }
        break;
      }

      case 'message.delta': {
        if (threadId) {
          streamStore.appendMessageDelta(
            threadId,
            String(payload.message_id || ''),
            String(payload.text_delta || ''),
          );
        }
        break;
      }

      case 'tool.call.updated': {
        if (threadId) {
          const tc: ToolCallItem = {
            call_id: String(payload.call_id || `tc_${Date.now()}`),
            tool_name: String(payload.tool_name || 'tool'),
            category: String(payload.category || 'mcp'),
            status: String(payload.status || 'running'),
            summary: String(payload.summary || ''),
            output_preview: typeof payload.output_preview === 'string' ? payload.output_preview : undefined,
          };
          streamStore.upsertToolCall(threadId, String(payload.message_id || ''), tc);
        }
        break;
      }

      case 'message.completed': {
        if (threadId) {
          const completedMsg = payload.message as Message | undefined;
          const turnId = payload.turn_id
            ? String(payload.turn_id)
            : env.turn_id
              ? String(env.turn_id)
              : undefined;
          streamStore.completeTurn(
            threadId,
            String(payload.message_id || completedMsg?.id || ''),
            turnId,
          );
          if (completedMsg) {
            queryClient.setQueryData<ThreadMessagesResponse>(
              ['thread-messages', threadId],
              (prev) => {
                if (!prev) return prev;
                const exists = prev.messages.some((m) => m.id === completedMsg.id);
                const nextMessages = exists
                  ? prev.messages.map((m) => (m.id === completedMsg.id ? completedMsg : m))
                  : [...prev.messages, completedMsg];
                return { ...prev, messages: nextMessages };
              },
            );
          }
          void queryClient.invalidateQueries({ queryKey: ['thread-messages', threadId] });
          void queryClient.invalidateQueries({ queryKey: ['roster'] });
          if (botId) {
            void queryClient.invalidateQueries({ queryKey: ['library', botId] });
          }
        }
        break;
      }

      case 'hitl.approval.requested':
      case 'hitl.approval.resolved':
      case 'hitl.approval.expired': {
        const card = payload.approval as ApprovalCard | undefined;
        if (card) {
          hitlStore.upsertApproval(card);
          if (env.type === 'hitl.approval.requested' && card.thread_id) {
            streamStore.markAwaitingHitl(card.thread_id);
          }
          void queryClient.invalidateQueries({ queryKey: ['thread-messages', card.thread_id] });
          void queryClient.invalidateQueries({ queryKey: ['roster'] });
        }
        break;
      }

      case 'hitl.draft.created':
      case 'hitl.draft.updated': {
        const draft = payload.draft as DraftCard | undefined;
        if (draft) {
          hitlStore.upsertDraft(draft);
          void queryClient.invalidateQueries({ queryKey: ['thread-messages', draft.thread_id] });
        }
        break;
      }

      case 'hitl.secure_form.requested':
      case 'hitl.secure_form.resolved': {
        const form = payload.form as SecureFormCard | undefined;
        if (form) {
          hitlStore.upsertSecureForm(form);
          void queryClient.invalidateQueries({ queryKey: ['thread-messages', form.thread_id] });
        }
        break;
      }

      case 'computer.state': {
        const st = payload as unknown as ComputerStatus;
        if (st && st.vm_id) {
          computerStore.setStatus(st);
          queryClient.setQueryData(['computer-status', st.vm_id], st);
        }
        break;
      }

      case 'artifact.page.updated': {
        void queryClient.invalidateQueries({ queryKey: ['library'] });
        const art = payload.artifact as { id?: string } | undefined;
        if (art?.id) {
          void queryClient.invalidateQueries({ queryKey: ['page', art.id] });
        }
        if (threadId) {
          void queryClient.invalidateQueries({ queryKey: ['thread-messages', threadId] });
        }
        break;
      }

      case 'routine.run.status': {
        const routineId = String(payload.routine_id || '');
        if (routineId) {
          void queryClient.invalidateQueries({ queryKey: ['routine-runs', routineId] });
        }
        if (botId) {
          void queryClient.invalidateQueries({ queryKey: ['routines', botId] });
        }
        break;
      }

      case 'handoff.dispatched': {
        const fromName = String(payload.from_name || 'Bot');
        const toName = String(payload.to_name || 'Bot');
        const summary = String(payload.summary || '');
        uiStore.pushToast({
          tone: 'info',
          title: `Handoff: ${fromName} → ${toName}`,
          description: summary || undefined,
        });
        if (threadId) {
          void queryClient.invalidateQueries({ queryKey: ['thread-messages', threadId] });
        }
        break;
      }

      case 'stream.resync': {
        if (!env.id && typeof payload.last_event_id === 'string' && payload.last_event_id) {
          streamStore.setLastEventId(payload.last_event_id);
        }
        streamStore.clearTurns();
        hitlStore.markResync();
        void queryClient.invalidateQueries({ queryKey: ['thread-messages'] });
        void queryClient.invalidateQueries({ queryKey: ['roster'] });
        void queryClient.invalidateQueries({ queryKey: ['computer-status'] });
        void queryClient.invalidateQueries({ queryKey: ['library'] });
        void queryClient.invalidateQueries({ queryKey: ['page'] });
        void queryClient.invalidateQueries({ queryKey: ['routines'] });
        break;
      }

      case 'message.reaction': {
        const msgObj = payload.message as Message | undefined;
        const targetThreadId = threadId || msgObj?.thread_id || '';
        const msgId = String(payload.message_id || msgObj?.id || '');
        const reactions = (msgObj?.reactions ?? payload.reactions) as
          | Record<string, number>
          | undefined;
        if (targetThreadId && msgId && (msgObj || reactions)) {
          queryClient.setQueryData<ThreadMessagesResponse>(
            ['thread-messages', targetThreadId],
            (prev) => {
              if (!prev) return prev;
              return {
                ...prev,
                messages: prev.messages.map((m) => {
                  if (m.id !== msgId) return m;
                  if (msgObj) return msgObj;
                  return { ...m, reactions: reactions ?? m.reactions };
                }),
              };
            },
          );
        }
        if (targetThreadId) {
          void queryClient.invalidateQueries({
            queryKey: ['thread-messages', targetThreadId],
          });
        } else {
          void queryClient.invalidateQueries({ queryKey: ['thread-messages'] });
        }
        break;
      }

      case 'artifact.deleted': {
        const artObj = payload.artifact as
          | { id?: string; thread_id?: string | null }
          | undefined;
        const deletedId = String(payload.artifact_id || payload.id || artObj?.id || '');
        const targetThreadId = threadId || artObj?.thread_id || '';
        void queryClient.invalidateQueries({ queryKey: ['library'] });
        if (deletedId) {
          queryClient.removeQueries({ queryKey: ['page', deletedId] });
        }
        if (targetThreadId) {
          void queryClient.invalidateQueries({
            queryKey: ['thread-messages', targetThreadId],
          });
        } else {
          void queryClient.invalidateQueries({ queryKey: ['thread-messages'] });
        }
        if (deletedId && uiStore.activePageId === deletedId) {
          uiStore.setActivePageId(null);
          uiStore.pushToast({ tone: 'info', title: 'Page deleted' });
        }
        if (deletedId && uiStore.lightboxArtifact?.id === deletedId) {
          uiStore.setLightboxArtifact(null);
        }
        break;
      }

      default:
        break;
    }
  };

  const connect = () => {
    if (closed) return;
    const lastId = useChatStreamStore.getState().lastEventId;
    const base = lastId
      ? `/api/v1/events/stream?last_event_id=${encodeURIComponent(lastId)}`
      : '/api/v1/events/stream';
    const url = withAuthToken(base);

    try {
      es = new EventSource(url);
    } catch {
      scheduleReconnect();
      return;
    }

    es.onopen = () => {
      attempt = 0;
      useChatStreamStore.getState().setSseConnected(true);
    };

    const handleRaw = (ev: MessageEvent) => {
      try {
        const parsed = JSON.parse(ev.data) as ServerSseEnvelope;
        if (parsed && typeof parsed.type === 'string') {
          if (!parsed.id && ev.lastEventId) {
            useChatStreamStore.getState().setLastEventId(ev.lastEventId);
          }
          dispatchEnvelope(parsed);
        }
      } catch {
        // ignore keepalive comments or non-JSON frames
      }
    };

    es.onmessage = handleRaw;

    // Also listen to named SSE event types if the server sets `event: <type>`
    const namedTypes = [
      'bot.presence',
      'turn.started',
      'thinking.delta',
      'message.delta',
      'message.completed',
      'tool.call.updated',
      'hitl.approval.requested',
      'hitl.approval.resolved',
      'hitl.approval.expired',
      'hitl.draft.created',
      'hitl.draft.updated',
      'hitl.secure_form.requested',
      'hitl.secure_form.resolved',
      'computer.state',
      'artifact.page.updated',
      'artifact.deleted',
      'message.reaction',
      'routine.run.status',
      'handoff.dispatched',
      'stream.resync',
    ];
    for (const t of namedTypes) {
      es.addEventListener(t, handleRaw as EventListener);
    }

    es.onerror = () => {
      if (!closed) {
        reportClientError({
          kind: 'sse_error',
          message: `SSE stream disconnected or errored (attempt ${attempt + 1})`,
          url: '/api/v1/events/stream',
          extra: {
            attempt: attempt + 1,
            last_event_id: useChatStreamStore.getState().lastEventId,
          },
        });
      }
      useChatStreamStore.getState().setSseConnected(false);
      if (es) {
        es.close();
        es = null;
      }
      scheduleReconnect();
    };
  };

  const scheduleReconnect = () => {
    if (closed || reconnectTimer !== null) return;
    attempt += 1;
    const delayMs = Math.min(1000 * Math.pow(1.6, attempt - 1), 12000);
    reconnectTimer = window.setTimeout(() => {
      reconnectTimer = null;
      connect();
    }, delayMs);
  };

  connect();

  return () => {
    closed = true;
    useChatStreamStore.getState().setSseConnected(false);
    if (reconnectTimer !== null) {
      window.clearTimeout(reconnectTimer);
      reconnectTimer = null;
    }
    if (es) {
      es.close();
      es = null;
    }
  };
}
