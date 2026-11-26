import { create } from 'zustand';
import type { ToolCallItem } from '../lib/types';

export interface ActiveTurnDraft {
  turnId: string;
  messageId: string;
  senderBotId: string | null;
  senderName: string;
  modelId: string | null;
  engineId: string | null;
  status: 'streaming' | 'tool_running' | 'awaiting_hitl';
  rawText: string;
  thinkingText: string;
  thinkingSummary?: string;
  toolCalls: Record<string, ToolCallItem>;
  startedAt: number;
}

interface ChatStreamState {
  activeTurnByThread: Record<string, ActiveTurnDraft>;
  lastEventId: string | null;
  sseConnected: boolean;

  setSseConnected: (connected: boolean) => void;
  setLastEventId: (eventId: string) => void;
  startTurn: (
    threadId: string,
    info: {
      turnId: string;
      messageId: string;
      senderBotId?: string | null;
      senderName?: string;
      modelId?: string | null;
      engineId?: string | null;
    },
  ) => void;
  appendThinkingDelta: (
    threadId: string,
    messageId: string,
    textDelta: string,
    summary?: string,
  ) => void;
  appendMessageDelta: (threadId: string, messageId: string, textDelta: string) => void;
  upsertToolCall: (threadId: string, messageId: string, toolCall: ToolCallItem) => void;
  markAwaitingHitl: (threadId: string) => void;
  completeTurn: (threadId: string, messageId?: string, turnId?: string) => void;
  clearTurns: () => void;
}

export const useChatStreamStore = create<ChatStreamState>((set) => ({
  activeTurnByThread: {},
  lastEventId: null,
  sseConnected: false,

  setSseConnected: (sseConnected) => set({ sseConnected }),
  setLastEventId: (lastEventId) => set({ lastEventId }),

  startTurn: (threadId, info) =>
    set((s) => ({
      activeTurnByThread: {
        ...s.activeTurnByThread,
        [threadId]: {
          turnId: info.turnId,
          messageId: info.messageId || `pending_${info.turnId}`,
          senderBotId: info.senderBotId ?? null,
          senderName: info.senderName || 'Bot',
          modelId: info.modelId ?? null,
          engineId: info.engineId ?? null,
          status: 'streaming',
          rawText: '',
          thinkingText: '',
          toolCalls: {},
          startedAt: Date.now(),
        },
      },
    })),

  appendThinkingDelta: (threadId, messageId, textDelta, summary) =>
    set((s) => {
      const existing = s.activeTurnByThread[threadId];
      if (!existing) {
        const turnId = `trn_${Date.now()}`;
        return {
          activeTurnByThread: {
            ...s.activeTurnByThread,
            [threadId]: {
              turnId,
              messageId: messageId || `pending_${turnId}`,
              senderBotId: null,
              senderName: 'Bot',
              modelId: null,
              engineId: null,
              status: 'streaming',
              rawText: '',
              thinkingText: textDelta,
              thinkingSummary: summary || undefined,
              toolCalls: {},
              startedAt: Date.now(),
            },
          },
        };
      }
      const isPendingMsg = existing.messageId.startsWith('pending_');
      if (!isPendingMsg && messageId && existing.messageId && existing.messageId !== messageId) {
        return s;
      }
      return {
        activeTurnByThread: {
          ...s.activeTurnByThread,
          [threadId]: {
            ...existing,
            messageId: isPendingMsg && messageId ? messageId : existing.messageId,
            thinkingText: existing.thinkingText + textDelta,
            thinkingSummary: summary || existing.thinkingSummary,
          },
        },
      };
    }),

  appendMessageDelta: (threadId, messageId, textDelta) =>
    set((s) => {
      const existing = s.activeTurnByThread[threadId];
      if (!existing) {
        const turnId = `trn_${Date.now()}`;
        return {
          activeTurnByThread: {
            ...s.activeTurnByThread,
            [threadId]: {
              turnId,
              messageId: messageId || `pending_${turnId}`,
              senderBotId: null,
              senderName: 'Bot',
              modelId: null,
              engineId: null,
              status: 'streaming',
              rawText: textDelta,
              thinkingText: '',
              toolCalls: {},
              startedAt: Date.now(),
            },
          },
        };
      }
      const isPendingMsg = existing.messageId.startsWith('pending_');
      if (!isPendingMsg && messageId && existing.messageId && existing.messageId !== messageId) {
        return s;
      }
      return {
        activeTurnByThread: {
          ...s.activeTurnByThread,
          [threadId]: {
            ...existing,
            messageId: isPendingMsg && messageId ? messageId : existing.messageId,
            status: 'streaming',
            rawText: existing.rawText + textDelta,
          },
        },
      };
    }),

  upsertToolCall: (threadId, messageId, toolCall) =>
    set((s) => {
      const existing = s.activeTurnByThread[threadId];
      if (!existing) {
        const turnId = `trn_${Date.now()}`;
        return {
          activeTurnByThread: {
            ...s.activeTurnByThread,
            [threadId]: {
              turnId,
              messageId: messageId || `pending_${turnId}`,
              senderBotId: null,
              senderName: 'Bot',
              modelId: null,
              engineId: null,
              status: toolCall.status === 'running' ? 'tool_running' : 'streaming',
              rawText: '',
              thinkingText: '',
              toolCalls: {
                [toolCall.call_id]: toolCall,
              },
              startedAt: Date.now(),
            },
          },
        };
      }
      const isPendingMsg = existing.messageId.startsWith('pending_');
      if (!isPendingMsg && messageId && existing.messageId && existing.messageId !== messageId) {
        return s;
      }
      return {
        activeTurnByThread: {
          ...s.activeTurnByThread,
          [threadId]: {
            ...existing,
            messageId: isPendingMsg && messageId ? messageId : existing.messageId,
            status: toolCall.status === 'running' ? 'tool_running' : 'streaming',
            toolCalls: {
              ...existing.toolCalls,
              [toolCall.call_id]: toolCall,
            },
          },
        },
      };
    }),

  markAwaitingHitl: (threadId) =>
    set((s) => {
      const existing = s.activeTurnByThread[threadId];
      if (!existing) return s;
      return {
        activeTurnByThread: {
          ...s.activeTurnByThread,
          [threadId]: { ...existing, status: 'awaiting_hitl' },
        },
      };
    }),

  completeTurn: (threadId, messageId, turnId) =>
    set((s) => {
      const existing = s.activeTurnByThread[threadId];
      if (!existing) return s;
      if (turnId && existing.turnId && existing.turnId === turnId) {
        const next = { ...s.activeTurnByThread };
        delete next[threadId];
        return { activeTurnByThread: next };
      }
      if (messageId && existing.messageId && existing.messageId !== messageId) {
        return s;
      }
      const next = { ...s.activeTurnByThread };
      delete next[threadId];
      return { activeTurnByThread: next };
    }),

  clearTurns: () => set({ activeTurnByThread: {} }),
}));
