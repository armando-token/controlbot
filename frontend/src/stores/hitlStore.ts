import { create } from 'zustand';
import type { ApprovalCard, DraftCard, SecureFormCard } from '../lib/types';

interface HitlState {
  approvalsByThread: Record<string, ApprovalCard[]>;
  draftsByThread: Record<string, DraftCard[]>;
  secureFormsByThread: Record<string, SecureFormCard[]>;
  sseUpdatedAtById: Record<string, number>;

  seedThread: (
    threadId: string,
    approvals: ApprovalCard[],
    drafts: DraftCard[],
    secureForms: SecureFormCard[],
    opts?: { fetchStartedAt?: number },
  ) => void;
  markResync: () => void;
  upsertApproval: (card: ApprovalCard) => void;
  upsertDraft: (card: DraftCard) => void;
  upsertSecureForm: (card: SecureFormCard) => void;
}

function upsertList<T extends { id: string }>(list: T[] | undefined, item: T): T[] {
  const prev = list ?? [];
  const idx = prev.findIndex((x) => x.id === item.id);
  if (idx === -1) return [...prev, item];
  const copy = prev.slice();
  copy[idx] = item;
  return copy;
}

function reconcileSeededList<
  T extends { id: string; status: string; resolved_at?: string | null },
>(
  existingList: T[] | undefined,
  incomingList: T[],
  sseUpdatedAtById: Record<string, number>,
  fetchStartedAt?: number,
): T[] {
  const existingMap = new Map<string, T>();
  for (const item of existingList ?? []) {
    existingMap.set(item.id, item);
  }
  const byId = new Map<string, T>();
  const now = Date.now();
  for (const inc of incomingList) {
    const ext = existingMap.get(inc.id);
    if (!ext) {
      byId.set(inc.id, inc);
      continue;
    }
    if (ext.status !== 'pending' && inc.status === 'pending') {
      byId.set(inc.id, ext);
      continue;
    }
    if (ext.status === 'pending' && inc.status !== 'pending') {
      byId.set(inc.id, inc);
      continue;
    }
    const touchedAt = sseUpdatedAtById[inc.id] ?? 0;
    const isFreshSse =
      fetchStartedAt !== undefined
        ? touchedAt >= fetchStartedAt
        : touchedAt > 0 && now - touchedAt < 5000;
    byId.set(inc.id, isFreshSse ? ext : inc);
  }
  for (const ext of existingList ?? []) {
    if (!byId.has(ext.id)) {
      byId.set(ext.id, ext);
    }
  }
  return Array.from(byId.values());
}

export const useHitlStore = create<HitlState>((set) => ({
  approvalsByThread: {},
  draftsByThread: {},
  secureFormsByThread: {},
  sseUpdatedAtById: {},

  seedThread: (threadId, approvals, drafts, secureForms, opts) =>
    set((s) => ({
      approvalsByThread: {
        ...s.approvalsByThread,
        [threadId]: reconcileSeededList(
          s.approvalsByThread[threadId],
          approvals,
          s.sseUpdatedAtById,
          opts?.fetchStartedAt,
        ),
      },
      draftsByThread: {
        ...s.draftsByThread,
        [threadId]: reconcileSeededList(
          s.draftsByThread[threadId],
          drafts,
          s.sseUpdatedAtById,
          opts?.fetchStartedAt,
        ),
      },
      secureFormsByThread: {
        ...s.secureFormsByThread,
        [threadId]: reconcileSeededList(
          s.secureFormsByThread[threadId],
          secureForms,
          s.sseUpdatedAtById,
          opts?.fetchStartedAt,
        ),
      },
    })),

  markResync: () =>
    set((s) => {
      const nextSse = { ...s.sseUpdatedAtById };
      const clearPending = <T extends { id: string; status: string }>(
        map: Record<string, T[]>,
      ) => {
        for (const list of Object.values(map)) {
          for (const card of list) {
            if (card.status === 'pending') {
              delete nextSse[card.id];
            }
          }
        }
      };
      clearPending(s.approvalsByThread);
      clearPending(s.draftsByThread);
      clearPending(s.secureFormsByThread);
      return { sseUpdatedAtById: nextSse };
    }),

  upsertApproval: (card) =>
    set((s) => ({
      approvalsByThread: {
        ...s.approvalsByThread,
        [card.thread_id]: upsertList(s.approvalsByThread[card.thread_id], card),
      },
      sseUpdatedAtById: {
        ...s.sseUpdatedAtById,
        [card.id]: Date.now(),
      },
    })),

  upsertDraft: (card) =>
    set((s) => ({
      draftsByThread: {
        ...s.draftsByThread,
        [card.thread_id]: upsertList(s.draftsByThread[card.thread_id], card),
      },
      sseUpdatedAtById: {
        ...s.sseUpdatedAtById,
        [card.id]: Date.now(),
      },
    })),

  upsertSecureForm: (card) =>
    set((s) => ({
      secureFormsByThread: {
        ...s.secureFormsByThread,
        [card.thread_id]: upsertList(s.secureFormsByThread[card.thread_id], card),
      },
      sseUpdatedAtById: {
        ...s.sseUpdatedAtById,
        [card.id]: Date.now(),
      },
    })),
}));
