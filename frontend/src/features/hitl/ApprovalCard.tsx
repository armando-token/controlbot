import React, { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle,
  Check,
  Clock,
  Monitor,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Terminal,
  X,
} from 'lucide-react';
import { ApiError, computerApi, hitlApi } from '../../lib/api';
import type { ApprovalCard as ApprovalCardType, ApprovalDecision } from '../../lib/types';
import { useComputerStore } from '../../stores/computerStore';
import { useHitlStore } from '../../stores/hitlStore';
import { useUiStore } from '../../stores/uiStore';

interface ApprovalCardProps {
  card: ApprovalCardType;
  isGroupChannel: boolean;
}

export const ApprovalCard: React.FC<ApprovalCardProps> = ({ card, isGroupChannel }) => {
  const queryClient = useQueryClient();
  const upsertApproval = useHitlStore((s) => s.upsertApproval);
  const openSettings = useUiStore((s) => s.openSettings);
  const setFullscreenComputerVmId = useUiStore((s) => s.setFullscreenComputerVmId);
  const setComputerStatus = useComputerStore((s) => s.setStatus);
  const pushToast = useUiStore((s) => s.pushToast);

  const [pendingAction, setPendingAction] = useState<string | null>(null);

  const resolveMutation = useMutation({
    mutationFn: (decision: ApprovalDecision) => {
      setPendingAction(decision);
      return hitlApi.resolveApproval(card.id, decision);
    },
    onSuccess: (updated) => {
      upsertApproval(updated);
      void queryClient.invalidateQueries({ queryKey: ['thread-messages', card.thread_id] });
      void queryClient.invalidateQueries({ queryKey: ['roster'] });
      if (updated.status === 'allowed_always') {
        pushToast({ tone: 'success', title: 'Saved to Custom Rules' });
      }
    },
    onError: (err: Error) => {
      if (err instanceof ApiError && err.status === 409) {
        pushToast({
          tone: 'info',
          title: 'Already resolved',
          description: 'This approval card was already handled.',
        });
        void queryClient.invalidateQueries({ queryKey: ['thread-messages', card.thread_id] });
      } else {
        pushToast({ tone: 'error', title: 'Approval failed', description: err.message });
      }
    },
    onSettled: () => setPendingAction(null),
  });

  const takeoverMutation = useMutation({
    mutationFn: async () => {
      const status = await computerApi.takeover('default', card.title);
      setComputerStatus(status);
      return status;
    },
    onSuccess: () => {
      setFullscreenComputerVmId('default');
      pushToast({ tone: 'warn', title: "You're in control", description: 'Click I\'m done when finished.' });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not start takeover', description: err.message });
    },
  });

  const isPending = card.status === 'pending';
  const isExpired = card.status === 'expired';
  const showAlwaysAllow = !isGroupChannel && card.allow_always_allowed && card.kind !== 'terminal';

  const statusBadge = () => {
    switch (card.status) {
      case 'allowed_once':
        return (
          <span
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11.5px] font-medium"
            style={{ backgroundColor: 'var(--status-ok-bg)', color: 'var(--status-ok)' }}
          >
            <Check size={12} strokeWidth={2.2} />
            Allowed once
          </span>
        );
      case 'allowed_always':
        return (
          <span
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11.5px] font-medium"
            style={{ backgroundColor: 'var(--status-ok-bg)', color: 'var(--status-ok)' }}
          >
            <ShieldCheck size={12} strokeWidth={2} />
            Saved to Custom Rules
          </span>
        );
      case 'denied':
        return (
          <span
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11.5px] font-medium"
            style={{ backgroundColor: 'var(--status-danger-bg)', color: 'var(--status-danger)' }}
          >
            <X size={12} strokeWidth={2.2} />
            Denied
          </span>
        );
      case 'skipped':
        return (
          <span
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11.5px] font-medium"
            style={{ backgroundColor: 'var(--bg-subtle)', color: 'var(--text-secondary)' }}
          >
            Skipped
          </span>
        );
      case 'expired':
        return (
          <span
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11.5px] font-medium"
            style={{ backgroundColor: 'var(--status-warn-bg)', color: 'var(--status-warn)' }}
          >
            <Clock size={12} strokeWidth={2} />
            Expired
          </span>
        );
      default:
        return (
          <span
            className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11.5px] font-medium"
            style={{ backgroundColor: 'var(--status-warn-bg)', color: 'var(--status-warn)' }}
          >
            Needs approval
          </span>
        );
    }
  };

  const icon =
    card.kind === 'terminal' ? (
      <Terminal size={15} strokeWidth={1.75} />
    ) : card.kind === 'takeover' ? (
      <Monitor size={15} strokeWidth={1.75} />
    ) : card.kind === 'reconnect' ? (
      <RefreshCw size={15} strokeWidth={1.75} />
    ) : (
      <ShieldAlert size={15} strokeWidth={1.75} />
    );

  const argEntries = Object.entries(card.arguments || {});
  const allowLabel =
    card.kind === 'terminal' || card.kind === 'ask_first' ? 'Allow' : 'Allow once';
  const denyLabel =
    card.kind === 'terminal' ? 'Skip' : card.kind === 'ask_first' ? 'Not now' : 'Deny';
  const ruleLabel = card.kind === 'ask_first' ? 'Edit rule' : 'Manage rules';

  return (
    <div
      className="my-2.5 rounded-xl overflow-hidden transition-colors"
      style={{
        backgroundColor: 'var(--bg-canvas)',
        border: isPending
          ? '1px solid var(--border-strong)'
          : '1px solid var(--border-subtle)',
        boxShadow: isPending ? 'var(--shadow-sm)' : 'none',
      }}
    >
      {/* Risk Banner */}
      {card.risk_banner && isPending && (
        <div
          className="flex items-center gap-2 px-3.5 py-2 text-[12px] font-medium"
          style={{
            backgroundColor: 'var(--status-warn-bg)',
            color: 'var(--status-warn)',
            borderBottom: '1px solid rgba(180, 83, 9, 0.14)',
          }}
        >
          <AlertTriangle size={14} strokeWidth={1.9} className="shrink-0" />
          <span>{card.risk_banner}</span>
        </div>
      )}

      <div className="p-3.5 space-y-2.5">
        <div className="flex items-start justify-between gap-3">
          <div className="flex items-start gap-2.5 min-w-0">
            <span
              className="mt-0.5 p-1.5 rounded-lg shrink-0"
              style={{
                backgroundColor:
                  card.kind === 'takeover'
                    ? 'var(--accent-takeover-tint)'
                    : 'var(--bg-subtle)',
                color:
                  card.kind === 'takeover'
                    ? 'var(--accent-takeover)'
                    : 'var(--text-secondary)',
              }}
            >
              {icon}
            </span>
            <div className="min-w-0">
              <div
                className="text-[13.5px] font-medium leading-snug"
                style={{ color: 'var(--text-primary)' }}
              >
                {card.title}
              </div>
              {card.target && (
                <div
                  className="text-[12px] font-mono mt-0.5 truncate"
                  style={{ color: 'var(--text-muted)' }}
                >
                  {card.target}
                </div>
              )}
              {isGroupChannel && card.waiting_for_user && isPending && (
                <div className="text-[12px] mt-1" style={{ color: 'var(--status-warn)' }}>
                  Waiting for {card.waiting_for_user}
                </div>
              )}
            </div>
          </div>
          <div className="shrink-0">{statusBadge()}</div>
        </div>

        {/* Arguments / Command */}
        {argEntries.length > 0 && (
          <div
            className="rounded-lg p-2.5 text-[12px] font-mono overflow-x-auto"
            style={{
              backgroundColor:
                card.kind === 'terminal' ? 'var(--bg-terminal)' : 'var(--bg-sidebar)',
              color: card.kind === 'terminal' ? '#E5E7EB' : 'var(--text-primary)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            {card.kind === 'terminal' && typeof card.arguments.command === 'string' ? (
              <code>$ {card.arguments.command}</code>
            ) : (
              <div className="space-y-1">
                {argEntries.map(([k, v]) => (
                  <div key={k} className="flex items-start gap-2">
                    <span style={{ color: 'var(--text-muted)' }}>{k}:</span>
                    <span className="break-all">
                      {typeof v === 'string' ? v : JSON.stringify(v)}
                    </span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Action Row */}
        {isPending && (
          <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
            <div className="flex flex-wrap items-center gap-2">
              {card.kind === 'takeover' ? (
                <>
                  <button
                    type="button"
                    aria-label="Take over"
                    disabled={takeoverMutation.isPending}
                    onClick={() => takeoverMutation.mutate()}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12.5px] font-medium text-white transition-opacity disabled:opacity-50"
                    style={{ backgroundColor: 'var(--accent-takeover)' }}
                  >
                    <Monitor size={14} strokeWidth={1.9} />
                    {takeoverMutation.isPending ? 'Opening…' : 'Take over'}
                  </button>
                  <button
                    type="button"
                    disabled={resolveMutation.isPending}
                    onClick={() => resolveMutation.mutate('allow_once')}
                    className="px-3 py-1.5 rounded-lg text-[12.5px] font-medium hover:bg-[var(--bg-subtle)]"
                    style={{
                      border: '1px solid var(--border-strong)',
                      color: 'var(--text-primary)',
                    }}
                  >
                    Mark done
                  </button>
                  <button
                    type="button"
                    disabled={resolveMutation.isPending}
                    onClick={() => resolveMutation.mutate('deny')}
                    className="px-2.5 py-1.5 rounded-lg text-[12.5px] hover:bg-[var(--bg-subtle)]"
                    style={{ color: 'var(--text-secondary)' }}
                  >
                    Cancel
                  </button>
                </>
              ) : card.kind === 'reconnect' ? (
                <>
                  <button
                    type="button"
                    aria-label="Connect"
                    disabled={resolveMutation.isPending}
                    onClick={() => resolveMutation.mutate('allow_once')}
                    className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12.5px] font-medium transition-opacity disabled:opacity-50"
                    style={{
                      backgroundColor: 'var(--accent-primary)',
                      color: 'var(--bg-canvas)',
                    }}
                  >
                    <RefreshCw size={13} strokeWidth={2} />
                    {pendingAction === 'allow_once' ? 'Connecting…' : 'Connect'}
                  </button>
                  <button
                    type="button"
                    disabled={resolveMutation.isPending}
                    onClick={() => resolveMutation.mutate('skip')}
                    className="px-2.5 py-1.5 rounded-lg text-[12.5px] hover:bg-[var(--bg-subtle)]"
                    style={{ color: 'var(--text-secondary)' }}
                  >
                    Skip
                  </button>
                </>
              ) : (
                <>
                  <button
                    type="button"
                    aria-label={`${allowLabel}`}
                    disabled={resolveMutation.isPending}
                    onClick={() => resolveMutation.mutate('allow_once')}
                    className="px-3 py-1.5 rounded-lg text-[12.5px] font-medium transition-opacity disabled:opacity-50"
                    style={{
                      backgroundColor: 'var(--accent-primary)',
                      color: 'var(--bg-canvas)',
                    }}
                  >
                    {pendingAction === 'allow_once'
                      ? 'Allowing…'
                      : card.kind === 'terminal' || card.kind === 'ask_first'
                        ? 'Allow'
                        : 'Allow once'}
                  </button>

                  {showAlwaysAllow && (
                    <button
                      type="button"
                      aria-label="Always allow"
                      disabled={resolveMutation.isPending}
                      onClick={() => resolveMutation.mutate('always_allow')}
                      className="px-3 py-1.5 rounded-lg text-[12.5px] font-medium transition-colors hover:bg-[var(--bg-subtle)] disabled:opacity-50"
                      style={{
                        border: '1px solid var(--border-strong)',
                        color: 'var(--text-primary)',
                      }}
                    >
                      {pendingAction === 'always_allow' ? 'Saving…' : 'Always allow'}
                    </button>
                  )}

                  <button
                    type="button"
                    aria-label={`${denyLabel}`}
                    disabled={resolveMutation.isPending}
                    onClick={() =>
                      resolveMutation.mutate(card.kind === 'terminal' ? 'skip' : 'deny')
                    }
                    className="px-2.5 py-1.5 rounded-lg text-[12.5px] hover:bg-[var(--bg-subtle)] disabled:opacity-50"
                    style={{ color: 'var(--text-secondary)' }}
                  >
                    {card.kind === 'terminal'
                      ? 'Skip'
                      : card.kind === 'ask_first'
                        ? 'Not now'
                        : 'Deny'}
                  </button>
                </>
              )}
            </div>

            <button
              type="button"
              aria-label={`${ruleLabel}`}
              onClick={() => openSettings('general')}
              className="text-[12px] hover:underline"
              style={{ color: 'var(--text-muted)' }}
            >
              {card.kind === 'ask_first' ? 'Edit rule' : 'Manage rules'}
            </button>
          </div>
        )}

        {/* Expired retroactive action */}
        {isExpired && !isGroupChannel && (
          <div className="flex items-center justify-between pt-1">
            <span className="text-[12px]" style={{ color: 'var(--text-muted)' }}>
              Timed out waiting for approval.
            </span>
            <button
              type="button"
              disabled={resolveMutation.isPending}
              onClick={() => resolveMutation.mutate('always_allow')}
              className="px-3 py-1.5 rounded-lg text-[12px] font-medium hover:bg-[var(--bg-subtle)]"
              style={{
                border: '1px solid var(--border-strong)',
                color: 'var(--text-primary)',
              }}
            >
              Always allow next time
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
