import React, { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  Check,
  CheckCircle2,
  Copy,
  Loader2,
  Pencil,
  Play,
  RefreshCw,
  Webhook,
  XCircle,
} from 'lucide-react';
import { Modal } from '../../components/Modal';
import { routinesApi } from '../../lib/api';
import { copyToClipboard, formatRelativeTime } from '../../lib/markdown';
import type { Routine } from '../../lib/types';
import { useUiStore } from '../../stores/uiStore';

interface CreateRoutineModalProps {
  open: boolean;
  onClose: () => void;
  botId: string;
  defaultTimezone: string;
}

export const CreateRoutineModal: React.FC<CreateRoutineModalProps> = ({
  open,
  onClose,
  botId,
  defaultTimezone,
}) => {
  const queryClient = useQueryClient();
  const pushToast = useUiStore((s) => s.pushToast);

  const [name, setName] = useState('');
  const [instruction, setInstruction] = useState('');
  const [scheduleType, setScheduleType] = useState<'cron' | 'webhook' | 'manual'>('cron');
  const [cronExpr, setCronExpr] = useState('0 9 * * 1-5');
  const [timezone, setTimezone] = useState(defaultTimezone || 'UTC');
  const [visibility, setVisibility] = useState<'only_me' | 'team'>('only_me');

  useEffect(() => {
    if (open) {
      setTimezone(defaultTimezone || 'UTC');
    }
  }, [open, defaultTimezone]);

  const createMutation = useMutation({
    mutationFn: () =>
      routinesApi.create(botId, {
        name: name.trim(),
        instruction: instruction.trim(),
        schedule_type: scheduleType,
        cron_expr: scheduleType === 'cron' ? cronExpr.trim() : null,
        timezone,
        visibility,
      }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['routines', botId] });
      setName('');
      setInstruction('');
      setVisibility('only_me');
      onClose();
      pushToast({ tone: 'success', title: 'Routine created' });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not create routine', description: err.message });
    },
  });

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="New routine"
      subtitle="Run recurring schedules, webhook triggers, or manual playbooks."
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (name.trim() && instruction.trim()) createMutation.mutate();
        }}
        className="p-5 space-y-4"
      >
        <div>
          <label className="block text-[12px] font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
            Name
          </label>
          <input
            type="text"
            required
            autoFocus
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Morning operations brief"
            className="w-full px-3 py-2 rounded-lg text-[13.5px] outline-none"
            style={{
              backgroundColor: 'var(--bg-canvas)',
              border: '1px solid var(--border-strong)',
            }}
          />
        </div>

        <div>
          <label className="block text-[12px] font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
            Instruction
          </label>
          <textarea
            rows={4}
            required
            value={instruction}
            onChange={(e) => setInstruction(e.target.value)}
            placeholder="What should the bot check, produce, or report?"
            className="w-full px-3 py-2 rounded-lg text-[13px] outline-none resize-y"
            style={{
              backgroundColor: 'var(--bg-canvas)',
              border: '1px solid var(--border-strong)',
            }}
          />
        </div>

        <div>
          <div className="text-[12px] font-medium mb-1.5" style={{ color: 'var(--text-secondary)' }}>
            Trigger type
          </div>
          <div className="grid grid-cols-3 gap-2">
            {(
              [
                { id: 'cron', label: 'Scheduled (Cron)' },
                { id: 'webhook', label: 'Webhook' },
                { id: 'manual', label: 'Manual' },
              ] as const
            ).map((opt) => (
              <button
                key={opt.id}
                type="button"
                aria-label={`${opt.label}`}
                onClick={() => setScheduleType(opt.id)}
                className="px-2.5 py-2 rounded-xl text-[12.5px] font-medium"
                style={{
                  backgroundColor: scheduleType === opt.id ? 'var(--bg-active)' : 'var(--bg-sidebar)',
                  border:
                    scheduleType === opt.id
                      ? '1px solid var(--border-strong)'
                      : '1px solid var(--border-subtle)',
                }}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </div>

        {scheduleType === 'cron' && (
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-[12px] font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
                Cron expression
              </label>
              <input
                type="text"
                value={cronExpr}
                onChange={(e) => setCronExpr(e.target.value)}
                placeholder="0 9 * * *"
                className="w-full px-3 py-2 rounded-lg text-[13px] font-mono outline-none"
                style={{
                  backgroundColor: 'var(--bg-canvas)',
                  border: '1px solid var(--border-strong)',
                }}
              />
            </div>
            <div>
              <label
                htmlFor="create-routine-timezone"
                className="block text-[12px] font-medium mb-1"
                style={{ color: 'var(--text-secondary)' }}
              >
                Timezone
              </label>
              <input
                id="create-routine-timezone"
                type="text"
                aria-label="Timezone"
                value={timezone}
                onChange={(e) => setTimezone(e.target.value)}
                className="w-full px-3 py-2 rounded-lg text-[13px] outline-none"
                style={{
                  backgroundColor: 'var(--bg-canvas)',
                  border: '1px solid var(--border-strong)',
                }}
              />
            </div>
          </div>
        )}

        <div>
          <label
            htmlFor="create-routine-visibility"
            className="block text-[12px] font-medium mb-1"
            style={{ color: 'var(--text-secondary)' }}
          >
            Visibility
          </label>
          <select
            id="create-routine-visibility"
            aria-label="Routine visibility"
            value={visibility}
            onChange={(e) => setVisibility(e.target.value as 'only_me' | 'team')}
            className="w-full px-3 py-2 rounded-lg text-[13px] outline-none"
            style={{
              backgroundColor: 'var(--bg-canvas)',
              border: '1px solid var(--border-strong)',
            }}
          >
            <option value="only_me">Only me</option>
            <option value="team">Team</option>
          </select>
        </div>

        <div
          className="flex items-center justify-end gap-2 pt-3"
          style={{ borderTop: '1px solid var(--border-subtle)' }}
        >
          <button
            type="button"
            onClick={onClose}
            className="px-3.5 py-2 rounded-lg text-[13px] hover:bg-[var(--bg-subtle)]"
            style={{ color: 'var(--text-secondary)' }}
          >
            Cancel
          </button>
          <button
            type="submit"
            aria-label="Create routine"
            disabled={!name.trim() || !instruction.trim() || createMutation.isPending}
            className="px-4 py-2 rounded-lg text-[13px] font-medium disabled:opacity-45"
            style={{
              backgroundColor: 'var(--accent-primary)',
              color: 'var(--bg-canvas)',
            }}
          >
            {createMutation.isPending ? 'Creating…' : 'Create routine'}
          </button>
        </div>
      </form>
    </Modal>
  );
};

interface RoutineDetailModalProps {
  routine: Routine | null;
  initialEditing?: boolean;
  onClose: () => void;
}

export const RoutineDetailModal: React.FC<RoutineDetailModalProps> = ({
  routine,
  initialEditing = false,
  onClose,
}) => {
  const queryClient = useQueryClient();
  const pushToast = useUiStore((s) => s.pushToast);
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const [editing, setEditing] = useState(false);
  const [nameDraft, setNameDraft] = useState('');
  const [instructionDraft, setInstructionDraft] = useState('');
  const [scheduleTypeDraft, setScheduleTypeDraft] = useState<'cron' | 'webhook' | 'manual'>('cron');
  const [cronDraft, setCronDraft] = useState('');
  const [timezoneDraft, setTimezoneDraft] = useState('UTC');
  const [visibilityDraft, setVisibilityDraft] = useState<'only_me' | 'team'>('only_me');
  const [enabledDraft, setEnabledDraft] = useState(true);

  useEffect(() => {
    if (!routine) {
      setEditing(false);
      return;
    }
    setEditing(Boolean(initialEditing));
    setNameDraft(routine.name);
    setInstructionDraft(routine.instruction);
    setScheduleTypeDraft(routine.schedule_type);
    setCronDraft(routine.cron_expr || '0 9 * * 1-5');
    setTimezoneDraft(routine.timezone || 'UTC');
    setVisibilityDraft(routine.visibility || 'only_me');
    setEnabledDraft(routine.enabled);
  }, [routine?.id, initialEditing]);

  const startEdit = () => {
    if (!routine) return;
    setNameDraft(routine.name);
    setInstructionDraft(routine.instruction);
    setScheduleTypeDraft(routine.schedule_type);
    setCronDraft(routine.cron_expr || '0 9 * * 1-5');
    setTimezoneDraft(routine.timezone || 'UTC');
    setVisibilityDraft(routine.visibility || 'only_me');
    setEnabledDraft(routine.enabled);
    setEditing(true);
  };

  const runsQuery = useQuery({
    queryKey: ['routine-runs', routine?.id],
    queryFn: () => routinesApi.runs(routine!.id),
    enabled: Boolean(routine),
  });

  const testMutation = useMutation({
    mutationFn: () => routinesApi.test(routine!.id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['routine-runs', routine?.id] });
      void queryClient.invalidateQueries({ queryKey: ['routines', routine?.bot_id] });
      pushToast({ tone: 'success', title: 'Test run started' });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not run routine', description: err.message });
    },
  });

  const updateMutation = useMutation({
    mutationFn: (patch: Partial<Routine> & { regenerate_webhook_key?: boolean }) =>
      routinesApi.update(routine!.id, patch),
    onSuccess: (_updated, vars) => {
      void queryClient.invalidateQueries({ queryKey: ['routines', routine?.bot_id] });
      if (vars.regenerate_webhook_key) {
        pushToast({ tone: 'success', title: 'Webhook key regenerated' });
      } else {
        setEditing(false);
        pushToast({ tone: 'success', title: 'Routine updated' });
      }
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not update routine', description: err.message });
    },
  });

  if (!routine) return null;

  const fullWebhookUrl = `${window.location.origin}${routine.webhook_url}`;
  const authHeader = `Authorization: Bearer ${routine.webhook_key}`;

  const copyBox = async (key: string, value: string) => {
    const ok = await copyToClipboard(value);
    if (ok) {
      setCopiedKey(key);
      window.setTimeout(() => setCopiedKey(null), 1500);
    }
  };

  const scheduleSummary =
    routine.schedule_type === 'cron'
      ? `Schedule: ${routine.cron_expr || 'Custom'} (${routine.timezone})`
      : routine.schedule_type === 'manual'
        ? 'Manual trigger routine'
        : 'Event-triggered webhook routine';

  return (
    <Modal
      open={Boolean(routine)}
      onClose={onClose}
      title={editing ? `Edit ${routine.name}` : routine.name}
      subtitle={scheduleSummary}
      maxWidthClass="max-w-xl"
    >
      <div className="p-5 space-y-5">
        {editing ? (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (!nameDraft.trim() || !instructionDraft.trim()) return;
              updateMutation.mutate({
                name: nameDraft.trim(),
                instruction: instructionDraft.trim(),
                schedule_type: scheduleTypeDraft,
                cron_expr: scheduleTypeDraft === 'cron' ? cronDraft.trim() : null,
                timezone: timezoneDraft.trim() || 'UTC',
                visibility: visibilityDraft,
                enabled: enabledDraft,
              });
            }}
            className="space-y-4"
          >
            <div>
              <label className="block text-[12px] font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
                Name
              </label>
              <input
                type="text"
                required
                aria-label="Edit routine name"
                value={nameDraft}
                onChange={(e) => setNameDraft(e.target.value)}
                className="w-full px-3 py-2 rounded-lg text-[13.5px] outline-none bg-[var(--bg-canvas)] border border-[var(--border-strong)]"
              />
            </div>

            <div>
              <label className="block text-[12px] font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
                Instruction
              </label>
              <textarea
                rows={4}
                required
                aria-label="Edit routine instruction"
                value={instructionDraft}
                onChange={(e) => setInstructionDraft(e.target.value)}
                className="w-full px-3 py-2 rounded-lg text-[13px] outline-none resize-y bg-[var(--bg-canvas)] border border-[var(--border-strong)]"
              />
            </div>

            <div className="grid grid-cols-3 gap-2">
              {(
                [
                  { id: 'cron', label: 'Scheduled (Cron)' },
                  { id: 'webhook', label: 'Webhook' },
                  { id: 'manual', label: 'Manual' },
                ] as const
              ).map((opt) => (
                <button
                  key={opt.id}
                  type="button"
                  aria-label={`${opt.label}`}
                  onClick={() => setScheduleTypeDraft(opt.id)}
                  className="px-2.5 py-2 rounded-xl text-[12.5px] font-medium"
                  style={{
                    backgroundColor:
                      scheduleTypeDraft === opt.id ? 'var(--bg-active)' : 'var(--bg-sidebar)',
                    border:
                      scheduleTypeDraft === opt.id
                        ? '1px solid var(--border-strong)'
                        : '1px solid var(--border-subtle)',
                  }}
                >
                  {opt.label}
                </button>
              ))}
            </div>

            {scheduleTypeDraft === 'cron' && (
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-[12px] font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
                    Cron expression
                  </label>
                  <input
                    type="text"
                    aria-label="Edit cron expression"
                    value={cronDraft}
                    onChange={(e) => setCronDraft(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg text-[13px] font-mono outline-none bg-[var(--bg-canvas)] border border-[var(--border-strong)]"
                  />
                </div>
                <div>
                  <label className="block text-[12px] font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
                    Timezone
                  </label>
                  <input
                    type="text"
                    aria-label="Edit routine timezone"
                    value={timezoneDraft}
                    onChange={(e) => setTimezoneDraft(e.target.value)}
                    className="w-full px-3 py-2 rounded-lg text-[13px] outline-none bg-[var(--bg-canvas)] border border-[var(--border-strong)]"
                  />
                </div>
              </div>
            )}

            <div className="grid grid-cols-2 gap-3 items-center">
              <div>
                <label className="block text-[12px] font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
                  Visibility
                </label>
                <select
                  aria-label="Edit routine visibility"
                  value={visibilityDraft}
                  onChange={(e) => setVisibilityDraft(e.target.value as 'only_me' | 'team')}
                  className="w-full px-3 py-2 rounded-lg text-[13px] outline-none bg-[var(--bg-canvas)] border border-[var(--border-strong)]"
                >
                  <option value="only_me">Only me</option>
                  <option value="team">Team</option>
                </select>
              </div>
              <label className="flex items-center gap-2 text-[13px] pt-5 cursor-pointer">
                <input
                  type="checkbox"
                  aria-label="Enabled"
                  checked={enabledDraft}
                  onChange={(e) => setEnabledDraft(e.target.checked)}
                />
                <span>Enabled</span>
              </label>
            </div>

            <div
              className="flex items-center justify-end gap-2 pt-3"
              style={{ borderTop: '1px solid var(--border-subtle)' }}
            >
              <button
                type="button"
                onClick={() => setEditing(false)}
                className="px-3.5 py-2 rounded-lg text-[13px] hover:bg-[var(--bg-subtle)]"
                style={{ color: 'var(--text-secondary)' }}
              >
                Cancel
              </button>
              <button
                type="submit"
                aria-label="Save changes"
                disabled={!nameDraft.trim() || !instructionDraft.trim() || updateMutation.isPending}
                className="px-4 py-2 rounded-lg text-[13px] font-medium disabled:opacity-45"
                style={{
                  backgroundColor: 'var(--accent-primary)',
                  color: 'var(--bg-canvas)',
                }}
              >
                {updateMutation.isPending ? 'Saving…' : 'Save changes'}
              </button>
            </div>
          </form>
        ) : (
          <>
            {/* Status, Visibility & Edit Trigger */}
            <div className="flex items-center justify-between gap-2">
              <div className="flex items-center gap-2 text-[11.5px]">
                <span
                  className="px-2 py-0.5 rounded-full font-medium"
                  style={{
                    backgroundColor: routine.enabled ? 'var(--status-ok-bg)' : 'var(--bg-subtle)',
                    color: routine.enabled ? 'var(--status-ok)' : 'var(--text-muted)',
                  }}
                >
                  {routine.enabled ? 'Active' : 'Paused'}
                </span>
                <span
                  className="px-2 py-0.5 rounded-full font-medium"
                  style={{
                    backgroundColor: 'var(--bg-subtle)',
                    color: 'var(--text-secondary)',
                  }}
                >
                  {routine.visibility === 'team' ? 'Team' : 'Only me'}
                </span>
              </div>
              <button
                type="button"
                onClick={startEdit}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[12px] font-medium hover:bg-[var(--bg-subtle)]"
                style={{
                  color: 'var(--text-primary)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <Pencil size={12} />
                Edit routine
              </button>
            </div>

            {/* Instruction */}
            <div>
              <div className="text-[12px] font-medium mb-1.5" style={{ color: 'var(--text-secondary)' }}>
                Instruction
              </div>
              <div
                className="p-3 rounded-xl text-[13px] whitespace-pre-wrap"
                style={{
                  backgroundColor: 'var(--bg-sidebar)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                {routine.instruction}
              </div>
            </div>

            {/* Click-to-copy Webhook Boxes */}
            <div className="space-y-2">
              <div className="flex items-center justify-between gap-2">
                <div className="flex items-center gap-1.5 text-[12px] font-medium" style={{ color: 'var(--text-secondary)' }}>
                  <Webhook size={13.5} />
                  <span>Webhook trigger (click any box to copy)</span>
                </div>
                <button
                  type="button"
                  onClick={() => updateMutation.mutate({ regenerate_webhook_key: true })}
                  disabled={updateMutation.isPending}
                  className="inline-flex items-center gap-1 px-2 py-1 rounded-lg text-[11.5px] font-medium hover:bg-[var(--bg-subtle)] disabled:opacity-50"
                  style={{ color: 'var(--text-secondary)' }}
                >
                  <RefreshCw size={11.5} className={updateMutation.isPending ? 'animate-spin' : ''} />
                  Regenerate key
                </button>
              </div>

              {[
                { id: 'url', label: 'POST to', value: fullWebhookUrl },
                { id: 'key', label: 'Key', value: routine.webhook_key },
                { id: 'hdr', label: 'Header', value: authHeader },
              ].map((box) => (
                <button
                  key={box.id}
                  type="button"
                  aria-label={`Copy ${box.label}`}
                  onClick={() => void copyBox(box.id, box.value)}
                  className="w-full flex items-center justify-between gap-2 px-3 py-2 rounded-xl text-left transition-colors hover:bg-[var(--bg-active)]"
                  style={{
                    backgroundColor: 'var(--bg-sidebar)',
                    border: '1px solid var(--border-subtle)',
                  }}
                >
                  <div className="min-w-0">
                    <div className="text-[10.5px] uppercase tracking-wider" style={{ color: 'var(--text-muted)' }}>
                      {box.label}
                    </div>
                    <div className="text-[12px] font-mono truncate" style={{ color: 'var(--text-primary)' }}>
                      {box.value}
                    </div>
                  </div>
                  <span className="shrink-0" style={{ color: 'var(--text-muted)' }}>
                    {copiedKey === box.id ? (
                      <Check size={14} style={{ color: 'var(--status-ok)' }} />
                    ) : (
                      <Copy size={14} />
                    )}
                  </span>
                </button>
              ))}
            </div>

            {/* 20-Run History */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[12px] font-medium" style={{ color: 'var(--text-secondary)' }}>
                  Recent runs (last 20)
                </span>
                <button
                  type="button"
                  aria-label="Test now"
                  onClick={() => testMutation.mutate()}
                  disabled={testMutation.isPending}
                  className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[12px] font-medium"
                  style={{
                    backgroundColor: 'var(--bg-subtle)',
                    color: 'var(--text-primary)',
                  }}
                >
                  <Play size={12} />
                  {testMutation.isPending ? 'Running…' : 'Test now'}
                </button>
              </div>

              <div className="space-y-1.5 max-h-56 overflow-y-auto">
                {(runsQuery.data?.runs ?? []).length === 0 ? (
                  <div
                    className="text-[12.5px] py-4 text-center rounded-xl"
                    style={{
                      backgroundColor: 'var(--bg-sidebar)',
                      color: 'var(--text-muted)',
                    }}
                  >
                    No runs recorded yet.
                  </div>
                ) : (
                  (runsQuery.data?.runs ?? []).map((run) => (
                    <div
                      key={run.id}
                      className="flex items-start justify-between gap-2 px-3 py-2 rounded-xl text-[12.5px]"
                      style={{
                        backgroundColor: 'var(--bg-sidebar)',
                        border: '1px solid var(--border-subtle)',
                      }}
                    >
                      <div className="flex items-start gap-2 min-w-0">
                        {run.status === 'running' ? (
                          <Loader2 size={14} className="animate-spin mt-0.5 shrink-0" style={{ color: 'var(--accent-computer)' }} />
                        ) : run.status === 'failed' ? (
                          <XCircle size={14} className="mt-0.5 shrink-0" style={{ color: 'var(--status-danger)' }} />
                        ) : (
                          <CheckCircle2 size={14} className="mt-0.5 shrink-0" style={{ color: 'var(--status-ok)' }} />
                        )}
                        <div className="min-w-0">
                          <div className="font-medium capitalize">
                            {run.status} · {run.trigger}
                          </div>
                          {(run.summary || run.error) && (
                            <div
                              className="text-[11.5px] truncate"
                              style={{
                                color: run.error ? 'var(--status-danger)' : 'var(--text-secondary)',
                              }}
                            >
                              {run.error || run.summary}
                            </div>
                          )}
                        </div>
                      </div>
                      <span className="text-[11px] shrink-0" style={{ color: 'var(--text-muted)' }}>
                        {formatRelativeTime(run.started_at)}
                      </span>
                    </div>
                  ))
                )}
              </div>
            </div>
          </>
        )}
      </div>
    </Modal>
  );
};
