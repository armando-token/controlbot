import React, { useEffect, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  CheckCircle2,
  FolderOpen,
  Globe,
  GraduationCap,
  Hand,
  Maximize2,
  Monitor,
  Square,
  TerminalSquare,
} from 'lucide-react';
import { Modal } from '../../components/Modal';
import { computerApi } from '../../lib/api';
import type { Bot } from '../../lib/types';
import { useComputerStore } from '../../stores/computerStore';
import { useUiStore } from '../../stores/uiStore';
import { LiveVncCanvas } from './LiveVncCanvas';
import { TerminalTab } from './TerminalTab';
import { WorkspaceFilesTab } from './WorkspaceFilesTab';

interface ComputerTabProps {
  bot?: Bot | null;
  vmId?: string;
}

type SubTab = 'screen' | 'terminal' | 'files';

export const ComputerTab: React.FC<ComputerTabProps> = ({ bot, vmId = 'default' }) => {
  const queryClient = useQueryClient();
  const fullscreenComputerVmId = useUiStore((s) => s.fullscreenComputerVmId);
  const setFullscreenComputerVmId = useUiStore((s) => s.setFullscreenComputerVmId);
  const pushToast = useUiStore((s) => s.pushToast);

  const status = useComputerStore((s) => s.byVmId[vmId]);
  const statusLoaded = useComputerStore((s) => Boolean(s.loadedByVmId[vmId]));
  const setStatus = useComputerStore((s) => s.setStatus);
  const preferredSource = useComputerStore((s) => s.preferredSource);
  const hasExplicitSourceChoice = useComputerStore((s) => s.hasExplicitSourceChoice);
  const setPreferredSource = useComputerStore((s) => s.setPreferredSource);
  const teachSteps = useComputerStore((s) => s.teachSteps);
  const clearTeachSteps = useComputerStore((s) => s.clearTeachSteps);

  const [subTab, setSubTab] = useState<SubTab>('screen');
  const [teachModalOpen, setTeachModalOpen] = useState(false);
  const [teachName, setTeachName] = useState('');

  const statusQuery = useQuery({
    queryKey: ['computer-status', vmId],
    queryFn: () => computerApi.status(vmId),
    refetchInterval: 15_000,
  });

  useEffect(() => {
    if (statusQuery.data) {
      setStatus(statusQuery.data);
    }
  }, [statusQuery.data, setStatus]);

  const currentStatus = status ?? statusQuery.data;
  const isTakeover = currentStatus?.control_owner === 'human_takeover';
  const isTeaching = Boolean(currentStatus?.is_teaching_task);
  const effectiveSource: 'vnc' | 'screencast' =
    currentStatus && !currentStatus.vnc_available && !hasExplicitSourceChoice
      ? 'screencast'
      : preferredSource;
  const canMountCanvas = statusLoaded || statusQuery.isError;

  const takeoverMutation = useMutation({
    mutationFn: () => computerApi.takeover(vmId, 'user_preview_takeover'),
    onSuccess: (st) => {
      setStatus(st);
      void queryClient.invalidateQueries({ queryKey: ['computer-status', vmId] });
      setFullscreenComputerVmId(vmId);
      pushToast({
        tone: 'warn',
        title: "You're in control",
        description: "Agent automation is locked until you click I'm done.",
      });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not take control', description: err.message });
    },
  });

  const handbackMutation = useMutation({
    mutationFn: () => computerApi.handback(vmId),
    onSuccess: (st) => {
      setStatus(st);
      void queryClient.invalidateQueries({ queryKey: ['computer-status', vmId] });
      pushToast({ tone: 'success', title: 'Control returned to Bot' });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Handback failed', description: err.message });
    },
  });

  const teachStartMutation = useMutation({
    mutationFn: (name: string) =>
      computerApi.teachStart(vmId, { bot_id: bot?.id ?? null, name }),
    onSuccess: (st) => {
      clearTeachSteps();
      setStatus(st);
      setTeachModalOpen(false);
      setTeachName('');
      void queryClient.invalidateQueries({ queryKey: ['computer-status', vmId] });
      pushToast({
        tone: 'info',
        title: `${bot?.name || 'Bot'} is watching and learning`,
        description: 'Demonstrate the workflow, then click Stop & save skill.',
      });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not start teaching', description: err.message });
    },
  });

  const teachStopMutation = useMutation({
    mutationFn: () => computerApi.teachStop(vmId, { bot_id: bot?.id ?? null }),
    onSuccess: (res) => {
      setStatus(res.status);
      clearTeachSteps();
      void queryClient.invalidateQueries({ queryKey: ['computer-status', vmId] });
      void queryClient.invalidateQueries({ queryKey: ['skills'] });
      void queryClient.invalidateQueries({ queryKey: ['library'] });
      pushToast({
        tone: 'success',
        title: `Saved skill: ${res.skill?.name || 'Recorded task'}`,
      });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not save skill', description: err.message });
    },
  });

  return (
    <div className="h-full flex flex-col">
      {/* Sub-tabs: Screen | Terminal | Files */}
      <div
        className="px-3 py-2 flex items-center justify-between gap-2 shrink-0"
        style={{ borderBottom: '1px solid var(--border-subtle)' }}
      >
        <div
          className="inline-flex rounded-lg p-0.5"
          style={{ backgroundColor: 'var(--bg-subtle)' }}
        >
          {(
            [
              { id: 'screen', label: 'Screen', icon: Monitor },
              { id: 'terminal', label: 'Terminal', icon: TerminalSquare },
              { id: 'files', label: 'Files', icon: FolderOpen },
            ] as const
          ).map((t) => {
            const Icon = t.icon;
            const active = subTab === t.id;
            return (
              <button
                key={t.id}
                type="button"
                onClick={() => setSubTab(t.id)}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[12px] font-medium transition-colors"
                style={{
                  backgroundColor: active ? 'var(--bg-canvas)' : 'transparent',
                  color: active ? 'var(--text-primary)' : 'var(--text-secondary)',
                  boxShadow: active ? 'var(--shadow-sm)' : 'none',
                }}
              >
                <Icon size={13} strokeWidth={1.75} />
                <span>{t.label}</span>
              </button>
            );
          })}
        </div>

        {subTab === 'screen' && (
          <button
            type="button"
            onClick={() => setFullscreenComputerVmId(vmId)}
            title="Expand full screen"
            aria-label="Expand full screen"
            className="p-1.5 rounded-lg hover:bg-[var(--bg-subtle)]"
            style={{ color: 'var(--text-secondary)' }}
          >
            <Maximize2 size={14.5} strokeWidth={1.75} />
          </button>
        )}
      </div>

      {/* Live Teach-a-Task Banner */}
      {isTeaching && (
        <div
          className="px-3 py-2 flex items-center justify-between gap-2 shrink-0 text-[12px]"
          style={{
            backgroundColor: 'var(--accent-computer-tint)',
            borderBottom: '1px solid rgba(124, 58, 237, 0.22)',
            color: 'var(--accent-computer)',
          }}
        >
          <div className="min-w-0">
            <div className="font-semibold truncate">
              {bot?.name || 'Bot'} is watching and learning
            </div>
            <div className="text-[11.5px] opacity-85 truncate">
              {currentStatus?.teach_name || 'Workflow'} ·{' '}
              {Math.max(currentStatus?.teach_steps_count || 0, teachSteps.length)} steps captured
            </div>
          </div>
          <button
            type="button"
            onClick={() => teachStopMutation.mutate()}
            disabled={teachStopMutation.isPending}
            className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[11.5px] font-semibold text-white shrink-0"
            style={{ backgroundColor: 'var(--accent-computer)' }}
          >
            <Square size={10} fill="currentColor" />
            Stop &amp; save skill
          </button>
        </div>
      )}

      {/* Sub-tab body */}
      {subTab === 'screen' && (
        <div className="flex-1 min-h-0 flex flex-col">
          {/* Source & Action Toolbar */}
          <div
            className="px-3 py-2 flex flex-wrap items-center justify-between gap-2 shrink-0"
            style={{
              backgroundColor: 'var(--bg-sidebar)',
              borderBottom: '1px solid var(--border-subtle)',
            }}
          >
            <div className="inline-flex rounded-lg p-0.5" style={{ backgroundColor: 'var(--bg-subtle)' }}>
              <button
                type="button"
                onClick={() => setPreferredSource('vnc')}
                className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-[11.5px] font-medium"
                style={{
                  backgroundColor: effectiveSource === 'vnc' ? 'var(--bg-canvas)' : 'transparent',
                  color: effectiveSource === 'vnc' ? 'var(--text-primary)' : 'var(--text-secondary)',
                }}
              >
                <Monitor size={12} />
                VM Desktop
              </button>
              <button
                type="button"
                onClick={() => setPreferredSource('screencast')}
                className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-[11.5px] font-medium"
                style={{
                  backgroundColor:
                    effectiveSource === 'screencast' ? 'var(--bg-canvas)' : 'transparent',
                  color:
                    effectiveSource === 'screencast'
                      ? 'var(--text-primary)'
                      : 'var(--text-secondary)',
                }}
              >
                <Globe size={12} />
                Live Browser
              </button>
            </div>

            <div className="flex items-center gap-1.5">
              {!isTeaching && bot && (
                <button
                  type="button"
                  onClick={() => setTeachModalOpen(true)}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[11.5px] font-medium hover:bg-[var(--bg-active)]"
                  style={{
                    backgroundColor: 'var(--bg-canvas)',
                    border: '1px solid var(--border-strong)',
                    color: 'var(--text-primary)',
                  }}
                >
                  <GraduationCap size={13} />
                  Teach a task
                </button>
              )}

              {isTakeover ? (
                <button
                  type="button"
                  onClick={() => handbackMutation.mutate()}
                  disabled={handbackMutation.isPending}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[11.5px] font-semibold text-white"
                  style={{ backgroundColor: '#15803D' }}
                >
                  <CheckCircle2 size={12.5} />
                  I&apos;m done
                </button>
              ) : (
                <button
                  type="button"
                  onClick={() => takeoverMutation.mutate()}
                  disabled={takeoverMutation.isPending}
                  className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[11.5px] font-semibold text-white"
                  style={{ backgroundColor: '#D97706' }}
                >
                  <Hand size={12.5} />
                  Take control
                </button>
              )}
            </div>
          </div>

          {/* Active step status strip */}
          {currentStatus?.active_step_summary && (
            <div
              className="px-3 py-1.5 text-[11.5px] truncate shrink-0"
              style={{
                backgroundColor: 'var(--accent-computer-tint)',
                color: 'var(--accent-computer)',
                borderBottom: '1px solid var(--border-subtle)',
              }}
            >
              Computer working · {currentStatus.active_step_summary}
            </div>
          )}

          {/* Embedded Preview Canvas (read-only unless human_takeover; unmounted when fullscreen is active) */}
          <div
            className="flex-1 min-h-0 m-2.5 rounded-xl overflow-hidden"
            style={{
              border: isTakeover
                ? '2px solid #D97706'
                : '1px solid var(--border-strong)',
            }}
          >
            {fullscreenComputerVmId === vmId ? (
              <div
                className="h-full min-h-[220px] flex flex-col items-center justify-center gap-2.5 p-4 text-center"
                style={{ backgroundColor: 'var(--bg-sidebar)', color: 'var(--text-secondary)' }}
              >
                <Monitor size={24} style={{ color: 'var(--accent-computer)' }} />
                <div className="text-[13px] font-medium" style={{ color: 'var(--text-primary)' }}>
                  Active in full-screen takeover
                </div>
                <button
                  type="button"
                  onClick={() => setFullscreenComputerVmId(null)}
                  className="px-3 py-1.5 rounded-lg text-[12px] font-medium hover:bg-[var(--bg-active)]"
                  style={{
                    backgroundColor: 'var(--bg-canvas)',
                    border: '1px solid var(--border-strong)',
                    color: 'var(--text-primary)',
                  }}
                >
                  Exit full-screen
                </button>
              </div>
            ) : !canMountCanvas ? (
              <div
                className="h-full min-h-[220px] flex flex-col items-center justify-center gap-2 p-4 text-center"
                style={{ backgroundColor: '#18191C', color: '#A1A7B5' }}
              >
                <Monitor size={22} className="text-[#A78BFA]" />
                <div className="text-[12.5px]">Checking display availability…</div>
              </div>
            ) : (
              <LiveVncCanvas
                vmId={vmId}
                source={effectiveSource}
                interactive={isTakeover}
              />
            )}
          </div>
        </div>
      )}

      {subTab === 'terminal' && <TerminalTab vmId={vmId} projectName={bot?.project_name} />}

      {subTab === 'files' && (
        <WorkspaceFilesTab vmId={vmId} defaultProject={bot?.project_name} />
      )}

      {/* Teach a task modal */}
      <Modal
        open={teachModalOpen}
        onClose={() => setTeachModalOpen(false)}
        title="Teach a task"
        subtitle={`Demonstrate a workflow in the live computer and ${bot?.name || 'your bot'} will compile it into a reusable Skill.`}
        maxWidthClass="max-w-sm"
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (teachName.trim()) teachStartMutation.mutate(teachName.trim());
          }}
          className="p-4 space-y-3"
        >
          <div>
            <label className="block text-[12px] font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
              Task name
            </label>
            <input
              type="text"
              autoFocus
              required
              value={teachName}
              onChange={(e) => setTeachName(e.target.value)}
              placeholder="e.g. Export weekly metrics CSV"
              className="w-full px-3 py-2 rounded-lg text-[13px] outline-none bg-[var(--bg-sidebar)] border border-[var(--border-strong)]"
            />
          </div>
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => setTeachModalOpen(false)}
              className="px-3 py-1.5 rounded-lg text-[12.5px]"
              style={{ color: 'var(--text-secondary)' }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={!teachName.trim() || teachStartMutation.isPending}
              className="px-3.5 py-1.5 rounded-lg text-[12.5px] font-medium text-white"
              style={{ backgroundColor: 'var(--accent-computer)' }}
            >
              {teachStartMutation.isPending ? 'Starting…' : 'Start watching'}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
};
