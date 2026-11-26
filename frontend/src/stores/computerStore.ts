import { create } from 'zustand';
import type { ComputerStatus } from '../lib/types';

export interface TeachStepItem {
  index: number;
  description: string;
  action?: string;
  url?: string;
  ts: number;
}

interface ComputerState {
  byVmId: Record<string, ComputerStatus>;
  preferredSource: 'vnc' | 'screencast';
  teachSteps: TeachStepItem[];

  setStatus: (status: ComputerStatus) => void;
  setPreferredSource: (source: 'vnc' | 'screencast') => void;
  addTeachStep: (step: {
    index: number;
    description: string;
    action?: string;
    url?: string;
  }) => void;
  clearTeachSteps: () => void;
}

const defaultStatus: ComputerStatus = {
  vm_id: 'default',
  status: 'ready',
  control_owner: 'agent',
  lease_id: null,
  lease_expires_at: null,
  vnc_available: true,
  browser_running: false,
  active_url: '',
  active_tab_title: '',
  active_step_summary: null,
  is_teaching_task: false,
  teach_name: null,
  teach_steps_count: 0,
  display_mode: 'vnc',
};

export const useComputerStore = create<ComputerState>((set) => ({
  byVmId: { default: defaultStatus },
  preferredSource: 'vnc',
  teachSteps: [],

  setStatus: (status) =>
    set((s) => ({
      byVmId: {
        ...s.byVmId,
        [status.vm_id || 'default']: status,
      },
    })),

  setPreferredSource: (preferredSource) => set({ preferredSource }),

  addTeachStep: (step) =>
    set((s) => ({
      teachSteps: [...s.teachSteps, { ...step, ts: Date.now() }],
    })),

  clearTeachSteps: () => set({ teachSteps: [] }),
}));
