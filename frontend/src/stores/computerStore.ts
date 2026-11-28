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
  loadedByVmId: Record<string, boolean>;
  preferredSource: 'vnc' | 'screencast';
  hasExplicitSourceChoice: boolean;
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
  loadedByVmId: {},
  preferredSource: 'vnc',
  hasExplicitSourceChoice: false,
  teachSteps: [],

  setStatus: (status) =>
    set((s) => {
      const vmKey = status.vm_id || 'default';
      const vncUnavailable = !status.vnc_available;
      let nextPreferred = s.preferredSource;
      if (!s.hasExplicitSourceChoice) {
        if (vncUnavailable || status.browser_running) {
          nextPreferred = 'screencast';
        } else if (status.display_mode === 'vnc' && s.preferredSource === 'screencast') {
          nextPreferred = 'vnc';
        }
      }
      return {
        byVmId: {
          ...s.byVmId,
          [vmKey]: status,
        },
        loadedByVmId: {
          ...s.loadedByVmId,
          [vmKey]: true,
        },
        preferredSource: nextPreferred,
      };
    }),

  setPreferredSource: (preferredSource) => set({ preferredSource, hasExplicitSourceChoice: true }),

  addTeachStep: (step) =>
    set((s) => ({
      teachSteps: [...s.teachSteps, { ...step, ts: Date.now() }],
    })),

  clearTeachSteps: () => set({ teachSteps: [] }),
}));
