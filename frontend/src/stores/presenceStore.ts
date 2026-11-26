import { create } from 'zustand';
import type { Bot, BotLifecycleState } from '../lib/types';

export interface BotPresence {
  state: BotLifecycleState;
  stepLabel?: string;
  subtext: string;
  computerActive: boolean;
  updatedAt: number;
}

interface PresenceState {
  byBotId: Record<string, BotPresence>;
  seedFromBots: (bots: Bot[]) => void;
  updatePresence: (
    botId: string,
    patch: {
      state: BotLifecycleState;
      step_label?: string;
      subtext: string;
      computer_active: boolean;
    },
  ) => void;
}

export const usePresenceStore = create<PresenceState>((set) => ({
  byBotId: {},

  seedFromBots: (bots) =>
    set((s) => {
      const next = { ...s.byBotId };
      for (const bot of bots) {
        if (!next[bot.id]) {
          next[bot.id] = {
            state: bot.status_state || 'idle',
            subtext: bot.status_subtext || 'Ready',
            computerActive: Boolean(bot.computer_active),
            updatedAt: Date.now(),
          };
        }
      }
      return { byBotId: next };
    }),

  updatePresence: (botId, patch) =>
    set((s) => ({
      byBotId: {
        ...s.byBotId,
        [botId]: {
          state: patch.state,
          stepLabel: patch.step_label,
          subtext: patch.subtext,
          computerActive: Boolean(patch.computer_active),
          updatedAt: Date.now(),
        },
      },
    })),
}));
