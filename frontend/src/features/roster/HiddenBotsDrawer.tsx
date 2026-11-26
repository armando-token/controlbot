import React from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Eye, Hash, MessageSquare } from 'lucide-react';
import { Modal } from '../../components/Modal';
import { botsApi, channelsApi } from '../../lib/api';
import type { Bot, Channel } from '../../lib/types';
import { useUiStore } from '../../stores/uiStore';
import { BotAvatar } from './BotAvatar';

interface HiddenBotsDrawerProps {
  bots: Bot[];
  channels: Channel[];
}

export const HiddenBotsDrawer: React.FC<HiddenBotsDrawerProps> = ({ bots, channels }) => {
  const open = useUiStore((s) => s.hiddenBotsOpen);
  const setOpen = useUiStore((s) => s.setHiddenBotsOpen);
  const setActiveTarget = useUiStore((s) => s.setActiveTarget);
  const pushToast = useUiStore((s) => s.pushToast);
  const queryClient = useQueryClient();

  const hiddenBots = bots.filter((b) => b.hidden);
  const hiddenChannels = channels.filter((c) => c.hidden);

  const unhideBotMutation = useMutation({
    mutationFn: (botId: string) => botsApi.update(botId, { hidden: false }),
    onSuccess: (bot) => {
      void queryClient.invalidateQueries({ queryKey: ['roster'] });
      pushToast({ tone: 'success', title: `Restored ${bot.name} to sidebar` });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not restore bot', description: err.message });
    },
  });

  const unhideChannelMutation = useMutation({
    mutationFn: (channelId: string) => channelsApi.update(channelId, { hidden: false }),
    onSuccess: (ch) => {
      void queryClient.invalidateQueries({ queryKey: ['roster'] });
      pushToast({ tone: 'success', title: `Restored #${ch.name} to sidebar` });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not restore channel', description: err.message });
    },
  });

  return (
    <Modal
      open={open}
      onClose={() => setOpen(false)}
      title="Hidden bots"
      subtitle="Hiding removes a bot from your sidebar without pausing its routines or clearing memory."
    >
      <div className="p-5 space-y-3">
        {hiddenBots.length === 0 && hiddenChannels.length === 0 ? (
          <div
            className="text-center py-8 text-[13px]"
            style={{ color: 'var(--text-muted)' }}
          >
            No hidden bots or channels. Right-click any bot in the sidebar to hide it.
          </div>
        ) : (
          <>
            {hiddenBots.map((bot) => (
              <div
                key={bot.id}
                className="flex items-center justify-between gap-3 p-3 rounded-xl"
                style={{
                  backgroundColor: 'var(--bg-sidebar)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <div className="flex items-center gap-3 min-w-0">
                  <BotAvatar
                    shape={bot.avatar_shape}
                    color={bot.avatar_color}
                    eyesLarge={bot.avatar_eyes_large}
                    size={30}
                  />
                  <div className="min-w-0">
                    <div
                      className="text-[13.5px] font-medium truncate"
                      style={{ color: 'var(--text-primary)' }}
                    >
                      {bot.name}
                    </div>
                    <div className="text-[12px] truncate" style={{ color: 'var(--text-muted)' }}>
                      {bot.status_subtext || 'Idle'}
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-1.5 shrink-0">
                  <button
                    type="button"
                    onClick={() => {
                      setActiveTarget({ kind: 'bot', id: bot.id, threadId: bot.thread_id });
                      setOpen(false);
                    }}
                    className="inline-flex items-center gap-1 px-2.5 py-1.5 text-[12px] font-medium rounded-lg hover:bg-[var(--bg-active)]"
                    style={{ color: 'var(--text-secondary)' }}
                  >
                    <MessageSquare size={13} strokeWidth={1.75} />
                    Open
                  </button>
                  <button
                    type="button"
                    onClick={() => unhideBotMutation.mutate(bot.id)}
                    disabled={unhideBotMutation.isPending}
                    className="inline-flex items-center gap-1 px-2.5 py-1.5 text-[12px] font-medium rounded-lg"
                    style={{
                      backgroundColor: 'var(--bg-canvas)',
                      border: '1px solid var(--border-strong)',
                      color: 'var(--text-primary)',
                    }}
                  >
                    <Eye size={13} strokeWidth={1.75} />
                    Unhide
                  </button>
                </div>
              </div>
            ))}

            {hiddenChannels.map((ch) => (
              <div
                key={ch.id}
                className="flex items-center justify-between gap-3 p-3 rounded-xl"
                style={{
                  backgroundColor: 'var(--bg-sidebar)',
                  border: '1px solid var(--border-subtle)',
                }}
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  <div
                    className="w-8 h-8 rounded-lg flex items-center justify-center"
                    style={{ backgroundColor: 'var(--bg-subtle)', color: 'var(--text-secondary)' }}
                  >
                    <Hash size={15} strokeWidth={1.75} />
                  </div>
                  <div className="min-w-0">
                    <div
                      className="text-[13.5px] font-medium truncate"
                      style={{ color: 'var(--text-primary)' }}
                    >
                      {ch.name}
                    </div>
                    <div className="text-[12px]" style={{ color: 'var(--text-muted)' }}>
                      {ch.bot_ids.length} bots
                    </div>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={() => unhideChannelMutation.mutate(ch.id)}
                  disabled={unhideChannelMutation.isPending}
                  className="inline-flex items-center gap-1 px-2.5 py-1.5 text-[12px] font-medium rounded-lg disabled:opacity-45"
                  style={{
                    backgroundColor: 'var(--bg-canvas)',
                    border: '1px solid var(--border-strong)',
                    color: 'var(--text-primary)',
                  }}
                >
                  <Eye size={13} strokeWidth={1.75} />
                  Unhide
                </button>
              </div>
            ))}
          </>
        )}
      </div>
    </Modal>
  );
};
