import React, { useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Check } from 'lucide-react';
import { Modal } from '../../components/Modal';
import { channelsApi } from '../../lib/api';
import type { Bot } from '../../lib/types';
import { useUiStore } from '../../stores/uiStore';
import { BotAvatar } from './BotAvatar';

interface CreateChannelModalProps {
  bots: Bot[];
}

export const CreateChannelModal: React.FC<CreateChannelModalProps> = ({ bots }) => {
  const open = useUiStore((s) => s.createChannelOpen);
  const setOpen = useUiStore((s) => s.setCreateChannelOpen);
  const setActiveTarget = useUiStore((s) => s.setActiveTarget);
  const pushToast = useUiStore((s) => s.pushToast);
  const queryClient = useQueryClient();

  const [name, setName] = useState('');
  const [selectedIds, setSelectedIds] = useState<string[]>([]);

  const visibleBots = bots.filter((b) => !b.hidden);

  const toggleBot = (id: string) => {
    setSelectedIds((prev) => {
      if (prev.includes(id)) return prev.filter((x) => x !== id);
      if (prev.length >= 6) return prev;
      return [...prev, id];
    });
  };

  const createMutation = useMutation({
    mutationFn: () =>
      channelsApi.create({
        name: name.trim(),
        bot_ids: selectedIds,
      }),
    onSuccess: (channel) => {
      void queryClient.invalidateQueries({ queryKey: ['roster'] });
      setActiveTarget({ kind: 'channel', id: channel.id, threadId: channel.thread_id });
      setName('');
      setSelectedIds([]);
      setOpen(false);
      pushToast({ tone: 'success', title: `Created #${channel.name}` });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not create group chat', description: err.message });
    },
  });

  const canSubmit = name.trim().length > 0 && selectedIds.length >= 2 && selectedIds.length <= 6;

  return (
    <Modal
      open={open}
      onClose={() => setOpen(false)}
      title="New group chat"
      subtitle="Collaborate with 2 to 6 bots in a shared channel using @mentions."
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (canSubmit && !createMutation.isPending) createMutation.mutate();
        }}
        className="p-5 space-y-4"
      >
        <div>
          <label
            htmlFor="new-channel-name"
            className="block text-[12px] font-medium mb-1"
            style={{ color: 'var(--text-secondary)' }}
          >
            Channel name
          </label>
          <input
            id="new-channel-name"
            type="text"
            autoFocus
            required
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="e.g. Operations Room, Design Review"
            className="w-full px-3 py-2 text-[14px] rounded-lg outline-none"
            style={{
              backgroundColor: 'var(--bg-canvas)',
              border: '1px solid var(--border-strong)',
            }}
          />
        </div>

        <div>
          <div className="flex items-center justify-between mb-2">
            <span className="text-[12px] font-medium" style={{ color: 'var(--text-secondary)' }}>
              Select bots (2–6)
            </span>
            <span className="text-[12px] tabular-nums" style={{ color: 'var(--text-muted)' }}>
              {selectedIds.length} / 6 selected
            </span>
          </div>

          {visibleBots.length < 2 ? (
            <div
              className="p-3 rounded-xl text-[13px]"
              style={{
                backgroundColor: 'var(--bg-sidebar)',
                color: 'var(--text-secondary)',
              }}
            >
              Create at least 2 bots first to start a group chat.
            </div>
          ) : (
            <div className="space-y-1.5 max-h-60 overflow-y-auto pr-1">
              {visibleBots.map((bot) => {
                const selected = selectedIds.includes(bot.id);
                return (
                  <button
                    key={bot.id}
                    type="button"
                    aria-label={`${bot.name}`}
                    onClick={() => toggleBot(bot.id)}
                    className="w-full flex items-center gap-3 px-3 py-2 rounded-xl text-left transition-colors"
                    style={{
                      backgroundColor: selected ? 'var(--bg-active)' : 'var(--bg-sidebar)',
                      border: selected
                        ? '1px solid var(--border-strong)'
                        : '1px solid transparent',
                    }}
                  >
                    <BotAvatar
                      shape={bot.avatar_shape}
                      color={bot.avatar_color}
                      eyesLarge={bot.avatar_eyes_large}
                      size={28}
                    />
                    <div className="min-w-0 flex-1">
                      <div
                        className="text-[13px] font-medium truncate"
                        style={{ color: 'var(--text-primary)' }}
                      >
                        {bot.name}
                      </div>
                      <div
                        className="text-[11.5px] truncate"
                        style={{ color: 'var(--text-muted)' }}
                      >
                        {bot.status_subtext || bot.model_id}
                      </div>
                    </div>
                    <div
                      className="w-5 h-5 rounded-md flex items-center justify-center shrink-0"
                      style={{
                        backgroundColor: selected ? 'var(--accent-primary)' : 'transparent',
                        border: selected ? 'none' : '1px solid var(--border-strong)',
                        color: selected ? 'var(--bg-canvas)' : 'transparent',
                      }}
                    >
                      <Check size={13} strokeWidth={2.5} />
                    </div>
                  </button>
                );
              })}
            </div>
          )}
        </div>

        <div
          className="flex items-center justify-end gap-2 pt-3"
          style={{ borderTop: '1px solid var(--border-subtle)' }}
        >
          <button
            type="button"
            onClick={() => setOpen(false)}
            className="px-3.5 py-2 text-[13px] font-medium rounded-lg hover:bg-[var(--bg-subtle)]"
            style={{ color: 'var(--text-secondary)' }}
          >
            Cancel
          </button>
          <button
            type="submit"
            aria-label="Create group chat"
            disabled={!canSubmit || createMutation.isPending}
            className="px-4 py-2 text-[13px] font-medium rounded-lg transition-opacity disabled:opacity-45"
            style={{
              backgroundColor: 'var(--accent-primary)',
              color: 'var(--bg-canvas)',
            }}
          >
            {createMutation.isPending ? 'Creating…' : 'Create group chat'}
          </button>
        </div>
      </form>
    </Modal>
  );
};
