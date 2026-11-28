import React, { useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Modal } from '../../components/Modal';
import { botsApi, legacyApi } from '../../lib/api';
import type { AvatarShape, EngineId, ThinkingLevel } from '../../lib/types';
import { useUiStore } from '../../stores/uiStore';
import { AVATAR_COLORS, AVATAR_SHAPES, BotAvatar } from './BotAvatar';

export const CreateBotModal: React.FC = () => {
  const open = useUiStore((s) => s.createBotOpen);
  const setOpen = useUiStore((s) => s.setCreateBotOpen);
  const setActiveTarget = useUiStore((s) => s.setActiveTarget);
  const pushToast = useUiStore((s) => s.pushToast);
  const queryClient = useQueryClient();

  const [name, setName] = useState('');
  const [shape, setShape] = useState<AvatarShape>('sparkle');
  const [color, setColor] = useState<string>('#7C3AED');
  const [eyesLarge, setEyesLarge] = useState(false);
  const [engineId, setEngineId] = useState<EngineId>('agy');
  const [modelId, setModelId] = useState('gemini-4-carbon-low');
  const [thinkingLevel, setThinkingLevel] = useState<ThinkingLevel>('medium');
  const [projectName, setProjectName] = useState('');

  const modelsQuery = useQuery({
    queryKey: ['agy-models'],
    queryFn: () => legacyApi.agyModels(),
    enabled: open,
    staleTime: 60_000,
  });

  const projectsQuery = useQuery({
    queryKey: ['local-projects'],
    queryFn: () => legacyApi.projects(),
    enabled: open,
    staleTime: 60_000,
  });

  const createMutation = useMutation({
    mutationFn: () =>
      botsApi.create({
        name: name.trim(),
        avatar_shape: shape,
        avatar_color: color,
        avatar_eyes_large: eyesLarge,
        engine_id: engineId,
        model_id: modelId,
        thinking_level: thinkingLevel,
        project_name: projectName || null,
      }),
    onSuccess: (bot) => {
      void queryClient.invalidateQueries({ queryKey: ['roster'] });
      setActiveTarget({ kind: 'bot', id: bot.id, threadId: bot.thread_id });
      setName('');
      setOpen(false);
      pushToast({
        tone: 'success',
        title: `${bot.name} is ready`,
        description: 'Introduce their role in the first message.',
      });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not create bot', description: err.message });
    },
  });

  const availableModels = (modelsQuery.data?.models ?? []).filter((m) => !m.is_hydrogen);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim() || createMutation.isPending) return;
    createMutation.mutate();
  };

  return (
    <Modal
      open={open}
      onClose={() => setOpen(false)}
      title="Create a bot"
      subtitle="Setup is a message — give them a name and avatar, then describe their job in chat."
    >
      <form onSubmit={handleSubmit} className="p-5 space-y-5">
        {/* Preview + Name */}
        <div className="flex items-center gap-4">
          <div
            className="w-16 h-16 rounded-2xl flex items-center justify-center shrink-0"
            style={{
              backgroundColor: 'var(--bg-sidebar)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            <BotAvatar
              shape={shape}
              color={color}
              eyesLarge={eyesLarge}
              state="idle"
              size={44}
            />
          </div>
          <div className="flex-1 min-w-0">
            <label
              htmlFor="new-bot-name"
              className="block text-[12px] font-medium mb-1"
              style={{ color: 'var(--text-secondary)' }}
            >
              Name
            </label>
            <input
              id="new-bot-name"
              type="text"
              autoFocus
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Dispatch, Research Lead, Ops Analyst"
              className="w-full px-3 py-2 text-[14px] rounded-lg outline-none transition-colors"
              style={{
                backgroundColor: 'var(--bg-canvas)',
                border: '1px solid var(--border-strong)',
              }}
            />
          </div>
        </div>

        {/* Shape picker */}
        <div>
          <div
            className="text-[12px] font-medium mb-2"
            style={{ color: 'var(--text-secondary)' }}
          >
            Shape
          </div>
          <div className="grid grid-cols-7 gap-1.5">
            {AVATAR_SHAPES.map((s) => {
              const selected = shape === s.id;
              return (
                <button
                  key={s.id}
                  type="button"
                  onClick={() => setShape(s.id)}
                  title={`${s.label}`}
                  aria-label={`${s.label}`}
                  className="flex flex-col items-center justify-center p-2 rounded-xl transition-all"
                  style={{
                    backgroundColor: selected ? 'var(--bg-active)' : 'var(--bg-sidebar)',
                    border: selected
                      ? `1.5px solid ${color}`
                      : '1px solid var(--border-subtle)',
                  }}
                >
                  <BotAvatar shape={s.id} color={color} eyesLarge={eyesLarge} size={26} />
                </button>
              );
            })}
          </div>
        </div>

        {/* Color & Eyes */}
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <div
              className="text-[12px] font-medium mb-2"
              style={{ color: 'var(--text-secondary)' }}
            >
              Color
            </div>
            <div className="flex items-center gap-2">
              {AVATAR_COLORS.map((c) => {
                const selected = color === c;
                return (
                  <button
                    key={c}
                    type="button"
                    onClick={() => setColor(c)}
                    aria-label={`Select color ${c}`}
                    className="w-6 h-6 rounded-full transition-transform hover:scale-110"
                    style={{
                      backgroundColor: c,
                      boxShadow: selected
                        ? `0 0 0 2px var(--bg-canvas), 0 0 0 4px ${c}`
                        : 'none',
                    }}
                  />
                );
              })}
            </div>
          </div>

          <label className="inline-flex items-center gap-2 text-[13px] cursor-pointer select-none mt-4">
            <input
              type="checkbox"
              aria-label="Larger eyes"
              checked={eyesLarge}
              onChange={(e) => setEyesLarge(e.target.checked)}
              className="rounded"
            />
            <span style={{ color: 'var(--text-secondary)' }}>Larger eyes</span>
          </label>
        </div>

        {/* Capability defaults */}
        <div
          className="grid grid-cols-1 sm:grid-cols-2 gap-3 pt-3"
          style={{ borderTop: '1px solid var(--border-subtle)' }}
        >
          <div>
            <label
              htmlFor="create-bot-engine"
              className="block text-[12px] font-medium mb-1"
              style={{ color: 'var(--text-secondary)' }}
            >
              Engine
            </label>
            <select
              id="create-bot-engine"
              aria-label="Engine"
              value={engineId}
              onChange={(e) => setEngineId(e.target.value as EngineId)}
              className="w-full px-2.5 py-2 text-[13px] rounded-lg outline-none"
              style={{
                backgroundColor: 'var(--bg-canvas)',
                border: '1px solid var(--border-strong)',
              }}
            >
              <option value="agy">Antigravity CLI (agy)</option>
              <option value="controlbot_runtime">ControlBot Runtime</option>
            </select>
          </div>

          <div>
            <label
              htmlFor="create-bot-model"
              className="block text-[12px] font-medium mb-1"
              style={{ color: 'var(--text-secondary)' }}
            >
              Model
            </label>
            <select
              id="create-bot-model"
              aria-label="Model"
              value={modelId}
              onChange={(e) => setModelId(e.target.value)}
              className="w-full px-2.5 py-2 text-[13px] rounded-lg outline-none"
              style={{
                backgroundColor: 'var(--bg-canvas)',
                border: '1px solid var(--border-strong)',
              }}
            >
              {availableModels.length > 0 ? (
                availableModels.map((m) => (
                  <option key={m.id} value={m.id}>
                    {m.label}
                  </option>
                ))
              ) : (
                <option value="gemini-4-carbon-low">Gemini 4 Carbon (Low)</option>
              )}
            </select>
          </div>

          <div>
            <label
              htmlFor="create-bot-thinking"
              className="block text-[12px] font-medium mb-1"
              style={{ color: 'var(--text-secondary)' }}
            >
              Thinking effort
            </label>
            <select
              id="create-bot-thinking"
              aria-label="Thinking effort"
              value={thinkingLevel}
              onChange={(e) => setThinkingLevel(e.target.value as ThinkingLevel)}
              className="w-full px-2.5 py-2 text-[13px] rounded-lg outline-none"
              style={{
                backgroundColor: 'var(--bg-canvas)',
                border: '1px solid var(--border-strong)',
              }}
            >
              <option value="off">Off</option>
              <option value="low">Low</option>
              <option value="medium">Medium</option>
              <option value="high">High</option>
              <option value="max">Max</option>
            </select>
          </div>

          <div>
            <label
              htmlFor="create-bot-project"
              className="block text-[12px] font-medium mb-1"
              style={{ color: 'var(--text-secondary)' }}
            >
              Workspace project
            </label>
            <select
              id="create-bot-project"
              aria-label="Workspace project"
              value={projectName}
              onChange={(e) => setProjectName(e.target.value)}
              className="w-full px-2.5 py-2 text-[13px] rounded-lg outline-none"
              style={{
                backgroundColor: 'var(--bg-canvas)',
                border: '1px solid var(--border-strong)',
              }}
            >
              <option value="">Default workspace</option>
              {(projectsQuery.data?.projects ?? []).map((p) => (
                <option key={p.name} value={p.name}>
                  {p.name}
                </option>
              ))}
            </select>
          </div>
        </div>

        {/* Actions */}
        <div
          className="flex items-center justify-end gap-2 pt-3"
          style={{ borderTop: '1px solid var(--border-subtle)' }}
        >
          <button
            type="button"
            onClick={() => setOpen(false)}
            className="px-3.5 py-2 text-[13px] font-medium rounded-lg hover:bg-[var(--bg-subtle)] transition-colors"
            style={{ color: 'var(--text-secondary)' }}
          >
            Cancel
          </button>
          <button
            type="submit"
            aria-label="Create bot"
            disabled={!name.trim() || createMutation.isPending}
            className="px-4 py-2 text-[13px] font-medium rounded-lg text-white transition-opacity disabled:opacity-45"
            style={{ backgroundColor: color }}
          >
            {createMutation.isPending ? 'Creating…' : 'Create bot'}
          </button>
        </div>
      </form>
    </Modal>
  );
};
