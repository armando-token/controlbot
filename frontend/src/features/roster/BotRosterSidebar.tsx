import React, { useEffect, useRef, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import {
  BellDot,
  ChevronDown,
  ChevronRight,
  Crown,
  Database,
  EyeOff,
  FolderPlus,
  Hash,
  Keyboard,
  MoreHorizontal,
  PanelLeftClose,
  PanelLeftOpen,
  Pencil,
  Pin,
  PinOff,
  Plug,
  Plus,
  Search,
  Settings,
  Trash2,
  Users,
} from 'lucide-react';
import { botsApi, channelsApi, sectionsApi } from '../../lib/api';
import type { Bot, Channel, Section } from '../../lib/types';
import { usePresenceStore } from '../../stores/presenceStore';
import { useUiStore } from '../../stores/uiStore';
import { BotAvatar } from './BotAvatar';

interface BotRosterSidebarProps {
  bots: Bot[];
  sections: Section[];
  channels: Channel[];
  compact: boolean;
}

interface ContextMenuState {
  kind: 'bot' | 'channel';
  id: string;
  x: number;
  y: number;
}

export const BotRosterSidebar: React.FC<BotRosterSidebarProps> = ({
  bots,
  sections,
  channels,
  compact,
}) => {
  const queryClient = useQueryClient();
  const activeTarget = useUiStore((s) => s.activeTarget);
  const setActiveTarget = useUiStore((s) => s.setActiveTarget);
  const unreadOnly = useUiStore((s) => s.unreadOnly);
  const toggleUnreadOnly = useUiStore((s) => s.toggleUnreadOnly);
  const toggleSidebar = useUiStore((s) => s.toggleSidebar);
  const openCommandPalette = useUiStore((s) => s.openCommandPalette);
  const setCreateBotOpen = useUiStore((s) => s.setCreateBotOpen);
  const setCreateChannelOpen = useUiStore((s) => s.setCreateChannelOpen);
  const setConnectAppsOpen = useUiStore((s) => s.setConnectAppsOpen);
  const setHiddenBotsOpen = useUiStore((s) => s.setHiddenBotsOpen);
  const setMemoryOpen = useUiStore((s) => s.setMemoryOpen);
  const openSettings = useUiStore((s) => s.openSettings);
  const setShortcutsOpen = useUiStore((s) => s.setShortcutsOpen);
  const pushToast = useUiStore((s) => s.pushToast);

  const presenceByBotId = usePresenceStore((s) => s.byBotId);

  const [plusMenuOpen, setPlusMenuOpen] = useState(false);
  const [collapsedSections, setCollapsedSections] = useState<Record<string, boolean>>({});
  const [contextMenu, setContextMenu] = useState<ContextMenuState | null>(null);
  const [renamingId, setRenamingId] = useState<string | null>(null);
  const [renameDraft, setRenameDraft] = useState('');
  const [creatingSection, setCreatingSection] = useState(false);
  const [newSectionName, setNewSectionName] = useState('');

  const plusRef = useRef<HTMLDivElement | null>(null);
  const plusTriggerRef = useRef<HTMLButtonElement | null>(null);
  const plusMenuOpenRef = useRef(plusMenuOpen);
  plusMenuOpenRef.current = plusMenuOpen;
  const contextMenuRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    const closeOnClick = (e: MouseEvent) => {
      if (plusRef.current && !plusRef.current.contains(e.target as Node)) {
        setPlusMenuOpen(false);
      }
      if (!contextMenuRef.current || !contextMenuRef.current.contains(e.target as Node)) {
        setContextMenu(null);
      }
    };
    const closeOnContextMenu = (e: MouseEvent) => {
      if (plusRef.current && !plusRef.current.contains(e.target as Node)) {
        setPlusMenuOpen(false);
      }
      if (contextMenuRef.current && !contextMenuRef.current.contains(e.target as Node)) {
        setContextMenu(null);
      }
    };
    const closeOnKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        if (plusMenuOpenRef.current) {
          e.preventDefault();
          setPlusMenuOpen(false);
          plusTriggerRef.current?.focus();
        }
        setContextMenu(null);
      }
    };
    const closeOnScroll = () => {
      setContextMenu(null);
    };
    window.addEventListener('click', closeOnClick);
    window.addEventListener('contextmenu', closeOnContextMenu);
    window.addEventListener('keydown', closeOnKeyDown);
    window.addEventListener('scroll', closeOnScroll, true);
    return () => {
      window.removeEventListener('click', closeOnClick);
      window.removeEventListener('contextmenu', closeOnContextMenu);
      window.removeEventListener('keydown', closeOnKeyDown);
      window.removeEventListener('scroll', closeOnScroll, true);
    };
  }, []);

  const updateBotMutation = useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: Partial<Bot> }) =>
      botsApi.update(id, patch),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['roster'] });
    },
    onError: (err: Error) =>
      pushToast({ tone: 'error', title: 'Update failed', description: err.message }),
  });

  const deleteBotMutation = useMutation({
    mutationFn: (id: string) => botsApi.remove(id),
    onSuccess: (_res, id) => {
      void queryClient.invalidateQueries({ queryKey: ['roster'] });
      if (activeTarget?.kind === 'bot' && activeTarget.id === id) {
        setActiveTarget(null);
      }
      pushToast({ tone: 'info', title: 'Bot deleted' });
    },
    onError: (err: Error) =>
      pushToast({ tone: 'error', title: 'Could not delete bot', description: err.message }),
  });

  const updateChannelMutation = useMutation({
    mutationFn: ({ id, patch }: { id: string; patch: Partial<Channel> }) =>
      channelsApi.update(id, patch),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['roster'] });
    },
    onError: (err: Error) =>
      pushToast({ tone: 'error', title: 'Update failed', description: err.message }),
  });

  const deleteChannelMutation = useMutation({
    mutationFn: (id: string) => channelsApi.remove(id),
    onSuccess: (_res, id) => {
      void queryClient.invalidateQueries({ queryKey: ['roster'] });
      if (activeTarget?.kind === 'channel' && activeTarget.id === id) {
        setActiveTarget(null);
      }
      pushToast({ tone: 'info', title: 'Group chat deleted' });
    },
    onError: (err: Error) =>
      pushToast({ tone: 'error', title: 'Could not delete group chat', description: err.message }),
  });

  const createSectionMutation = useMutation({
    mutationFn: (name: string) => sectionsApi.create(name),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['roster'] });
      setNewSectionName('');
      setCreatingSection(false);
      pushToast({ tone: 'success', title: 'Section created' });
    },
    onError: (err: Error) =>
      pushToast({ tone: 'error', title: 'Could not create section', description: err.message }),
  });

  const updateSectionMutation = useMutation({
    mutationFn: ({ id, name }: { id: string; name: string }) =>
      sectionsApi.update(id, { name }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['roster'] });
    },
    onError: (err: Error) =>
      pushToast({ tone: 'error', title: 'Could not rename section', description: err.message }),
  });

  const deleteSectionMutation = useMutation({
    mutationFn: (id: string) => sectionsApi.remove(id),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['roster'] });
      pushToast({ tone: 'info', title: 'Section removed' });
    },
    onError: (err: Error) =>
      pushToast({ tone: 'error', title: 'Could not remove section', description: err.message }),
  });

  const visibleBots = bots.filter((b) => {
    if (b.hidden) return false;
    if (unreadOnly) return b.unread_count > 0 || b.needs_attention;
    return true;
  });

  const visibleChannels = channels.filter((c) => {
    if (c.hidden) return false;
    if (unreadOnly) return c.unread_count > 0;
    return true;
  });

  const hiddenCount =
    bots.filter((b) => b.hidden).length + channels.filter((c) => c.hidden).length;

  const pinnedBots = visibleBots.filter((b) => b.pinned);
  const pinnedChannels = visibleChannels.filter((c) => c.pinned);
  const unpinnedBots = visibleBots.filter((b) => !b.pinned);
  const unpinnedChannels = visibleChannels.filter((c) => !c.pinned);

  const directBotsNoSection = unpinnedBots.filter((b) => !b.section_id);
  const channelsNoSection = unpinnedChannels.filter((c) => !c.section_id);

  const openContext = (e: React.MouseEvent, kind: 'bot' | 'channel', id: string) => {
    e.preventDefault();
    e.stopPropagation();
    const x = Math.min(e.clientX, window.innerWidth - 220);
    const y = Math.min(e.clientY, window.innerHeight - 280);
    setContextMenu({ kind, id, x, y });
  };

  const commitRename = (kind: 'bot' | 'channel' | 'section', id: string) => {
    const trimmed = renameDraft.trim();
    setRenamingId(null);
    if (!trimmed) return;
    if (kind === 'bot') {
      updateBotMutation.mutate({ id, patch: { name: trimmed } });
    } else if (kind === 'channel') {
      updateChannelMutation.mutate({ id, patch: { name: trimmed } });
    } else {
      updateSectionMutation.mutate({ id, name: trimmed });
    }
  };

  const renderBotRow = (bot: Bot) => {
    const isActive = activeTarget?.kind === 'bot' && activeTarget.id === bot.id;
    const live = presenceByBotId[bot.id];
    const state = live?.state ?? bot.status_state ?? 'idle';
    const subtext = live?.subtext ?? bot.status_subtext ?? 'Ready';
    const computerActive = live?.computerActive ?? bot.computer_active;
    const tooltip = live?.stepLabel || `${bot.name} · ${subtext}`;
    const isRenaming = renamingId === bot.id;
    const botRowLabel = `${bot.name} — ${subtext}`;

    if (compact) {
      return (
        <button
          key={bot.id}
          type="button"
          onClick={() =>
            setActiveTarget({ kind: 'bot', id: bot.id, threadId: bot.thread_id })
          }
          onContextMenu={(e) => openContext(e, 'bot', bot.id)}
          title={`${bot.name} — ${subtext}`}
          aria-label={`${bot.name} — ${subtext}`}
          className="relative w-11 h-11 mx-auto flex items-center justify-center rounded-xl transition-colors"
          style={{
            backgroundColor: isActive ? 'var(--bg-active)' : 'transparent',
          }}
        >
          <BotAvatar
            shape={bot.avatar_shape}
            color={bot.avatar_color}
            eyesLarge={bot.avatar_eyes_large}
            state={state}
            size={30}
            computerActive={computerActive}
          />
          {bot.unread_count > 0 && (
            <span
              className="absolute top-1 right-1 min-w-[15px] h-[15px] px-1 rounded-full text-[10px] font-semibold flex items-center justify-center text-white"
              style={{ backgroundColor: 'var(--accent-primary)' }}
            >
              {bot.unread_count}
            </span>
          )}
        </button>
      );
    }

    return (
      <div
        key={bot.id}
        onContextMenu={(e) => openContext(e, 'bot', bot.id)}
        className="group flex items-center gap-1.5 px-1.5 py-1 rounded-xl transition-colors select-none"
        style={{
          backgroundColor: isActive ? 'var(--bg-active)' : 'transparent',
        }}
        onMouseEnter={(e) => {
          if (!isActive) e.currentTarget.style.backgroundColor = 'var(--bg-subtle)';
        }}
        onMouseLeave={(e) => {
          if (!isActive) e.currentTarget.style.backgroundColor = 'transparent';
        }}
      >
        {isRenaming ? (
          <div className="flex items-center gap-2.5 flex-1 min-w-0 px-1 py-1">
            <BotAvatar
              shape={bot.avatar_shape}
              color={bot.avatar_color}
              eyesLarge={bot.avatar_eyes_large}
              state={state}
              size={32}
              tooltipText={tooltip}
              computerActive={computerActive}
            />
            <div className="min-w-0 flex-1">
              <input
                type="text"
                autoFocus
                aria-label={`Rename ${bot.name}`}
                value={renameDraft}
                onChange={(e) => setRenameDraft(e.target.value)}
                onClick={(e) => e.stopPropagation()}
                onBlur={() => commitRename('bot', bot.id)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') commitRename('bot', bot.id);
                  if (e.key === 'Escape') setRenamingId(null);
                }}
                className="w-full px-1.5 py-0.5 text-[13px] rounded bg-[var(--bg-canvas)] border border-[var(--border-strong)] outline-none"
              />
              <div
                className="text-[12px] truncate leading-snug mt-0.5"
                style={{
                  color:
                    state === 'waiting_human'
                      ? 'var(--status-warn)'
                      : state === 'error'
                        ? 'var(--status-danger)'
                        : 'var(--text-secondary)',
                }}
              >
                {subtext}
              </div>
            </div>
          </div>
        ) : (
          <button
            type="button"
            aria-label={`${botRowLabel}`}
            onClick={() =>
              setActiveTarget({ kind: 'bot', id: bot.id, threadId: bot.thread_id })
            }
            onDoubleClick={(e) => {
              e.stopPropagation();
              setRenamingId(bot.id);
              setRenameDraft(bot.name);
            }}
            className="flex items-center gap-2.5 flex-1 min-w-0 px-1 py-1 text-left rounded-lg focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-computer)]"
          >
            <BotAvatar
              shape={bot.avatar_shape}
              color={bot.avatar_color}
              eyesLarge={bot.avatar_eyes_large}
              state={state}
              size={32}
              tooltipText={tooltip}
              computerActive={computerActive}
            />

            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-1.5">
                <span
                  className="text-[13px] font-medium truncate leading-tight"
                  style={{ color: 'var(--text-primary)' }}
                >
                  {bot.name}
                </span>
                {bot.is_primary && (
                  <span
                    className="text-[10px] px-1.5 py-0.5 rounded-full font-medium shrink-0"
                    style={{
                      backgroundColor: 'var(--bg-subtle)',
                      color: 'var(--text-muted)',
                    }}
                    title="Primary bot"
                  >
                    Primary
                  </span>
                )}
              </div>
              <div
                className="text-[12px] truncate leading-snug mt-0.5"
                style={{
                  color:
                    state === 'waiting_human'
                      ? 'var(--status-warn)'
                      : state === 'error'
                        ? 'var(--status-danger)'
                        : 'var(--text-secondary)',
                }}
              >
                {subtext}
              </div>
            </div>
          </button>
        )}

        <div className="flex items-center gap-1 shrink-0 pr-1">
          {bot.unread_count > 0 && (
            <span
              className="min-w-[18px] h-[18px] px-1.5 rounded-full text-[11px] font-semibold flex items-center justify-center tabular-nums"
              style={{
                backgroundColor: 'var(--accent-primary)',
                color: 'var(--bg-canvas)',
              }}
            >
              {bot.unread_count}
            </span>
          )}
          <button
            type="button"
            onClick={(e) => openContext(e, 'bot', bot.id)}
            aria-label={`More options for ${bot.name}`}
            aria-haspopup="menu"
            className="opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 focus-visible:opacity-100 p-1 rounded-md hover:bg-[var(--bg-canvas)] transition-opacity"
            style={{ color: 'var(--text-muted)' }}
          >
            <MoreHorizontal size={14} strokeWidth={1.75} />
          </button>
        </div>
      </div>
    );
  };

  const renderChannelRow = (channel: Channel) => {
    const isActive = activeTarget?.kind === 'channel' && activeTarget.id === channel.id;
    const isRenaming = renamingId === channel.id;
    const memberBots = channel.bot_ids
      .map((id) => bots.find((b) => b.id === id))
      .filter((b): b is Bot => Boolean(b));
    const channelRowLabel = `Group chat ${channel.name}`;

    if (compact) {
      return (
        <button
          key={channel.id}
          type="button"
          onClick={() =>
            setActiveTarget({ kind: 'channel', id: channel.id, threadId: channel.thread_id })
          }
          onContextMenu={(e) => openContext(e, 'channel', channel.id)}
          title={`#${channel.name} (${memberBots.length} bots)`}
          aria-label={`Group chat ${channel.name} (${memberBots.length} bots)`}
          className="relative w-11 h-11 mx-auto flex items-center justify-center rounded-xl transition-colors"
          style={{
            backgroundColor: isActive ? 'var(--bg-active)' : 'var(--bg-subtle)',
            color: 'var(--text-secondary)',
          }}
        >
          <Hash size={17} strokeWidth={1.75} />
        </button>
      );
    }

    return (
      <div
        key={channel.id}
        onContextMenu={(e) => openContext(e, 'channel', channel.id)}
        className="group flex items-center gap-1.5 px-1.5 py-1 rounded-xl transition-colors select-none"
        style={{ backgroundColor: isActive ? 'var(--bg-active)' : 'transparent' }}
        onMouseEnter={(e) => {
          if (!isActive) e.currentTarget.style.backgroundColor = 'var(--bg-subtle)';
        }}
        onMouseLeave={(e) => {
          if (!isActive) e.currentTarget.style.backgroundColor = 'transparent';
        }}
      >
        {isRenaming ? (
          <div className="flex items-center gap-2.5 flex-1 min-w-0 px-1 py-1">
            <div
              className="w-8 h-8 rounded-xl flex items-center justify-center shrink-0"
              style={{
                backgroundColor: isActive ? 'var(--bg-canvas)' : 'var(--bg-subtle)',
                color: 'var(--text-secondary)',
              }}
            >
              <Hash size={15} strokeWidth={1.85} />
            </div>
            <div className="min-w-0 flex-1">
              <input
                type="text"
                autoFocus
                aria-label={`Rename group chat ${channel.name}`}
                value={renameDraft}
                onChange={(e) => setRenameDraft(e.target.value)}
                onClick={(e) => e.stopPropagation()}
                onBlur={() => commitRename('channel', channel.id)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') commitRename('channel', channel.id);
                  if (e.key === 'Escape') setRenamingId(null);
                }}
                className="w-full px-1.5 py-0.5 text-[13px] rounded bg-[var(--bg-canvas)] border border-[var(--border-strong)] outline-none"
              />
              <div
                className="text-[11.5px] truncate mt-0.5"
                style={{ color: 'var(--text-muted)' }}
              >
                {memberBots.map((b) => b.name).join(', ') || `${channel.bot_ids.length} bots`}
              </div>
            </div>
          </div>
        ) : (
          <button
            type="button"
            aria-label={`${channelRowLabel}`}
            onClick={() =>
              setActiveTarget({ kind: 'channel', id: channel.id, threadId: channel.thread_id })
            }
            className="flex items-center gap-2.5 flex-1 min-w-0 px-1 py-1 text-left rounded-lg focus:outline-none focus-visible:ring-2 focus-visible:ring-[var(--accent-computer)]"
          >
            <div
              className="w-8 h-8 rounded-xl flex items-center justify-center shrink-0"
              style={{
                backgroundColor: isActive ? 'var(--bg-canvas)' : 'var(--bg-subtle)',
                color: 'var(--text-secondary)',
              }}
            >
              <Hash size={15} strokeWidth={1.85} />
            </div>
            <div className="min-w-0 flex-1">
              <div
                className="text-[13px] font-medium truncate leading-tight"
                style={{ color: 'var(--text-primary)' }}
              >
                {channel.name}
              </div>
              <div
                className="text-[11.5px] truncate mt-0.5"
                style={{ color: 'var(--text-muted)' }}
              >
                {memberBots.map((b) => b.name).join(', ') || `${channel.bot_ids.length} bots`}
              </div>
            </div>
          </button>
        )}
        <button
          type="button"
          onClick={(e) => openContext(e, 'channel', channel.id)}
          aria-label={`More options for ${channel.name}`}
          aria-haspopup="menu"
          className="opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 focus-visible:opacity-100 p-1 mr-1 rounded-md hover:bg-[var(--bg-canvas)] transition-opacity"
          style={{ color: 'var(--text-muted)' }}
        >
          <MoreHorizontal size={14} strokeWidth={1.75} />
        </button>
      </div>
    );
  };

  const contextBot =
    contextMenu?.kind === 'bot' ? bots.find((b) => b.id === contextMenu.id) : null;
  const contextChannel =
    contextMenu?.kind === 'channel'
      ? channels.find((c) => c.id === contextMenu.id)
      : null;
  const unreadTitle = unreadOnly ? 'Showing unread only (click to show all)' : 'Filter unread';
  const unreadLabel = unreadOnly ? 'Show all conversations' : 'Filter unread conversations';
  const sidebarTitle = compact
    ? 'Expand sidebar (Cmd/Ctrl+B)'
    : 'Collapse sidebar (Cmd/Ctrl+B)';
  const sidebarLabel = compact ? 'Expand sidebar' : 'Collapse sidebar';
  const botPinLabel = contextBot?.pinned ? 'Unpin' : 'Pin to top';
  const chanPinLabel = contextChannel?.pinned ? 'Unpin' : 'Pin to top';
  const contextMenuLabel = contextBot
    ? `Actions for ${contextBot.name}`
    : contextChannel
      ? `Actions for ${contextChannel.name}`
      : 'Context menu';

  return (
    <aside
      className="h-full flex flex-col select-none"
      style={{
        backgroundColor: 'var(--bg-sidebar)',
        borderRight: '1px solid var(--border-subtle)',
      }}
    >
      {/* Top Bar */}
      <div
        className={`flex items-center ${compact ? 'flex-col gap-2 py-3 px-2' : 'justify-between px-3 py-2.5'}`}
        style={{ borderBottom: '1px solid var(--border-subtle)' }}
      >
        {!compact ? (
          <div className="flex items-center gap-2 min-w-0">
            <BotAvatar shape="sparkle" color="#111318" size={22} />
            <h2
              className="m-0 text-[14px] font-semibold tracking-tight truncate"
              style={{ color: 'var(--text-primary)' }}
            >
              Grok Bot
            </h2>
          </div>
        ) : (
          <h2 className="sr-only">Grok Bot</h2>
        )}

        <div className={`flex items-center ${compact ? 'flex-col gap-1.5' : 'gap-1'}`}>
          <button
            type="button"
            onClick={toggleUnreadOnly}
            title={`${unreadTitle}`}
            aria-label={`${unreadLabel}`}
            aria-pressed={unreadOnly}
            className="p-1.5 rounded-lg transition-colors"
            style={{
              backgroundColor: unreadOnly ? 'var(--bg-active)' : 'transparent',
              color: unreadOnly ? 'var(--accent-computer)' : 'var(--text-secondary)',
            }}
          >
            <BellDot size={16} strokeWidth={1.75} />
          </button>

          <div className="relative" ref={plusRef}>
            <button
              ref={plusTriggerRef}
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                setPlusMenuOpen((v) => !v);
              }}
              title="New bot, group chat, or section (Cmd/Ctrl+N)"
              aria-label="New bot, group chat, or section"
              aria-haspopup="menu"
              aria-expanded={plusMenuOpen}
              className="p-1.5 rounded-lg transition-colors hover:bg-[var(--bg-subtle)]"
              style={{ color: 'var(--text-primary)' }}
            >
              <Plus size={17} strokeWidth={1.9} />
            </button>

            {plusMenuOpen && (
              <div
                role="menu"
                aria-label="New item menu"
                className="absolute left-0 sm:right-0 sm:left-auto top-full mt-1 w-48 py-1 rounded-xl z-40"
                style={{
                  backgroundColor: 'var(--bg-elevated)',
                  border: '1px solid var(--border-strong)',
                  boxShadow: 'var(--shadow-md)',
                }}
              >
                <button
                  type="button"
                  onClick={() => {
                    setPlusMenuOpen(false);
                    setCreateBotOpen(true);
                  }}
                  className="w-full flex items-center justify-between px-3 py-2 text-[13px] hover:bg-[var(--bg-subtle)]"
                >
                  <span className="inline-flex items-center gap-2">
                    <Plus size={14} strokeWidth={1.75} />
                    New bot
                  </span>
                  <span className="text-[11px]" style={{ color: 'var(--text-muted)' }}>
                    ⌘N
                  </span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setPlusMenuOpen(false);
                    setCreateChannelOpen(true);
                  }}
                  className="w-full flex items-center justify-between px-3 py-2 text-[13px] hover:bg-[var(--bg-subtle)]"
                >
                  <span className="inline-flex items-center gap-2">
                    <Users size={14} strokeWidth={1.75} />
                    New group chat
                  </span>
                  <span className="text-[11px]" style={{ color: 'var(--text-muted)' }}>
                    ⇧⌘N
                  </span>
                </button>
                <button
                  type="button"
                  onClick={() => {
                    setPlusMenuOpen(false);
                    if (compact) toggleSidebar();
                    setCreatingSection(true);
                  }}
                  className="w-full flex items-center gap-2 px-3 py-2 text-[13px] hover:bg-[var(--bg-subtle)]"
                >
                  <FolderPlus size={14} strokeWidth={1.75} />
                  New section
                </button>
              </div>
            )}
          </div>

          <button
            type="button"
            onClick={toggleSidebar}
            title={`${sidebarTitle}`}
            aria-label={`${sidebarLabel}`}
            className="p-1.5 rounded-lg transition-colors hover:bg-[var(--bg-subtle)]"
            style={{ color: 'var(--text-secondary)' }}
          >
            {compact ? (
              <PanelLeftOpen size={16} strokeWidth={1.75} />
            ) : (
              <PanelLeftClose size={16} strokeWidth={1.75} />
            )}
          </button>
        </div>
      </div>

      {/* Search trigger */}
      <div className={compact ? 'px-2 pt-2' : 'px-3 pt-2.5 pb-1'}>
        {compact ? (
          <button
            type="button"
            onClick={() => openCommandPalette('all')}
            title="Search & commands (Cmd/Ctrl+K)"
            aria-label="Search and commands"
            className="w-10 h-9 mx-auto flex items-center justify-center rounded-lg hover:bg-[var(--bg-subtle)]"
            style={{ color: 'var(--text-secondary)' }}
          >
            <Search size={16} strokeWidth={1.75} />
          </button>
        ) : (
          <button
            type="button"
            onClick={() => openCommandPalette('all')}
            className="w-full flex items-center justify-between px-2.5 py-1.5 rounded-lg text-[12.5px] transition-colors hover:bg-[var(--bg-active)]"
            style={{
              backgroundColor: 'var(--bg-subtle)',
              color: 'var(--text-secondary)',
            }}
          >
            <span className="inline-flex items-center gap-2">
              <Search size={14} strokeWidth={1.75} />
              Search or jump…
            </span>
            <kbd
              className="text-[11px] font-mono px-1.5 py-0.5 rounded"
              style={{
                backgroundColor: 'var(--bg-canvas)',
                border: '1px solid var(--border-subtle)',
                color: 'var(--text-muted)',
              }}
            >
              ⌘K
            </kbd>
          </button>
        )}
      </div>

      {/* Inline new section input */}
      {creatingSection && !compact && (
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (newSectionName.trim()) {
              createSectionMutation.mutate(newSectionName.trim());
            }
          }}
          className="px-3 pt-2"
        >
          <input
            type="text"
            autoFocus
            aria-label="New section name"
            value={newSectionName}
            onChange={(e) => setNewSectionName(e.target.value)}
            onBlur={() => {
              if (!newSectionName.trim()) setCreatingSection(false);
            }}
            onKeyDown={(e) => {
              if (e.key === 'Escape') {
                setCreatingSection(false);
                setNewSectionName('');
              }
            }}
            placeholder="Section name, press Enter…"
            className="w-full px-2.5 py-1.5 text-[12.5px] rounded-lg outline-none"
            style={{
              backgroundColor: 'var(--bg-canvas)',
              border: '1px solid var(--border-strong)',
            }}
          />
        </form>
      )}

      {/* Scrollable Roster */}
      <div className={`flex-1 overflow-y-auto ${compact ? 'py-2 space-y-1.5' : 'px-2 py-2 space-y-4'}`}>
        {/* Pinned */}
        {(pinnedBots.length > 0 || pinnedChannels.length > 0) && (
          <div>
            {!compact && (
              <h3
                className="m-0 px-2.5 pb-1 text-[11px] font-medium uppercase tracking-wider"
                style={{ color: 'var(--text-muted)' }}
              >
                Pinned
              </h3>
            )}
            <div className="space-y-0.5">
              {pinnedBots.map(renderBotRow)}
              {pinnedChannels.map(renderChannelRow)}
            </div>
          </div>
        )}

        {/* Custom Sections */}
        {sections.map((section) => {
          const secBots = unpinnedBots.filter((b) => b.section_id === section.id);
          const secChannels = unpinnedChannels.filter((c) => c.section_id === section.id);
          const collapsed = Boolean(collapsedSections[section.id]);

          if (compact) {
            return (
              <div key={section.id} className="space-y-1">
                {secBots.map(renderBotRow)}
                {secChannels.map(renderChannelRow)}
              </div>
            );
          }

          return (
            <div key={section.id}>
              <div className="group flex items-center justify-between gap-1 px-2 pb-1">
                {renamingId === section.id ? (
                  <input
                    type="text"
                    autoFocus
                    aria-label="Rename section"
                    value={renameDraft}
                    onChange={(e) => setRenameDraft(e.target.value)}
                    onBlur={() => commitRename('section', section.id)}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') commitRename('section', section.id);
                      if (e.key === 'Escape') setRenamingId(null);
                    }}
                    className="flex-1 px-1.5 py-0.5 text-[11px] font-medium uppercase tracking-wider rounded bg-[var(--bg-canvas)] border border-[var(--border-strong)] outline-none"
                  />
                ) : (
                  <>
                    <button
                      type="button"
                      aria-label={`Toggle section ${section.name}`}
                      onClick={() =>
                        setCollapsedSections((prev) => ({
                          ...prev,
                          [section.id]: !prev[section.id],
                        }))
                      }
                      className="inline-flex items-center gap-1 min-w-0 text-[11px] font-medium uppercase tracking-wider hover:text-[var(--text-primary)]"
                      style={{ color: 'var(--text-muted)' }}
                    >
                      {collapsed ? <ChevronRight size={12} /> : <ChevronDown size={12} />}
                      <span className="truncate">{section.name}</span>
                    </button>
                    <div className="flex items-center gap-0.5 shrink-0">
                      <button
                        type="button"
                        onClick={() => {
                          setRenamingId(section.id);
                          setRenameDraft(section.name);
                        }}
                        title="Rename section"
                        aria-label={`Rename section ${section.name}`}
                        className="opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 focus-visible:opacity-100 p-0.5 rounded hover:bg-[var(--bg-subtle)]"
                        style={{ color: 'var(--text-muted)' }}
                      >
                        <Pencil size={12} strokeWidth={1.75} />
                      </button>
                      <button
                        type="button"
                        onClick={() => deleteSectionMutation.mutate(section.id)}
                        title="Delete section"
                        aria-label={`Delete section ${section.name}`}
                        className="opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 focus-visible:opacity-100 p-0.5 rounded hover:bg-[var(--bg-subtle)]"
                        style={{ color: 'var(--text-muted)' }}
                      >
                        <Trash2 size={12} strokeWidth={1.75} />
                      </button>
                    </div>
                  </>
                )}
              </div>
              {!collapsed && (
                <div className="space-y-0.5">
                  {secBots.map(renderBotRow)}
                  {secChannels.map(renderChannelRow)}
                  {secBots.length === 0 && secChannels.length === 0 && (
                    <div
                      className="px-3 py-1 text-[11.5px]"
                      style={{ color: 'var(--text-muted)' }}
                    >
                      Right-click a bot to move here
                    </div>
                  )}
                </div>
              )}
            </div>
          );
        })}

        {/* Direct bots */}
        {directBotsNoSection.length > 0 && (
          <div>
            {!compact && (
              <h3
                className="m-0 px-2.5 pb-1 text-[11px] font-medium uppercase tracking-wider"
                style={{ color: 'var(--text-muted)' }}
              >
                Bots
              </h3>
            )}
            <div className="space-y-0.5">{directBotsNoSection.map(renderBotRow)}</div>
          </div>
        )}

        {/* Group chats */}
        {channelsNoSection.length > 0 && (
          <div>
            {!compact && (
              <h3
                className="m-0 px-2.5 pb-1 text-[11px] font-medium uppercase tracking-wider"
                style={{ color: 'var(--text-muted)' }}
              >
                Group chats
              </h3>
            )}
            <div className="space-y-0.5">{channelsNoSection.map(renderChannelRow)}</div>
          </div>
        )}

        {visibleBots.length === 0 && visibleChannels.length === 0 && !compact && (
          <div className="px-3 py-6 text-center">
            <div className="text-[13px]" style={{ color: 'var(--text-secondary)' }}>
              {unreadOnly ? 'No unread conversations' : 'No bots yet'}
            </div>
            {unreadOnly ? (
              <button
                type="button"
                onClick={toggleUnreadOnly}
                className="mt-2 text-[12px] font-medium underline"
                style={{ color: 'var(--accent-computer)' }}
              >
                Show all bots
              </button>
            ) : (
              <button
                type="button"
                onClick={() => setCreateBotOpen(true)}
                className="mt-2 px-3 py-1.5 text-[12.5px] font-medium rounded-lg"
                style={{
                  backgroundColor: 'var(--accent-primary)',
                  color: 'var(--bg-canvas)',
                }}
              >
                Create first bot
              </button>
            )}
          </div>
        )}
      </div>

      {/* Footer Navigation */}
      <div
        className={`shrink-0 ${compact ? 'py-2 px-2 flex flex-col items-center gap-1' : 'p-2 space-y-0.5'}`}
        style={{ borderTop: '1px solid var(--border-subtle)' }}
      >
        <button
          type="button"
          onClick={() => setConnectAppsOpen(true)}
          title="Connect apps"
          aria-label="Connect apps"
          className={`${compact ? 'w-10 h-9 justify-center' : 'w-full px-2.5 py-1.5 justify-start'} flex items-center gap-2 rounded-lg text-[12.5px] transition-colors hover:bg-[var(--bg-subtle)]`}
          style={{ color: 'var(--text-secondary)' }}
        >
          <Plug size={15} strokeWidth={1.75} />
          {!compact && <span>Connect apps</span>}
        </button>

        <button
          type="button"
          onClick={() => setMemoryOpen(true)}
          title="Memory"
          aria-label="Memory"
          className={`${compact ? 'w-10 h-9 justify-center' : 'w-full px-2.5 py-1.5 justify-start'} flex items-center gap-2 rounded-lg text-[12.5px] transition-colors hover:bg-[var(--bg-subtle)]`}
          style={{ color: 'var(--text-secondary)' }}
        >
          <Database size={15} strokeWidth={1.75} />
          {!compact && <span>Memory</span>}
        </button>

        <button
          type="button"
          onClick={() => setHiddenBotsOpen(true)}
          title="Hidden bots"
          aria-label="Hidden bots"
          className={`${compact ? 'w-10 h-9 justify-center' : 'w-full px-2.5 py-1.5 justify-between'} flex items-center rounded-lg text-[12.5px] transition-colors hover:bg-[var(--bg-subtle)]`}
          style={{ color: 'var(--text-secondary)' }}
        >
          <span className="inline-flex items-center gap-2">
            <EyeOff size={15} strokeWidth={1.75} />
            {!compact && <span>Hidden bots</span>}
          </span>
          {!compact && hiddenCount > 0 && (
            <span
              className="text-[11px] px-1.5 rounded-full tabular-nums"
              style={{ backgroundColor: 'var(--bg-subtle)', color: 'var(--text-muted)' }}
            >
              {hiddenCount}
            </span>
          )}
        </button>

        <div className={`flex ${compact ? 'flex-col items-center gap-1' : 'items-center gap-1'}`}>
          <button
            type="button"
            onClick={() => openSettings('general')}
            title="Settings (Cmd/Ctrl+,)"
            aria-label="Settings"
            className={`${compact ? 'w-10 h-9 justify-center' : 'flex-1 px-2.5 py-1.5 justify-start'} flex items-center gap-2 rounded-lg text-[12.5px] transition-colors hover:bg-[var(--bg-subtle)]`}
            style={{ color: 'var(--text-secondary)' }}
          >
            <Settings size={15} strokeWidth={1.75} />
            {!compact && <span>Settings</span>}
          </button>

          <button
            type="button"
            onClick={() => setShortcutsOpen(true)}
            title="Keyboard shortcuts (Cmd/Ctrl+/)"
            aria-label="Keyboard shortcuts"
            className="p-2 rounded-lg transition-colors hover:bg-[var(--bg-subtle)]"
            style={{ color: 'var(--text-secondary)' }}
          >
            <Keyboard size={15} strokeWidth={1.75} />
          </button>
        </div>
      </div>

      {/* Floating Context Menu */}
      {contextMenu && (contextBot || contextChannel) && (
        <div
          ref={contextMenuRef}
          role="menu"
          aria-label={`${contextMenuLabel}`}
          className="fixed z-50 w-52 py-1 rounded-xl text-[13px]"
          style={{
            left: contextMenu.x,
            top: contextMenu.y,
            backgroundColor: 'var(--bg-elevated)',
            border: '1px solid var(--border-strong)',
            boxShadow: 'var(--shadow-lg)',
          }}
          onClick={(e) => e.stopPropagation()}
          onContextMenu={(e) => e.stopPropagation()}
        >
          {contextBot && (
            <>
              <button
                type="button"
                aria-label={`${botPinLabel}`}
                onClick={() => {
                  updateBotMutation.mutate({
                    id: contextBot.id,
                    patch: { pinned: !contextBot.pinned },
                  });
                  setContextMenu(null);
                }}
                className="w-full flex items-center gap-2.5 px-3 py-1.5 hover:bg-[var(--bg-subtle)]"
              >
                {contextBot.pinned ? <PinOff size={14} /> : <Pin size={14} />}
                <span>{contextBot.pinned ? 'Unpin' : 'Pin to top'}</span>
              </button>

              <button
                type="button"
                onClick={() => {
                  setRenamingId(contextBot.id);
                  setRenameDraft(contextBot.name);
                  setContextMenu(null);
                }}
                className="w-full flex items-center gap-2.5 px-3 py-1.5 hover:bg-[var(--bg-subtle)]"
              >
                <Pencil size={14} />
                <span>Rename</span>
              </button>

              {!contextBot.is_primary && !contextBot.is_team_bot && (
                <button
                  type="button"
                  onClick={() => {
                    updateBotMutation.mutate({
                      id: contextBot.id,
                      patch: { is_primary: true },
                    });
                    setContextMenu(null);
                  }}
                  className="w-full flex items-center gap-2.5 px-3 py-1.5 hover:bg-[var(--bg-subtle)]"
                >
                  <Crown size={14} />
                  <span>Make primary</span>
                </button>
              )}

              {sections.length > 0 && (
                <div
                  className="my-1 py-1"
                  style={{
                    borderTop: '1px solid var(--border-subtle)',
                    borderBottom: '1px solid var(--border-subtle)',
                  }}
                >
                  <div
                    className="px-3 py-0.5 text-[11px] font-medium"
                    style={{ color: 'var(--text-muted)' }}
                  >
                    Move to section
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      updateBotMutation.mutate({
                        id: contextBot.id,
                        patch: { section_id: null },
                      });
                      setContextMenu(null);
                    }}
                    className="w-full text-left px-3 py-1 text-[12.5px] hover:bg-[var(--bg-subtle)]"
                  >
                    None {!contextBot.section_id ? '✓' : ''}
                  </button>
                  {sections.map((sec) => (
                    <button
                      key={sec.id}
                      type="button"
                      aria-label={`Move bot to section ${sec.name}`}
                      onClick={() => {
                        updateBotMutation.mutate({
                          id: contextBot.id,
                          patch: { section_id: sec.id },
                        });
                        setContextMenu(null);
                      }}
                      className="w-full text-left px-3 py-1 text-[12.5px] hover:bg-[var(--bg-subtle)] truncate"
                    >
                      {sec.name} {contextBot.section_id === sec.id ? '✓' : ''}
                    </button>
                  ))}
                </div>
              )}

              <button
                type="button"
                onClick={() => {
                  updateBotMutation.mutate({
                    id: contextBot.id,
                    patch: { hidden: true },
                  });
                  setContextMenu(null);
                }}
                className="w-full flex items-center gap-2.5 px-3 py-1.5 hover:bg-[var(--bg-subtle)]"
              >
                <EyeOff size={14} />
                <span>Hide from sidebar</span>
              </button>

              <button
                type="button"
                onClick={() => {
                  setContextMenu(null);
                  deleteBotMutation.mutate(contextBot.id);
                }}
                className="w-full flex items-center gap-2.5 px-3 py-1.5 hover:bg-[var(--status-danger-bg)]"
                style={{ color: 'var(--status-danger)' }}
              >
                <Trash2 size={14} />
                <span>Delete bot</span>
              </button>
            </>
          )}

          {contextChannel && (
            <>
              <button
                type="button"
                aria-label={`${chanPinLabel}`}
                onClick={() => {
                  updateChannelMutation.mutate({
                    id: contextChannel.id,
                    patch: { pinned: !contextChannel.pinned },
                  });
                  setContextMenu(null);
                }}
                className="w-full flex items-center gap-2.5 px-3 py-1.5 hover:bg-[var(--bg-subtle)]"
              >
                {contextChannel.pinned ? <PinOff size={14} /> : <Pin size={14} />}
                <span>{contextChannel.pinned ? 'Unpin' : 'Pin to top'}</span>
              </button>

              <button
                type="button"
                onClick={() => {
                  setRenamingId(contextChannel.id);
                  setRenameDraft(contextChannel.name);
                  setContextMenu(null);
                }}
                className="w-full flex items-center gap-2.5 px-3 py-1.5 hover:bg-[var(--bg-subtle)]"
              >
                <Pencil size={14} />
                <span>Rename</span>
              </button>

              {sections.length > 0 && (
                <div
                  className="my-1 py-1"
                  style={{
                    borderTop: '1px solid var(--border-subtle)',
                    borderBottom: '1px solid var(--border-subtle)',
                  }}
                >
                  <div
                    className="px-3 py-0.5 text-[11px] font-medium"
                    style={{ color: 'var(--text-muted)' }}
                  >
                    Move to section
                  </div>
                  <button
                    type="button"
                    onClick={() => {
                      updateChannelMutation.mutate({
                        id: contextChannel.id,
                        patch: { section_id: null },
                      });
                      setContextMenu(null);
                    }}
                    className="w-full text-left px-3 py-1 text-[12.5px] hover:bg-[var(--bg-subtle)]"
                  >
                    None {!contextChannel.section_id ? '✓' : ''}
                  </button>
                  {sections.map((sec) => (
                    <button
                      key={sec.id}
                      type="button"
                      aria-label={`Move group chat to section ${sec.name}`}
                      onClick={() => {
                        updateChannelMutation.mutate({
                          id: contextChannel.id,
                          patch: { section_id: sec.id },
                        });
                        setContextMenu(null);
                      }}
                      className="w-full text-left px-3 py-1 text-[12.5px] hover:bg-[var(--bg-subtle)] truncate"
                    >
                      {sec.name} {contextChannel.section_id === sec.id ? '✓' : ''}
                    </button>
                  ))}
                </div>
              )}

              <button
                type="button"
                onClick={() => {
                  updateChannelMutation.mutate({
                    id: contextChannel.id,
                    patch: { hidden: true },
                  });
                  setContextMenu(null);
                }}
                className="w-full flex items-center gap-2.5 px-3 py-1.5 hover:bg-[var(--bg-subtle)]"
              >
                <EyeOff size={14} />
                <span>Hide from sidebar</span>
              </button>

              <button
                type="button"
                onClick={() => {
                  setContextMenu(null);
                  deleteChannelMutation.mutate(contextChannel.id);
                }}
                className="w-full flex items-center gap-2.5 px-3 py-1.5 hover:bg-[var(--status-danger-bg)]"
                style={{ color: 'var(--status-danger)' }}
              >
                <Trash2 size={14} />
                <span>Delete group chat</span>
              </button>
            </>
          )}
        </div>
      )}
    </aside>
  );
};
