import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  BookOpen,
  CalendarClock,
  Database,
  FileText,
  Hash,
  Keyboard,
  MessageSquare,
  Monitor,
  PanelLeft,
  PanelRight,
  Plug,
  Plus,
  Search,
  Settings,
  Users,
} from 'lucide-react';
import { searchApi } from '../../lib/api';
import type { Bot, Channel } from '../../lib/types';
import { useUiStore } from '../../stores/uiStore';
import { BotAvatar } from '../../features/roster/BotAvatar';

interface CommandPaletteProps {
  bots: Bot[];
  channels: Channel[];
}

interface PaletteEntry {
  id: string;
  group: string;
  label: string;
  sublabel?: string;
  icon: React.ReactNode;
  onSelect: () => void;
}

export const CommandPalette: React.FC<CommandPaletteProps> = ({ bots, channels }) => {
  const open = useUiStore((s) => s.commandPaletteOpen);
  const mode = useUiStore((s) => s.commandPaletteMode);
  const closeCommandPalette = useUiStore((s) => s.closeCommandPalette);
  const setActiveTarget = useUiStore((s) => s.setActiveTarget);
  const setActivePageId = useUiStore((s) => s.setActivePageId);
  const setCreateBotOpen = useUiStore((s) => s.setCreateBotOpen);
  const setCreateChannelOpen = useUiStore((s) => s.setCreateChannelOpen);
  const toggleSidebar = useUiStore((s) => s.toggleSidebar);
  const toggleInspector = useUiStore((s) => s.toggleInspector);
  const openInspectorTab = useUiStore((s) => s.openInspectorTab);
  const openSettings = useUiStore((s) => s.openSettings);
  const setConnectAppsOpen = useUiStore((s) => s.setConnectAppsOpen);
  const setMemoryOpen = useUiStore((s) => s.setMemoryOpen);
  const setShortcutsOpen = useUiStore((s) => s.setShortcutsOpen);

  const [query, setQuery] = useState('');
  const [activeIdx, setActiveIdx] = useState(0);
  const dialogRef = useRef<HTMLDivElement | null>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);
  const wasOpenRef = useRef(false);
  const focusRestoredRef = useRef(false);
  const itemRefs = useRef<(HTMLButtonElement | null)[]>([]);

  if (open && !wasOpenRef.current) {
    focusRestoredRef.current = false;
    const active = document.activeElement;
    if (
      active instanceof HTMLElement &&
      (!dialogRef.current || !dialogRef.current.contains(active))
    ) {
      previousFocusRef.current = active;
    }
  }

  const restoreFocusBeforeClose = useCallback(() => {
    focusRestoredRef.current = true;
    const restoreTarget = previousFocusRef.current;
    previousFocusRef.current = null;
    if (
      restoreTarget &&
      restoreTarget.isConnected &&
      restoreTarget !== document.body &&
      restoreTarget !== document.documentElement
    ) {
      restoreTarget.focus();
    } else {
      const fallback = document.querySelector<HTMLElement>(
        'textarea[aria-label="Message composer"], button[aria-label="Search and commands"]',
      );
      fallback?.focus();
    }
  }, []);

  const close = useCallback(() => {
    restoreFocusBeforeClose();
    closeCommandPalette();
  }, [restoreFocusBeforeClose, closeCommandPalette]);

  const closeRef = useRef(close);
  closeRef.current = close;

  useEffect(() => {
    if (open) {
      setQuery('');
      setActiveIdx(0);
    }
  }, [open, mode]);

  useEffect(() => {
    wasOpenRef.current = open;
    if (!open) return;
    if (!previousFocusRef.current) {
      const prev = document.activeElement instanceof HTMLElement ? document.activeElement : null;
      if (prev && (!dialogRef.current || !dialogRef.current.contains(prev))) {
        previousFocusRef.current = prev;
      }
    }

    const onKeyDown = (e: KeyboardEvent) => {
      if (e.isComposing) return;
      if (e.key === 'Escape') {
        e.preventDefault();
        e.stopPropagation();
        closeRef.current();
        return;
      }
      if ((e.metaKey || e.ctrlKey) && !e.shiftKey && !e.altKey && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        e.stopPropagation();
        closeRef.current();
        return;
      }
      if (e.key === 'Tab') {
        const root = dialogRef.current;
        if (!root) return;
        const focusables = Array.from(
          root.querySelectorAll<HTMLElement>(
            'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])',
          ),
        ).filter((el) => !el.hasAttribute('disabled') && el.getClientRects().length > 0);
        if (focusables.length === 0) {
          e.preventDefault();
          root.focus();
          return;
        }
        const first = focusables[0];
        const last = focusables[focusables.length - 1];
        if (!first || !last) return;
        const active = document.activeElement;
        if (e.shiftKey) {
          if (active === first || active === root || !root.contains(active)) {
            e.preventDefault();
            last.focus();
          }
        } else if (active === last || !root.contains(active)) {
          e.preventDefault();
          first.focus();
        }
      }
    };
    window.addEventListener('keydown', onKeyDown, true);
    return () => {
      window.removeEventListener('keydown', onKeyDown, true);
      const restoreTarget = previousFocusRef.current;
      previousFocusRef.current = null;
      const alreadyRestored = focusRestoredRef.current;
      focusRestoredRef.current = false;
      if (!alreadyRestored && !document.querySelector('[role="dialog"][aria-modal="true"]')) {
        if (
          restoreTarget &&
          restoreTarget.isConnected &&
          restoreTarget !== document.body &&
          restoreTarget !== document.documentElement
        ) {
          restoreTarget.focus();
        } else {
          const fallback = document.querySelector<HTMLElement>(
            'textarea[aria-label="Message composer"], button[aria-label="Search and commands"]',
          );
          fallback?.focus();
        }
      }
    };
  }, [open]);

  const searchQuery = useQuery({
    queryKey: ['global-search', query],
    queryFn: () => searchApi.query(query.trim()),
    enabled: open && query.trim().length > 0 && mode === 'all',
    staleTime: 10_000,
  });

  const entries: PaletteEntry[] = useMemo(() => {
    const q = query.trim().toLowerCase();
    const list: PaletteEntry[] = [];

    // Bots
    for (const bot of bots.filter((b) => !b.hidden)) {
      if (!q || bot.name.toLowerCase().includes(q) || bot.status_subtext.toLowerCase().includes(q)) {
        list.push({
          id: `bot:${bot.id}`,
          group: 'Bots',
          label: bot.name,
          sublabel: bot.status_subtext || bot.model_id,
          icon: (
            <BotAvatar
              shape={bot.avatar_shape}
              color={bot.avatar_color}
              eyesLarge={bot.avatar_eyes_large}
              size={22}
            />
          ),
          onSelect: () => {
            setActiveTarget({ kind: 'bot', id: bot.id, threadId: bot.thread_id });
            close();
          },
        });
      }
    }

    if (mode === 'bots') {
      return list;
    }

    // Channels
    for (const ch of channels.filter((c) => !c.hidden)) {
      if (!q || ch.name.toLowerCase().includes(q)) {
        list.push({
          id: `ch:${ch.id}`,
          group: 'Group chats',
          label: `#${ch.name}`,
          sublabel: `${ch.bot_ids.length} bots`,
          icon: <Hash size={15} style={{ color: 'var(--text-secondary)' }} />,
          onSelect: () => {
            setActiveTarget({ kind: 'channel', id: ch.id, threadId: ch.thread_id });
            close();
          },
        });
      }
    }

    // Live server search results
    if (searchQuery.data && q) {
      for (const page of searchQuery.data.pages || []) {
        list.push({
          id: `page:${page.id}`,
          group: 'Pages',
          label: page.title,
          sublabel: `Page · v${page.version}`,
          icon: <FileText size={15} style={{ color: 'var(--accent-computer)' }} />,
          onSelect: () => {
            setActivePageId(page.id);
            close();
          },
        });
      }
      for (const msg of (searchQuery.data.messages || []).slice(0, 6)) {
        list.push({
          id: `msg:${msg.id}`,
          group: 'Messages',
          label: `${msg.sender_name}: ${msg.content.slice(0, 70)}`,
          icon: <MessageSquare size={14} style={{ color: 'var(--text-muted)' }} />,
          onSelect: () => {
            const matchedBot = bots.find((b) => b.thread_id === msg.thread_id);
            const matchedCh = channels.find((c) => c.thread_id === msg.thread_id);
            if (matchedBot) {
              setActiveTarget({ kind: 'bot', id: matchedBot.id, threadId: matchedBot.thread_id });
            } else if (matchedCh) {
              setActiveTarget({ kind: 'channel', id: matchedCh.id, threadId: matchedCh.thread_id });
            }
            close();
          },
        });
      }
      for (const rtn of searchQuery.data.routines || []) {
        list.push({
          id: `rtn:${rtn.id}`,
          group: 'Routines',
          label: rtn.name,
          sublabel: rtn.schedule_type === 'cron' ? rtn.cron_expr || 'Scheduled' : 'Webhook',
          icon: <CalendarClock size={14} style={{ color: 'var(--text-secondary)' }} />,
          onSelect: () => {
            const b = bots.find((x) => x.id === rtn.bot_id);
            if (b) {
              setActiveTarget({ kind: 'bot', id: b.id, threadId: b.thread_id });
              openInspectorTab('details');
            }
            close();
          },
        });
      }
      for (const sk of searchQuery.data.skills || []) {
        list.push({
          id: `sk:${sk.id}`,
          group: 'Skills',
          label: sk.name,
          sublabel: sk.description,
          icon: <BookOpen size={14} style={{ color: 'var(--accent-computer)' }} />,
          onSelect: () => {
            openInspectorTab('details');
            close();
          },
        });
      }
    }

    // Commands
    const commands: PaletteEntry[] = [
      {
        id: 'cmd:new-bot',
        group: 'Commands',
        label: 'New bot',
        sublabel: '⌘N',
        icon: <Plus size={15} />,
        onSelect: () => {
          close();
          setCreateBotOpen(true);
        },
      },
      {
        id: 'cmd:new-channel',
        group: 'Commands',
        label: 'New group chat',
        sublabel: '⇧⌘N',
        icon: <Users size={15} />,
        onSelect: () => {
          close();
          setCreateChannelOpen(true);
        },
      },
      {
        id: 'cmd:computer',
        group: 'Commands',
        label: 'Open Bot Computer',
        icon: <Monitor size={15} style={{ color: 'var(--accent-computer)' }} />,
        onSelect: () => {
          close();
          openInspectorTab('computer');
        },
      },
      {
        id: 'cmd:memory',
        group: 'Commands',
        label: 'Open Memory Browser',
        icon: <Database size={15} style={{ color: 'var(--accent-computer)' }} />,
        onSelect: () => {
          close();
          setMemoryOpen(true);
        },
      },
      {
        id: 'cmd:sidebar',
        group: 'Commands',
        label: 'Toggle compact sidebar',
        sublabel: '⌘B',
        icon: <PanelLeft size={15} />,
        onSelect: () => {
          toggleSidebar();
          close();
        },
      },
      {
        id: 'cmd:inspector',
        group: 'Commands',
        label: 'Toggle details inspector',
        sublabel: '⇧⌘I',
        icon: <PanelRight size={15} />,
        onSelect: () => {
          toggleInspector();
          close();
        },
      },
      {
        id: 'cmd:apps',
        group: 'Commands',
        label: 'Connect apps',
        icon: <Plug size={15} />,
        onSelect: () => {
          close();
          setConnectAppsOpen(true);
        },
      },
      {
        id: 'cmd:settings',
        group: 'Commands',
        label: 'Open Settings',
        sublabel: '⌘,',
        icon: <Settings size={15} />,
        onSelect: () => {
          close();
          openSettings('general');
        },
      },
      {
        id: 'cmd:shortcuts',
        group: 'Commands',
        label: 'Keyboard shortcuts',
        sublabel: '⌘/',
        icon: <Keyboard size={15} />,
        onSelect: () => {
          close();
          setShortcutsOpen(true);
        },
      },
    ];

    for (const cmd of commands) {
      if (!q || cmd.label.toLowerCase().includes(q)) {
        list.push(cmd);
      }
    }

    return list;
  }, [
    bots,
    channels,
    mode,
    query,
    searchQuery.data,
    close,
    openInspectorTab,
    openSettings,
    setActivePageId,
    setActiveTarget,
    setConnectAppsOpen,
    setCreateBotOpen,
    setCreateChannelOpen,
    setMemoryOpen,
    setShortcutsOpen,
    toggleInspector,
    toggleSidebar,
  ]);

  useEffect(() => {
    setActiveIdx(0);
  }, [entries.length, query]);

  useEffect(() => {
    if (!open) return;
    itemRefs.current[activeIdx]?.scrollIntoView?.({ block: 'nearest' });
  }, [open, activeIdx, entries.length]);

  if (!open) return null;

  const dialogLabel = mode === 'bots' ? 'Jump to a bot' : 'Global search and command palette';
  const searchLabel =
    mode === 'bots' ? 'Jump to a bot' : 'Search bots, messages, Pages, routines, or commands';

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[12vh] px-4"
      style={{ backgroundColor: 'rgba(15, 23, 42, 0.36)', backdropFilter: 'blur(2px)' }}
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) {
          e.preventDefault();
          close();
        }
      }}
    >
      <div
        ref={dialogRef}
        tabIndex={-1}
        role="dialog"
        aria-modal="true"
        aria-label={`${dialogLabel}`}
        className="w-full max-w-xl rounded-2xl overflow-hidden outline-none"
        style={{
          backgroundColor: 'var(--bg-elevated)',
          border: '1px solid var(--border-strong)',
          boxShadow: 'var(--shadow-lg)',
        }}
      >
        <div
          className="flex items-center gap-2.5 px-4 py-3"
          style={{ borderBottom: '1px solid var(--border-subtle)' }}
        >
          <Search size={16} style={{ color: 'var(--text-muted)' }} />
          <input
            type="text"
            autoFocus
            aria-label={`${searchLabel}`}
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'ArrowDown' && entries.length > 0) {
                e.preventDefault();
                setActiveIdx((i) => (i + 1) % entries.length);
              } else if (e.key === 'ArrowUp' && entries.length > 0) {
                e.preventDefault();
                setActiveIdx((i) => (i - 1 + entries.length) % entries.length);
              } else if (e.key === 'Enter') {
                const selectedEntry = entries[activeIdx];
                if (selectedEntry) {
                  e.preventDefault();
                  selectedEntry.onSelect();
                }
              } else if (e.key === 'Escape') {
                e.preventDefault();
                e.stopPropagation();
                close();
              }
            }}
            placeholder={
              mode === 'bots'
                ? 'Jump directly to a bot…'
                : 'Search bots, messages, Pages, routines, or commands…'
            }
            className="flex-1 text-[14px] bg-transparent outline-none"
          />
          <kbd
            className="text-[11px] font-mono px-1.5 py-0.5 rounded"
            style={{
              backgroundColor: 'var(--bg-subtle)',
              color: 'var(--text-muted)',
            }}
          >
            ESC
          </kbd>
        </div>

        <div className="max-h-[55vh] overflow-y-auto p-2 space-y-1">
          {entries.length === 0 ? (
            <div className="py-10 text-center text-[13px]" style={{ color: 'var(--text-muted)' }}>
              No matching results
            </div>
          ) : (
            entries.map((item, idx) => {
              const prevEntry = idx > 0 ? entries[idx - 1] : undefined;
              const showGroup = !prevEntry || prevEntry.group !== item.group;
              const selected = idx === activeIdx;
              return (
                <React.Fragment key={item.id}>
                  {showGroup && (
                    <div
                      className="px-2.5 pt-2 pb-1 text-[11px] font-medium uppercase tracking-wider"
                      style={{ color: 'var(--text-muted)' }}
                    >
                      {item.group}
                    </div>
                  )}
                  <button
                    ref={(el) => {
                      itemRefs.current[idx] = el;
                    }}
                    type="button"
                    aria-label={`${item.label}`}
                    onMouseEnter={() => setActiveIdx(idx)}
                    onClick={item.onSelect}
                    className="w-full flex items-center justify-between gap-3 px-2.5 py-2 rounded-xl text-left transition-colors"
                    style={{
                      backgroundColor: selected ? 'var(--bg-active)' : 'transparent',
                    }}
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      <span className="shrink-0">{item.icon}</span>
                      <div className="min-w-0">
                        <div
                          className="text-[13.5px] font-medium truncate"
                          style={{ color: 'var(--text-primary)' }}
                        >
                          {item.label}
                        </div>
                        {item.sublabel && item.group !== 'Commands' && (
                          <div
                            className="text-[11.5px] truncate"
                            style={{ color: 'var(--text-muted)' }}
                          >
                            {item.sublabel}
                          </div>
                        )}
                      </div>
                    </div>
                    {item.group === 'Commands' && item.sublabel && (
                      <kbd
                        className="text-[11px] font-mono px-1.5 py-0.5 rounded shrink-0"
                        style={{
                          backgroundColor: 'var(--bg-subtle)',
                          color: 'var(--text-muted)',
                        }}
                      >
                        {item.sublabel}
                      </kbd>
                    )}
                  </button>
                </React.Fragment>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
};
