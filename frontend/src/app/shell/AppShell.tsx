import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { Panel, PanelGroup, PanelResizeHandle } from 'react-resizable-panels';
import { botsApi, settingsApi, threadsApi } from '../../lib/api';
import { startSseBridge } from '../../lib/sse';
import type { Message } from '../../lib/types';
import { useHitlStore } from '../../stores/hitlStore';
import { usePresenceStore } from '../../stores/presenceStore';
import { applyThemeToDocument, useUiStore } from '../../stores/uiStore';
import { ToastHost } from '../../components/ToastHost';
import { MediaLightbox } from '../../features/artifacts/MediaLightbox';
import { ChatHeader } from '../../features/chat/ChatHeader';
import { ComposerBox } from '../../features/chat/ComposerBox';
import { TranscriptViewport } from '../../features/chat/TranscriptViewport';
import { FullScreenTakeoverModal } from '../../features/computer/FullScreenTakeoverModal';
import { InspectorPanel } from '../../features/computer/InspectorPanel';
import { MemoryModal } from '../../features/memory/MemoryModal';
import { BotRosterSidebar } from '../../features/roster/BotRosterSidebar';
import { CreateBotModal } from '../../features/roster/CreateBotModal';
import { CreateChannelModal } from '../../features/roster/CreateChannelModal';
import { HiddenBotsDrawer } from '../../features/roster/HiddenBotsDrawer';
import { ConnectAppsModal } from '../../features/settings/ConnectAppsModal';
import { SettingsDialog } from '../../features/settings/SettingsDialog';
import { ShortcutsDialog } from '../../features/settings/ShortcutsDialog';
import { CommandPalette } from './CommandPalette';
import { GlobalDropOverlay } from './GlobalDropOverlay';
import { SplitPageWorkspace } from './SplitPageWorkspace';

export const AppShell: React.FC = () => {
  const queryClient = useQueryClient();

  const theme = useUiStore((s) => s.theme);
  const setTheme = useUiStore((s) => s.setTheme);
  const setAccentMode = useUiStore((s) => s.setAccentMode);
  const sidebarCollapsed = useUiStore((s) => s.sidebarCollapsed);
  const inspectorOpen = useUiStore((s) => s.inspectorOpen);
  const activeTarget = useUiStore((s) => s.activeTarget);
  const setActiveTarget = useUiStore((s) => s.setActiveTarget);
  const activePageId = useUiStore((s) => s.activePageId);

  const seedPresence = usePresenceStore((s) => s.seedFromBots);
  const seedHitlThread = useHitlStore((s) => s.seedThread);

  const [olderMessagesByThread, setOlderMessagesByThread] = useState<Record<string, Message[]>>({});
  const [loadingMore, setLoadingMore] = useState(false);
  const threadFetchStartedAtRef = useRef<Record<string, number>>({});

  // Start multiplexed SSE connection once
  useEffect(() => {
    const stop = startSseBridge(queryClient);
    return stop;
  }, [queryClient]);

  // Listen to OS theme changes when theme === 'system'
  useEffect(() => {
    applyThemeToDocument(theme);
    if (theme !== 'system') return;
    const mq = window.matchMedia?.('(prefers-color-scheme: dark)');
    if (!mq) return;
    const listener = () => applyThemeToDocument('system');
    mq.addEventListener('change', listener);
    return () => mq.removeEventListener('change', listener);
  }, [theme]);

  // Hydrate settings from backend on startup
  const settingsQuery = useQuery({
    queryKey: ['settings'],
    queryFn: () => settingsApi.get(),
    staleTime: 60_000,
  });

  useEffect(() => {
    const data = settingsQuery.data;
    if (!data) return;
    if (data.theme && ['light', 'dark', 'system'].includes(data.theme)) {
      setTheme(data.theme);
    }
    if (data.accent_mode && ['bot_color', 'black'].includes(data.accent_mode)) {
      setAccentMode(data.accent_mode);
    }
  }, [settingsQuery.data, setTheme, setAccentMode]);

  // Load Roster (Bots, Sections, Channels)
  const rosterQuery = useQuery({
    queryKey: ['roster'],
    queryFn: () => botsApi.list(),
    refetchInterval: 30_000,
  });

  const bots = useMemo(() => rosterQuery.data?.bots ?? [], [rosterQuery.data?.bots]);
  const sections = useMemo(() => rosterQuery.data?.sections ?? [], [rosterQuery.data?.sections]);
  const channels = useMemo(() => rosterQuery.data?.channels ?? [], [rosterQuery.data?.channels]);

  useEffect(() => {
    if (bots.length > 0) {
      seedPresence(bots);
    }
  }, [bots, seedPresence]);

  // Auto-select Primary or first visible bot on initial load
  useEffect(() => {
    if (activeTarget) return;
    const visible = bots.filter((b) => !b.hidden);
    if (visible.length === 0) return;
    const primary = visible.find((b) => b.is_primary) || visible[0];
    if (!primary) return;
    setActiveTarget({ kind: 'bot', id: primary.id, threadId: primary.thread_id });
  }, [activeTarget, bots, setActiveTarget]);

  const activeBot = useMemo(
    () =>
      activeTarget?.kind === 'bot'
        ? bots.find((b) => b.id === activeTarget.id) ?? null
        : null,
    [activeTarget, bots],
  );

  const activeChannel = useMemo(
    () =>
      activeTarget?.kind === 'channel'
        ? channels.find((c) => c.id === activeTarget.id) ?? null
        : null,
    [activeTarget, channels],
  );

  const activeThreadId = activeTarget?.threadId ?? null;

  // Load active thread messages & HITL cards
  const threadQuery = useQuery({
    queryKey: ['thread-messages', activeThreadId],
    queryFn: async () => {
      const tid = activeThreadId!;
      threadFetchStartedAtRef.current[tid] = Date.now();
      return threadsApi.messages(tid, { limit: 50 });
    },
    enabled: Boolean(activeThreadId),
  });

  useEffect(() => {
    if (activeThreadId && threadQuery.data) {
      seedHitlThread(
        activeThreadId,
        threadQuery.data.approvals ?? [],
        threadQuery.data.drafts ?? [],
        threadQuery.data.secure_forms ?? [],
        { fetchStartedAt: threadFetchStartedAtRef.current[activeThreadId] },
      );
    }
  }, [activeThreadId, threadQuery.data, threadQuery.dataUpdatedAt, seedHitlThread]);

  const mergedMessages = useMemo(() => {
    if (!activeThreadId) return [];
    const older = olderMessagesByThread[activeThreadId] ?? [];
    const current = threadQuery.data?.messages ?? [];
    if (older.length === 0) return current;
    const seen = new Set(current.map((m) => m.id));
    return [...older.filter((m) => !seen.has(m.id)), ...current];
  }, [activeThreadId, olderMessagesByThread, threadQuery.data?.messages]);

  const handleLoadMore = useCallback(async () => {
    const oldestId = mergedMessages[0]?.id;
    if (!activeThreadId || loadingMore || !oldestId) return;
    setLoadingMore(true);
    try {
      const res = await threadsApi.messages(activeThreadId, {
        limit: 50,
        beforeId: oldestId,
      });
      setOlderMessagesByThread((prev) => ({
        ...prev,
        [activeThreadId]: [...res.messages, ...(prev[activeThreadId] ?? [])],
      }));
    } finally {
      setLoadingMore(false);
    }
  }, [activeThreadId, loadingMore, mergedMessages]);

  // Global Keyboard Shortcuts
  useEffect(() => {
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.defaultPrevented || e.isComposing) return;
      const mod = e.metaKey || e.ctrlKey;
      const key = e.key.toLowerCase();
      const ui = useUiStore.getState();

      if (key === 'escape') {
        if (
          ui.commandPaletteOpen ||
          ui.settingsOpen ||
          ui.connectAppsOpen ||
          ui.hiddenBotsOpen ||
          ui.shortcutsOpen ||
          ui.createBotOpen ||
          ui.createChannelOpen ||
          ui.memoryOpen ||
          ui.fullscreenComputerVmId ||
          ui.lightboxArtifact
        ) {
          e.preventDefault();
          ui.closeAllOverlays();
        }
        return;
      }

      const target = e.target;
      const isGuardedTarget =
        target instanceof Element &&
        (Boolean(
          target.closest(
            '.xterm, canvas, input, textarea, select, [contenteditable="true"], [contenteditable=""]',
          ),
        ) ||
          (target instanceof HTMLElement && target.isContentEditable));
      const hasOpenOverlay =
        ui.commandPaletteOpen ||
        ui.settingsOpen ||
        ui.connectAppsOpen ||
        ui.hiddenBotsOpen ||
        ui.shortcutsOpen ||
        ui.createBotOpen ||
        ui.createChannelOpen ||
        ui.memoryOpen ||
        Boolean(ui.fullscreenComputerVmId) ||
        Boolean(ui.lightboxArtifact) ||
        Boolean(document.querySelector('[role="dialog"][aria-modal="true"]'));
      if (e.defaultPrevented || hasOpenOverlay || isGuardedTarget) {
        return;
      }

      if (mod && key === 'k') {
        e.preventDefault();
        if (ui.commandPaletteOpen) ui.closeCommandPalette();
        else ui.openCommandPalette('all');
        return;
      }

      if (mod && e.shiftKey && key === 'f') {
        e.preventDefault();
        ui.openCommandPalette('bots');
        return;
      }

      if (mod && e.shiftKey && key === 'n') {
        e.preventDefault();
        ui.setCreateChannelOpen(true);
        return;
      }

      if (mod && !e.shiftKey && key === 'n') {
        e.preventDefault();
        ui.setCreateBotOpen(true);
        return;
      }

      if (e.ctrlKey && e.altKey && key === 'b') {
        e.preventDefault();
        ui.toggleInspector();
        return;
      }

      if (mod && e.shiftKey && key === 'i') {
        e.preventDefault();
        ui.toggleInspector();
        return;
      }

      if (mod && !e.shiftKey && !e.altKey && key === 'b') {
        e.preventDefault();
        ui.toggleSidebar();
        return;
      }

      if (mod && !e.shiftKey && key === 'i') {
        e.preventDefault();
        ui.requestComposerFocus();
        return;
      }

      if (mod && !e.shiftKey && key === 'd') {
        e.preventDefault();
        ui.requestDictationToggle();
        return;
      }

      if (mod && key === ',') {
        e.preventDefault();
        ui.openSettings('general');
        return;
      }

      if (mod && key === '/') {
        e.preventDefault();
        ui.setShortcutsOpen(!ui.shortcutsOpen);
        return;
      }

      // Cmd/Ctrl + 1..9 jump to bot 1..9
      if (mod && !e.shiftKey && !e.altKey && key >= '1' && key <= '9') {
        const index = Number(key) - 1;
        const visibleBots = bots.filter((b) => !b.hidden);
        const target = visibleBots[index];
        if (target) {
          e.preventDefault();
          ui.setActiveTarget({
            kind: 'bot',
            id: target.id,
            threadId: target.thread_id,
          });
        }
      }
    };

    window.addEventListener('keydown', onKeyDown);
    return () => window.removeEventListener('keydown', onKeyDown);
  }, [bots]);

  const renderChatPane = (pageTitle?: string | null) => {
    if (!activeThreadId) {
      return (
        <div
          className="h-full flex flex-col items-center justify-center p-6 text-center space-y-3"
          style={{ backgroundColor: 'var(--bg-canvas)' }}
        >
          <h1 className="m-0 text-[16px] font-semibold" style={{ color: 'var(--text-primary)' }}>
            Welcome to Grok Bot
          </h1>
          <p className="text-[13.5px] max-w-sm" style={{ color: 'var(--text-secondary)' }}>
            Select a teammate from the sidebar or create a new bot to start working.
          </p>
          <button
            type="button"
            onClick={() => useUiStore.getState().setCreateBotOpen(true)}
            className="px-4 py-2 rounded-lg text-[13px] font-medium"
            style={{
              backgroundColor: 'var(--accent-primary)',
              color: 'var(--bg-canvas)',
            }}
          >
            Create a bot
          </button>
        </div>
      );
    }

    return (
      <section
        className="h-full flex flex-col min-w-0"
        style={{ backgroundColor: 'var(--bg-canvas)' }}
      >
        <ChatHeader
          bot={activeBot}
          channel={activeChannel}
          allBots={bots}
          compact={Boolean(pageTitle)}
        />

        <TranscriptViewport
          threadId={activeThreadId}
          messages={mergedMessages}
          approvals={threadQuery.data?.approvals ?? []}
          drafts={threadQuery.data?.drafts ?? []}
          secureForms={threadQuery.data?.secure_forms ?? []}
          hasMore={Boolean(threadQuery.data?.has_more)}
          loadingMore={loadingMore}
          onLoadMore={() => void handleLoadMore()}
          bot={activeBot}
          allBots={bots}
          isGroupChannel={Boolean(activeChannel)}
          compact={Boolean(pageTitle)}
        />

        <ComposerBox
          threadId={activeThreadId}
          bot={activeBot}
          channel={activeChannel}
          allBots={bots}
          allChannels={channels}
          pageContextTitle={pageTitle}
          pageContextId={activePageId}
        />
      </section>
    );
  };

  return (
    <div
      className="h-screen w-screen flex overflow-hidden"
      style={{ backgroundColor: 'var(--bg-canvas)', color: 'var(--text-primary)' }}
    >
      {/* Compact fixed sidebar (64px) when collapsed */}
      {sidebarCollapsed && (
        <div className="w-16 shrink-0 h-full">
          <BotRosterSidebar
            bots={bots}
            sections={sections}
            channels={channels}
            compact
          />
        </div>
      )}

      {/* Resizable Main Layout */}
      <div className="flex-1 min-w-0 h-full">
        <PanelGroup direction="horizontal" autoSaveId="grokbot-layout-v1">
          {!sidebarCollapsed && (
            <>
              <Panel
                id="roster"
                order={1}
                defaultSize={19}
                minSize={14}
                maxSize={30}
                className="min-w-[220px]"
              >
                <BotRosterSidebar
                  bots={bots}
                  sections={sections}
                  channels={channels}
                  compact={false}
                />
              </Panel>
              <PanelResizeHandle className="resize-handle" aria-label="Resize sidebar" />
            </>
          )}

          <Panel id="center" order={2} minSize={35} className="min-w-0">
            {activePageId ? (
              <SplitPageWorkspace
                pageId={activePageId}
                renderChatPane={(title) => renderChatPane(title)}
              />
            ) : (
              renderChatPane(null)
            )}
          </Panel>

          {inspectorOpen && (
            <>
              <PanelResizeHandle className="resize-handle" aria-label="Resize inspector panel" />
              <Panel
                id="inspector"
                order={3}
                defaultSize={30}
                minSize={22}
                maxSize={48}
                className="min-w-[320px]"
              >
                <InspectorPanel
                  bot={activeBot}
                  channel={activeChannel}
                  allBots={bots}
                />
              </Panel>
            </>
          )}
        </PanelGroup>
      </div>

      {/* Global Modals & Overlays */}
      <CommandPalette bots={bots} channels={channels} />
      <CreateBotModal />
      <CreateChannelModal bots={bots} />
      <HiddenBotsDrawer bots={bots} channels={channels} />
      <SettingsDialog />
      <ConnectAppsModal />
      <MemoryModal />
      <ShortcutsDialog />
      <FullScreenTakeoverModal />
      <MediaLightbox />
      <GlobalDropOverlay activeThreadId={activeThreadId} />
      <ToastHost />
    </div>
  );
};
