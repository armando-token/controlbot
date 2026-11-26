import { create } from 'zustand';
import type {
  AccentMode,
  Artifact,
  Attachment,
  InspectorTab,
  Message,
  ThemeMode,
} from '../lib/types';

export type ActiveTarget =
  | { kind: 'bot'; id: string; threadId: string }
  | { kind: 'channel'; id: string; threadId: string };

export type SettingsTabId = 'general' | 'computer' | 'vault' | 'usage' | 'system';

export interface ToastItem {
  id: string;
  tone: 'info' | 'success' | 'warn' | 'error';
  title: string;
  description?: string;
}

const LS_THEME = 'gb_theme';
const LS_ACCENT = 'gb_accent';
const LS_SIDEBAR = 'gb_sidebar_collapsed';

function readLs<T extends string>(key: string, fallback: T): T {
  try {
    const val = localStorage.getItem(key);
    return (val as T) || fallback;
  } catch {
    return fallback;
  }
}

export function applyThemeToDocument(theme: ThemeMode): void {
  if (typeof document === 'undefined') return;
  let resolved: 'light' | 'dark' = 'light';
  if (theme === 'dark') {
    resolved = 'dark';
  } else if (theme === 'system') {
    resolved = window.matchMedia?.('(prefers-color-scheme: dark)').matches
      ? 'dark'
      : 'light';
  }
  document.documentElement.setAttribute('data-theme', resolved);
}

interface UiState {
  theme: ThemeMode;
  accentMode: AccentMode;
  sidebarCollapsed: boolean;
  inspectorOpen: boolean;
  inspectorTab: InspectorTab;
  activeTarget: ActiveTarget | null;
  activePageId: string | null;
  fullscreenComputerVmId: string | null;
  unreadOnly: boolean;

  commandPaletteOpen: boolean;
  commandPaletteMode: 'all' | 'bots';
  settingsOpen: boolean;
  settingsTab: SettingsTabId;
  connectAppsOpen: boolean;
  hiddenBotsOpen: boolean;
  shortcutsOpen: boolean;
  createBotOpen: boolean;
  createChannelOpen: boolean;
  memoryOpen: boolean;
  lightboxArtifact: Artifact | null;

  composerDraftByThread: Record<string, string>;
  composerAttachmentsByThread: Record<string, Attachment[]>;
  replyToByThread: Record<string, Message | null>;
  composerFocusNonce: number;
  dictationToggleNonce: number;

  toasts: ToastItem[];

  setTheme: (theme: ThemeMode) => void;
  setAccentMode: (mode: AccentMode) => void;
  setSidebarCollapsed: (collapsed: boolean) => void;
  toggleSidebar: () => void;
  setInspectorOpen: (open: boolean) => void;
  toggleInspector: () => void;
  setInspectorTab: (tab: InspectorTab) => void;
  openInspectorTab: (tab: InspectorTab) => void;
  setActiveTarget: (target: ActiveTarget | null) => void;
  setActivePageId: (pageId: string | null) => void;
  setFullscreenComputerVmId: (vmId: string | null) => void;
  toggleUnreadOnly: () => void;

  openCommandPalette: (mode?: 'all' | 'bots') => void;
  closeCommandPalette: () => void;
  openSettings: (tab?: SettingsTabId) => void;
  closeSettings: () => void;
  setSettingsTab: (tab: SettingsTabId) => void;
  setConnectAppsOpen: (open: boolean) => void;
  setHiddenBotsOpen: (open: boolean) => void;
  setShortcutsOpen: (open: boolean) => void;
  setCreateBotOpen: (open: boolean) => void;
  setCreateChannelOpen: (open: boolean) => void;
  setMemoryOpen: (open: boolean) => void;
  setLightboxArtifact: (artifact: Artifact | null) => void;
  closeAllOverlays: () => void;

  setComposerDraft: (threadId: string, text: string) => void;
  appendComposerText: (threadId: string, text: string) => void;
  addComposerAttachment: (threadId: string, attachment: Attachment) => void;
  removeComposerAttachment: (threadId: string, attachmentId: string) => void;
  clearComposerAttachments: (threadId: string) => void;
  setReplyTo: (threadId: string, msg: Message | null) => void;
  requestComposerFocus: () => void;
  requestDictationToggle: () => void;

  pushToast: (toast: Omit<ToastItem, 'id'>) => void;
  dismissToast: (id: string) => void;
}

const initialTheme = readLs<ThemeMode>(LS_THEME, 'light');
applyThemeToDocument(initialTheme);

export const useUiStore = create<UiState>((set) => ({
  theme: initialTheme,
  accentMode: readLs<AccentMode>(LS_ACCENT, 'bot_color'),
  sidebarCollapsed: readLs<string>(LS_SIDEBAR, 'false') === 'true',
  inspectorOpen: false,
  inspectorTab: 'details',
  activeTarget: null,
  activePageId: null,
  fullscreenComputerVmId: null,
  unreadOnly: false,

  commandPaletteOpen: false,
  commandPaletteMode: 'all',
  settingsOpen: false,
  settingsTab: 'general',
  connectAppsOpen: false,
  hiddenBotsOpen: false,
  shortcutsOpen: false,
  createBotOpen: false,
  createChannelOpen: false,
  memoryOpen: false,
  lightboxArtifact: null,

  composerDraftByThread: {},
  composerAttachmentsByThread: {},
  replyToByThread: {},
  composerFocusNonce: 0,
  dictationToggleNonce: 0,

  toasts: [],

  setTheme: (theme) => {
    try {
      localStorage.setItem(LS_THEME, theme);
    } catch {
      // ignore storage failure
    }
    applyThemeToDocument(theme);
    set({ theme });
  },

  setAccentMode: (accentMode) => {
    try {
      localStorage.setItem(LS_ACCENT, accentMode);
    } catch {
      // ignore
    }
    set({ accentMode });
  },

  setSidebarCollapsed: (sidebarCollapsed) => {
    try {
      localStorage.setItem(LS_SIDEBAR, String(sidebarCollapsed));
    } catch {
      // ignore
    }
    set({ sidebarCollapsed });
  },

  toggleSidebar: () =>
    set((s) => {
      const next = !s.sidebarCollapsed;
      try {
        localStorage.setItem(LS_SIDEBAR, String(next));
      } catch {
        // ignore
      }
      return { sidebarCollapsed: next };
    }),

  setInspectorOpen: (inspectorOpen) => set({ inspectorOpen }),
  toggleInspector: () => set((s) => ({ inspectorOpen: !s.inspectorOpen })),
  setInspectorTab: (inspectorTab) => set({ inspectorTab }),
  openInspectorTab: (inspectorTab) => set({ inspectorOpen: true, inspectorTab }),

  setActiveTarget: (activeTarget) =>
    set({
      activeTarget,
      activePageId: null,
    }),

  setActivePageId: (activePageId) => set({ activePageId }),
  setFullscreenComputerVmId: (fullscreenComputerVmId) =>
    set({ fullscreenComputerVmId }),
  toggleUnreadOnly: () => set((s) => ({ unreadOnly: !s.unreadOnly })),

  openCommandPalette: (mode = 'all') =>
    set({ commandPaletteOpen: true, commandPaletteMode: mode }),
  closeCommandPalette: () => set({ commandPaletteOpen: false }),

  openSettings: (tab = 'general') =>
    set({ settingsOpen: true, settingsTab: tab }),
  closeSettings: () => set({ settingsOpen: false }),
  setSettingsTab: (settingsTab) => set({ settingsTab }),

  setConnectAppsOpen: (connectAppsOpen) => set({ connectAppsOpen }),
  setHiddenBotsOpen: (hiddenBotsOpen) => set({ hiddenBotsOpen }),
  setShortcutsOpen: (shortcutsOpen) => set({ shortcutsOpen }),
  setCreateBotOpen: (createBotOpen) => set({ createBotOpen }),
  setCreateChannelOpen: (createChannelOpen) => set({ createChannelOpen }),
  setMemoryOpen: (memoryOpen) => set({ memoryOpen }),
  setLightboxArtifact: (lightboxArtifact) => set({ lightboxArtifact }),

  closeAllOverlays: () =>
    set({
      commandPaletteOpen: false,
      settingsOpen: false,
      connectAppsOpen: false,
      hiddenBotsOpen: false,
      shortcutsOpen: false,
      createBotOpen: false,
      createChannelOpen: false,
      memoryOpen: false,
      lightboxArtifact: null,
      fullscreenComputerVmId: null,
    }),

  setComposerDraft: (threadId, text) =>
    set((s) => ({
      composerDraftByThread: { ...s.composerDraftByThread, [threadId]: text },
    })),

  appendComposerText: (threadId, text) =>
    set((s) => {
      const prev = s.composerDraftByThread[threadId] ?? '';
      const sep = prev && !prev.endsWith(' ') && !prev.endsWith('\n') ? ' ' : '';
      return {
        composerDraftByThread: {
          ...s.composerDraftByThread,
          [threadId]: `${prev}${sep}${text}`,
        },
        composerFocusNonce: s.composerFocusNonce + 1,
      };
    }),

  addComposerAttachment: (threadId, attachment) =>
    set((s) => {
      const existing = s.composerAttachmentsByThread[threadId] ?? [];
      if (existing.some((a) => a.id === attachment.id)) return s;
      return {
        composerAttachmentsByThread: {
          ...s.composerAttachmentsByThread,
          [threadId]: [...existing, attachment],
        },
      };
    }),

  removeComposerAttachment: (threadId, attachmentId) =>
    set((s) => ({
      composerAttachmentsByThread: {
        ...s.composerAttachmentsByThread,
        [threadId]: (s.composerAttachmentsByThread[threadId] ?? []).filter(
          (a) => a.id !== attachmentId,
        ),
      },
    })),

  clearComposerAttachments: (threadId) =>
    set((s) => ({
      composerAttachmentsByThread: {
        ...s.composerAttachmentsByThread,
        [threadId]: [],
      },
    })),

  setReplyTo: (threadId, msg) =>
    set((s) => ({
      replyToByThread: { ...s.replyToByThread, [threadId]: msg },
      composerFocusNonce: msg ? s.composerFocusNonce + 1 : s.composerFocusNonce,
    })),

  requestComposerFocus: () =>
    set((s) => ({ composerFocusNonce: s.composerFocusNonce + 1 })),

  requestDictationToggle: () =>
    set((s) => ({ dictationToggleNonce: s.dictationToggleNonce + 1 })),

  pushToast: (toast) => {
    const id = `toast_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
    set((s) => ({ toasts: [...s.toasts.slice(-4), { ...toast, id }] }));
    window.setTimeout(() => {
      set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) }));
    }, 4500);
  },

  dismissToast: (id) =>
    set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) })),
}));
