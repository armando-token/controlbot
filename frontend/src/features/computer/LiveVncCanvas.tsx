import React, {
  forwardRef,
  useCallback,
  useEffect,
  useImperativeHandle,
  useRef,
  useState,
} from 'react';
import {
  ArrowLeft,
  ArrowRight,
  Globe,
  Loader2,
  Play,
  RefreshCw,
  RotateCw,
  Square,
  WifiOff,
} from 'lucide-react';
import { computerApi, toWsUrl } from '../../lib/api';
import { reportClientError } from '../../lib/diagnostics';
import RFB from '@novnc/novnc';
import { useComputerStore } from '../../stores/computerStore';
import { useUiStore } from '../../stores/uiStore';

const RECONNECT_BACKOFF_MS = [1000, 2000, 4000, 8000, 15000] as const;
const MAX_RECONNECT_ATTEMPTS = 6;

const NAV_OR_EDIT_KEYS = new Set([
  'Tab',
  ' ',
  'ArrowUp',
  'ArrowDown',
  'ArrowLeft',
  'ArrowRight',
  'Backspace',
  'Enter',
  'Escape',
  'Delete',
  'Home',
  'End',
  'PageUp',
  'PageDown',
]);

const MODIFIER_CODE_TO_PLAYWRIGHT: Record<string, string> = {
  ControlLeft: 'Control',
  ControlRight: 'Control',
  AltLeft: 'Alt',
  AltRight: 'Alt',
  ShiftLeft: 'Shift',
  ShiftRight: 'Shift',
  MetaLeft: 'Meta',
  MetaRight: 'Meta',
};

const MODIFIER_KEYSYM_TO_PLAYWRIGHT: Record<number, string> = {
  0xffe3: 'Control',
  0xffe4: 'Control',
  0xffe9: 'Alt',
  0xffea: 'Alt',
  0xffe1: 'Shift',
  0xffe2: 'Shift',
  0xffeb: 'Meta',
  0xffec: 'Meta',
};

const KEYSYM_TO_PLAYWRIGHT: Record<number, string> = {
  0xff1b: 'Escape',
  0xff09: 'Tab',
  0xff0d: 'Enter',
  0xff08: 'Backspace',
  0xffff: 'Delete',
  0xff50: 'Home',
  0xff57: 'End',
  0xff55: 'PageUp',
  0xff56: 'PageDown',
  0xff51: 'ArrowLeft',
  0xff52: 'ArrowUp',
  0xff53: 'ArrowRight',
  0xff54: 'ArrowDown',
  0x0020: 'Space',
};

function mapKeyCodeToPlaywright(code?: string, keysym?: number): string | null {
  if (code) {
    const keyMatch = /^Key([A-Z])$/.exec(code);
    if (keyMatch && keyMatch[1]) return keyMatch[1].toLowerCase();
    const digitMatch = /^Digit([0-9])$/.exec(code);
    if (digitMatch && digitMatch[1]) return digitMatch[1];
    if (code === 'Space' || code === ' ') return 'Space';
    return code;
  }
  if (typeof keysym === 'number') {
    if (KEYSYM_TO_PLAYWRIGHT[keysym]) return KEYSYM_TO_PLAYWRIGHT[keysym];
    if (keysym >= 0x21 && keysym <= 0x7e) return String.fromCharCode(keysym);
  }
  return null;
}

function keysToPlaywrightCombo(keys: { keysym: number; code?: string }[]): string {
  const mods: string[] = [];
  const mainKeys: string[] = [];
  for (const item of keys) {
    const mod =
      (item.code ? MODIFIER_CODE_TO_PLAYWRIGHT[item.code] : undefined) ??
      MODIFIER_KEYSYM_TO_PLAYWRIGHT[item.keysym];
    if (mod) {
      if (!mods.includes(mod)) mods.push(mod);
    } else {
      const mapped = mapKeyCodeToPlaywright(item.code, item.keysym);
      if (mapped) mainKeys.push(mapped);
    }
  }
  if (mainKeys.length === 0) return mods[0] ?? 'Escape';
  return [...mods, ...mainKeys].join('+');
}

export interface LiveVncHandle {
  sendKeyCombo: (keys: { keysym: number; code?: string }[]) => void;
  pasteClipboard: (text: string) => void;
  reconnect: () => void;
}

interface LiveVncCanvasProps {
  vmId?: string;
  source: 'vnc' | 'screencast';
  interactive: boolean;
  allowDirectBrowserInput?: boolean;
  className?: string;
}

type ConnState = 'starting' | 'ready' | 'reconnecting' | 'unavailable';

function isDisplayableBrowserUrl(url: unknown): url is string {
  if (typeof url !== 'string') return false;
  const trimmed = url.trim();
  return (
    Boolean(trimmed) &&
    trimmed !== 'about:blank' &&
    !trimmed.startsWith('chrome-error://')
  );
}

export const LiveVncCanvas = forwardRef<LiveVncHandle, LiveVncCanvasProps>(
  function LiveVncCanvas(
    { vmId = 'default', source, interactive, allowDirectBrowserInput = false, className = '' },
    ref,
  ) {
    const pushToast = useUiStore((s) => s.pushToast);
    const setComputerStatus = useComputerStore((s) => s.setStatus);

    const vncHostRef = useRef<HTMLDivElement | null>(null);
    const viewportRef = useRef<HTMLDivElement | null>(null);
    const urlInputRef = useRef<HTMLInputElement | null>(null);
    const urlFocusedRef = useRef(false);
    const lastServerUrlRef = useRef('');
    const rfbRef = useRef<RFB | null>(null);
    const screencastWsRef = useRef<WebSocket | null>(null);
    const imgRef = useRef<HTMLImageElement | null>(null);
    const interactiveRef = useRef(interactive);
    interactiveRef.current = interactive;
    const vncAttemptRef = useRef(0);
    const screencastAttemptRef = useRef(0);
    const directQueueRef = useRef<Promise<void>>(Promise.resolve());
    const typeBufferRef = useRef('');
    const typeTimerRef = useRef<number | null>(null);
    const wheelAccumRef = useRef<{ dx: number; dy: number }>({ dx: 0, dy: 0 });
    const wheelTimerRef = useRef<number | null>(null);

    const [connState, setConnState] = useState<ConnState>('starting');
    const [statusMessage, setStatusMessage] = useState<string>('Connecting to display…');
    const [connectNonce, setConnectNonce] = useState(0);

    // Screencast (Playwright) state
    const [frameDataUrl, setFrameDataUrl] = useState<string | null>(null);
    const [frameDims, setFrameDims] = useState({ width: 1280, height: 800 });
    const [browserRunning, setBrowserRunning] = useState(() =>
      Boolean(useComputerStore.getState().byVmId[vmId]?.browser_running),
    );
    const [urlInput, setUrlInput] = useState(() => {
      const storedUrl = useComputerStore.getState().byVmId[vmId]?.active_url;
      if (isDisplayableBrowserUrl(storedUrl)) {
        lastServerUrlRef.current = storedUrl.trim();
        return storedUrl.trim();
      }
      return 'https://example.com';
    });
    const [navigating, setNavigating] = useState(false);
    const [activeTitle, setActiveTitle] = useState('');

    const syncServerUrl = useCallback((rawUrl: unknown) => {
      if (!isDisplayableBrowserUrl(rawUrl)) return;
      const trimmed = rawUrl.trim();
      if (trimmed === lastServerUrlRef.current) return;
      lastServerUrlRef.current = trimmed;
      if (!urlFocusedRef.current) {
        setUrlInput(trimmed);
      }
    }, []);

    useEffect(() => {
      return () => {
        if (typeTimerRef.current !== null) window.clearTimeout(typeTimerRef.current);
        if (wheelTimerRef.current !== null) window.clearTimeout(wheelTimerRef.current);
      };
    }, []);

    const reconnect = useCallback(() => {
      vncAttemptRef.current = 0;
      screencastAttemptRef.current = 0;
      setConnectNonce((n) => n + 1);
    }, []);

    useImperativeHandle(
      ref,
      () => ({
        sendKeyCombo: (keys) => {
          if (source === 'vnc' && rfbRef.current) {
            for (const k of keys) {
              rfbRef.current.sendKey(k.keysym, k.code ?? null, true);
            }
            for (let i = keys.length - 1; i >= 0; i -= 1) {
              const k = keys[i];
              if (!k) continue;
              rfbRef.current.sendKey(k.keysym, k.code ?? null, false);
            }
            rfbRef.current.focus();
          } else if (source === 'screencast' && screencastWsRef.current?.readyState === WebSocket.OPEN) {
            const combo = keysToPlaywrightCombo(keys);
            screencastWsRef.current.send(JSON.stringify({ type: 'key', key: combo }));
          }
        },
        pasteClipboard: (text) => {
          if (source === 'vnc' && rfbRef.current) {
            rfbRef.current.clipboardPasteFrom(text);
          } else if (source === 'screencast' && screencastWsRef.current?.readyState === WebSocket.OPEN) {
            screencastWsRef.current.send(JSON.stringify({ type: 'type', text }));
          }
        },
        reconnect,
      }),
      [source, reconnect],
    );

    // Toggle viewOnly dynamically when takeover state changes
    useEffect(() => {
      if (rfbRef.current) {
        rfbRef.current.viewOnly = !interactive;
        if (interactive) {
          rfbRef.current.focus();
        }
      }
    }, [interactive]);

    // VNC connection lifecycle
    useEffect(() => {
      if (source !== 'vnc') return;
      vncAttemptRef.current = 0;
      let cancelled = false;
      let authFailed = false;
      let reconnectTimer: number | null = null;

      const scheduleVncReconnect = (fallbackMsg: string) => {
        if (cancelled || authFailed) return;
        if (vncAttemptRef.current >= MAX_RECONNECT_ATTEMPTS) {
          setConnState('unavailable');
          setStatusMessage(fallbackMsg);
          return;
        }
        const delay =
          RECONNECT_BACKOFF_MS[Math.min(vncAttemptRef.current, RECONNECT_BACKOFF_MS.length - 1)] ??
          15000;
        vncAttemptRef.current += 1;
        setConnState('reconnecting');
        setStatusMessage(`Connection interrupted. Reconnecting in ${Math.round(delay / 1000)}s…`);
        if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
        reconnectTimer = window.setTimeout(() => {
          if (!cancelled && !authFailed) {
            void startVnc();
          }
        }, delay);
      };

      const startVnc = async () => {
        setConnState(vncAttemptRef.current > 0 ? 'reconnecting' : 'starting');
        setStatusMessage(
          vncAttemptRef.current > 0
            ? 'Reconnecting to VM Desktop…'
            : 'Requesting short-lived VNC capability token…',
        );
        try {
          const tokenRes = await computerApi.vncToken(vmId);
          if (cancelled || !vncHostRef.current) return;

          if (rfbRef.current) {
            try {
              rfbRef.current.disconnect();
            } catch {
              // ignore previous instance cleanup
            }
            rfbRef.current = null;
          }

          vncHostRef.current.innerHTML = '';
          const wsUrl = toWsUrl(tokenRes.ws_vnc_url);
          const rfb = new RFB(vncHostRef.current, wsUrl);
          rfb.viewOnly = !interactiveRef.current;
          rfb.focusOnClick = true;
          rfb.showDotCursor = true;
          rfb.scaleViewport = true;
          rfb.resizeSession = false;
          rfb.clipViewport = false;
          rfb.background = '#18191C';

          rfb.addEventListener('connect', () => {
            if (!cancelled) {
              vncAttemptRef.current = 0;
              rfb.viewOnly = !interactiveRef.current;
              if (interactiveRef.current) {
                rfb.focus();
              }
              setConnState('ready');
              setStatusMessage('Connected to VM Desktop');
            }
          });

          rfb.addEventListener('disconnect', (ev: Event) => {
            rfbRef.current = null;
            if (cancelled || authFailed) return;
            const clean = Boolean((ev as CustomEvent<{ clean?: boolean }>)?.detail?.clean);
            if (!clean) {
              reportClientError({
                kind: 'vnc_disconnect',
                message: `VNC disconnected unexpectedly (attempt ${vncAttemptRef.current + 1})`,
                url: tokenRes.ws_vnc_url,
              });
            }
            scheduleVncReconnect('VM Desktop disconnected. Click Retry to reconnect.');
          });

          rfb.addEventListener('securityfailure', () => {
            authFailed = true;
            rfbRef.current = null;
            reportClientError({
              kind: 'vnc_security_failure',
              message: 'VNC authentication failed',
              url: tokenRes.ws_vnc_url,
            });
            if (reconnectTimer !== null) {
              window.clearTimeout(reconnectTimer);
              reconnectTimer = null;
            }
            if (!cancelled) {
              setConnState('unavailable');
              setStatusMessage('VNC authentication failed.');
            }
          });

          rfbRef.current = rfb;
        } catch (err) {
          if (!cancelled && !authFailed) {
            const msg = err instanceof Error ? err.message : 'VM Desktop (VNC) is unavailable.';
            scheduleVncReconnect(msg);
          }
        }
      };

      void startVnc();

      return () => {
        cancelled = true;
        if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
        if (rfbRef.current) {
          try {
            rfbRef.current.disconnect();
          } catch {
            // ignore disconnect errors
          }
          rfbRef.current = null;
        }
      };
      // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [source, vmId, connectNonce]);

    // Playwright Screencast connection lifecycle
    useEffect(() => {
      if (source !== 'screencast') return;
      screencastAttemptRef.current = 0;
      let cancelled = false;
      let reconnectTimer: number | null = null;

      const scheduleScreencastReconnect = (fallbackMsg: string) => {
        if (cancelled) return;
        if (screencastAttemptRef.current >= MAX_RECONNECT_ATTEMPTS) {
          setConnState('unavailable');
          setStatusMessage(fallbackMsg);
          return;
        }
        const delay =
          RECONNECT_BACKOFF_MS[
            Math.min(screencastAttemptRef.current, RECONNECT_BACKOFF_MS.length - 1)
          ] ?? 15000;
        screencastAttemptRef.current += 1;
        setConnState('reconnecting');
        setStatusMessage(`Browser stream closed. Reconnecting in ${Math.round(delay / 1000)}s…`);
        if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
        reconnectTimer = window.setTimeout(() => {
          if (!cancelled) {
            void startScreencast();
          }
        }, delay);
      };

      const startScreencast = async () => {
        setConnState(screencastAttemptRef.current > 0 ? 'reconnecting' : 'starting');
        setStatusMessage(
          screencastAttemptRef.current > 0
            ? 'Reconnecting to Live Browser…'
            : 'Connecting to Live Browser…',
        );
        try {
          const tokenRes = await computerApi.vncToken(vmId);
          if (cancelled) return;

          const wsUrl = toWsUrl(tokenRes.ws_screencast_url);
          const ws = new WebSocket(wsUrl);
          screencastWsRef.current = ws;

          ws.onopen = () => {
            if (!cancelled) {
              screencastAttemptRef.current = 0;
              setConnState('ready');
              setStatusMessage('Connected to Live Browser');
            }
          };

          ws.onmessage = (ev) => {
            if (cancelled) return;
            try {
              const msg = JSON.parse(String(ev.data)) as Record<string, unknown>;
              if (msg.type === 'frame' && typeof msg.data === 'string') {
                const src = msg.data.startsWith('data:')
                  ? msg.data
                  : `data:image/jpeg;base64,${msg.data}`;
                setFrameDataUrl(src);
                setBrowserRunning(true);
                if (typeof msg.width === 'number' && typeof msg.height === 'number') {
                  setFrameDims({ width: msg.width, height: msg.height });
                }
                syncServerUrl(msg.url);
                if (typeof msg.title === 'string') setActiveTitle(msg.title);
              } else if (msg.type === 'status') {
                setBrowserRunning(Boolean(msg.running));
                syncServerUrl(msg.url);
                if (typeof msg.title === 'string') setActiveTitle(msg.title);
              } else if (msg.type === 'error' && typeof msg.message === 'string') {
                pushToast({ tone: 'warn', title: 'Browser notice', description: msg.message });
              }
            } catch {
              // ignore non-JSON frames
            }
          };

          ws.onclose = () => {
            if (screencastWsRef.current === ws) {
              screencastWsRef.current = null;
            }
            if (!cancelled) {
              scheduleScreencastReconnect('Browser stream closed. Click Retry to reconnect.');
            }
          };

          ws.onerror = () => {
            if (!cancelled) {
              setStatusMessage('Live Browser connection error — retrying…');
            }
          };
        } catch (err) {
          if (!cancelled) {
            const msg = err instanceof Error ? err.message : 'Live Browser unavailable.';
            scheduleScreencastReconnect(msg);
          }
        }
      };

      void startScreencast();

      return () => {
        cancelled = true;
        if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
        if (screencastWsRef.current) {
          try {
            screencastWsRef.current.close();
          } catch {
            // ignore
          }
          screencastWsRef.current = null;
        }
      };
    }, [source, vmId, connectNonce, pushToast, syncServerUrl]);

    const sendScreencast = useCallback((payload: Record<string, unknown>) => {
      const ws = screencastWsRef.current;
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify(payload));
        return true;
      }
      return false;
    }, []);

    const canDirectInteract =
      source === 'screencast' && allowDirectBrowserInput && browserRunning;
    const canInteract = interactive || canDirectInteract;

    const enqueueDirectAction = useCallback(
      (payload: Record<string, unknown>) => {
        directQueueRef.current = directQueueRef.current
          .then(async () => {
            const res = await computerApi.action(vmId, { ...payload, actor: 'human' });
            setComputerStatus(res.status);
            setBrowserRunning(Boolean(res.status.browser_running));
            syncServerUrl(res.status.active_url);
            sendScreencast({ type: 'status' });
          })
          .catch((err: unknown) => {
            pushToast({
              tone: 'warn',
              title: 'Browser action failed',
              description: err instanceof Error ? err.message : 'Error',
            });
          });
      },
      [vmId, setComputerStatus, syncServerUrl, sendScreencast, pushToast],
    );

    const flushDirectTypeBuffer = useCallback(() => {
      if (typeTimerRef.current !== null) {
        window.clearTimeout(typeTimerRef.current);
        typeTimerRef.current = null;
      }
      const buffered = typeBufferRef.current;
      if (buffered) {
        typeBufferRef.current = '';
        enqueueDirectAction({ type: 'type', text: buffered });
      }
    }, [enqueueDirectAction]);

    const dispatchBrowserInput = useCallback(
      (payload: Record<string, unknown>) => {
        if (interactive) {
          sendScreencast(payload);
          return;
        }
        if (!canDirectInteract) return;
        const evType = payload.type;
        if (evType === 'type' && typeof payload.text === 'string') {
          typeBufferRef.current += payload.text;
          if (typeTimerRef.current !== null) {
            window.clearTimeout(typeTimerRef.current);
          }
          typeTimerRef.current = window.setTimeout(() => {
            flushDirectTypeBuffer();
          }, 60);
          return;
        }
        if (evType === 'wheel') {
          const dx = typeof payload.dx === 'number' ? payload.dx : 0;
          const dy = typeof payload.dy === 'number' ? payload.dy : 0;
          wheelAccumRef.current.dx += dx;
          wheelAccumRef.current.dy += dy;
          if (wheelTimerRef.current === null) {
            wheelTimerRef.current = window.setTimeout(() => {
              wheelTimerRef.current = null;
              const acc = wheelAccumRef.current;
              wheelAccumRef.current = { dx: 0, dy: 0 };
              if (acc.dx !== 0 || acc.dy !== 0) {
                enqueueDirectAction({ type: 'wheel', dx: acc.dx, dy: acc.dy });
              }
            }, 120);
          }
          return;
        }
        flushDirectTypeBuffer();
        enqueueDirectAction(payload);
      },
      [interactive, canDirectInteract, sendScreencast, flushDirectTypeBuffer, enqueueDirectAction],
    );

    const handleNavigateUrl = async (rawUrl: string) => {
      const trimmedUrl = rawUrl.trim();
      if (!trimmedUrl) return;
      urlFocusedRef.current = false;
      urlInputRef.current?.blur();
      setNavigating(true);
      try {
        const res = await computerApi.action(vmId, {
          type: browserRunning ? 'navigate' : 'start',
          url: trimmedUrl,
          actor: 'human',
        });
        setComputerStatus(res.status);
        setBrowserRunning(Boolean(res.status.browser_running));
        if (isDisplayableBrowserUrl(res.status.active_url)) {
          lastServerUrlRef.current = res.status.active_url.trim();
          setUrlInput(res.status.active_url.trim());
        }
        sendScreencast({ type: 'status' });
      } catch (err) {
        sendScreencast({ type: 'status' });
        pushToast({
          tone: 'error',
          title: 'Could not open page',
          description: err instanceof Error ? err.message : 'Error',
        });
      } finally {
        setNavigating(false);
      }
    };

    const handleNavControl = (actionType: 'back' | 'forward' | 'reload') => {
      if (!sendScreencast({ type: actionType })) {
        enqueueDirectAction({ type: actionType });
      }
    };

    const handleStartBrowser = async () => {
      urlFocusedRef.current = false;
      setNavigating(true);
      try {
        const trimmedUrl = urlInput.trim();
        const res = await computerApi.action(vmId, {
          type: 'start',
          actor: 'human',
          ...(trimmedUrl ? { url: trimmedUrl } : {}),
        });
        setComputerStatus(res.status);
        setBrowserRunning(Boolean(res.status.browser_running));
        if (isDisplayableBrowserUrl(res.status.active_url)) {
          lastServerUrlRef.current = res.status.active_url.trim();
          setUrlInput(res.status.active_url.trim());
        }
        sendScreencast({ type: 'status' });
      } catch (err) {
        sendScreencast({ type: 'status' });
        pushToast({
          tone: 'error',
          title: 'Could not start browser',
          description: err instanceof Error ? err.message : 'Error',
        });
      } finally {
        setNavigating(false);
      }
    };

    const handleStopBrowser = async () => {
      try {
        const res = await computerApi.action(vmId, { type: 'stop', actor: 'human' });
        setFrameDataUrl(null);
        setBrowserRunning(false);
        setComputerStatus(res.status);
      } catch (err) {
        pushToast({
          tone: 'error',
          title: 'Could not stop browser',
          description: err instanceof Error ? err.message : 'Error',
        });
      }
    };

    const handleImagePointer = (
      e: React.MouseEvent<HTMLImageElement>,
      evType: 'click' | 'dblclick',
      buttonOverride?: 'left' | 'middle' | 'right',
    ) => {
      if (!canInteract || !imgRef.current) return;
      viewportRef.current?.focus();
      const rect = imgRef.current.getBoundingClientRect();
      if (rect.width <= 0 || rect.height <= 0) return;
      const x = Math.round(((e.clientX - rect.left) / rect.width) * frameDims.width);
      const y = Math.round(((e.clientY - rect.top) / rect.height) * frameDims.height);
      if (evType === 'dblclick') {
        dispatchBrowserInput({ type: 'dblclick', x, y });
        return;
      }
      const button: 'left' | 'middle' | 'right' =
        buttonOverride ?? (e.button === 2 ? 'right' : e.button === 1 ? 'middle' : 'left');
      dispatchBrowserInput({ type: 'click', x, y, button });
    };

    const handleImageWheel = (e: React.WheelEvent<HTMLImageElement>) => {
      if (!canInteract) return;
      dispatchBrowserInput({ type: 'wheel', dx: e.deltaX, dy: e.deltaY });
    };

    const handleImageKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
      if (
        e.target instanceof HTMLInputElement ||
        e.target instanceof HTMLTextAreaElement ||
        e.target instanceof HTMLSelectElement
      ) {
        return;
      }
      if (!canInteract) return;
      if (e.key === 'Control' || e.key === 'Shift' || e.key === 'Alt' || e.key === 'Meta') {
        return;
      }
      const hasPrimaryMod = e.ctrlKey || e.altKey || e.metaKey;
      if (hasPrimaryMod || NAV_OR_EDIT_KEYS.has(e.key)) {
        e.preventDefault();
      }
      if (hasPrimaryMod || (e.shiftKey && (e.key.length > 1 || e.key === ' '))) {
        const mods: string[] = [];
        if (e.ctrlKey) mods.push('Control');
        if (e.altKey) mods.push('Alt');
        if (e.shiftKey) mods.push('Shift');
        if (e.metaKey) mods.push('Meta');
        const keyPart =
          e.key === ' '
            ? 'Space'
            : e.key.length === 1 && e.shiftKey
              ? e.key.toLowerCase()
              : e.key;
        dispatchBrowserInput({ type: 'key', key: [...mods, keyPart].join('+') });
      } else if (e.key.length === 1) {
        dispatchBrowserInput({ type: 'type', text: e.key });
      } else {
        dispatchBrowserInput({ type: 'key', key: e.key });
      }
    };

    return (
      <div className={`flex flex-col h-full min-h-0 ${className}`}>
        {/* Browser Controls Bar for Screencast mode */}
        {source === 'screencast' && (
          <div
            className="flex items-center gap-1.5 px-2.5 py-2 shrink-0"
            style={{
              backgroundColor: 'var(--bg-sidebar)',
              borderBottom: '1px solid var(--border-subtle)',
            }}
          >
            <button
              type="button"
              onClick={() => handleNavControl('back')}
              disabled={!browserRunning}
              title="Back"
              aria-label="Back"
              className="p-1.5 rounded-lg hover:bg-[var(--bg-active)] disabled:opacity-40"
            >
              <ArrowLeft size={14} />
            </button>
            <button
              type="button"
              onClick={() => handleNavControl('forward')}
              disabled={!browserRunning}
              title="Forward"
              aria-label="Forward"
              className="p-1.5 rounded-lg hover:bg-[var(--bg-active)] disabled:opacity-40"
            >
              <ArrowRight size={14} />
            </button>
            <button
              type="button"
              onClick={() => handleNavControl('reload')}
              disabled={!browserRunning}
              title="Reload"
              aria-label="Reload"
              className="p-1.5 rounded-lg hover:bg-[var(--bg-active)] disabled:opacity-40"
            >
              <RotateCw size={13.5} />
            </button>

            <form
              onSubmit={(e) => {
                e.preventDefault();
                void handleNavigateUrl(urlInput);
              }}
              className="flex-1 flex items-center gap-1.5 px-2.5 py-1 rounded-lg"
              style={{
                backgroundColor: 'var(--bg-canvas)',
                border: '1px solid var(--border-subtle)',
              }}
            >
              {navigating ? (
                <Loader2 size={13} className="animate-spin shrink-0" style={{ color: 'var(--accent-computer)' }} />
              ) : (
                <Globe size={13} className="shrink-0" style={{ color: 'var(--text-muted)' }} />
              )}
              <input
                ref={urlInputRef}
                type="text"
                aria-label="Live browser URL"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                onFocus={() => {
                  urlFocusedRef.current = true;
                }}
                onBlur={() => {
                  urlFocusedRef.current = false;
                }}
                onKeyDown={(e) => e.stopPropagation()}
                placeholder="https://…"
                className="w-full text-[12px] bg-transparent outline-none"
              />
              <button
                type="submit"
                disabled={navigating || !urlInput.trim()}
                title="Go"
                aria-label="Go to URL"
                className="px-1.5 py-0.5 rounded text-[11px] font-medium hover:bg-[var(--bg-active)] disabled:opacity-40 shrink-0"
                style={{ color: 'var(--text-secondary)' }}
              >
                Go
              </button>
            </form>

            {browserRunning ? (
              <button
                type="button"
                onClick={() => void handleStopBrowser()}
                title="Stop browser"
                className="inline-flex items-center gap-1 px-2 py-1.5 rounded-lg text-[11.5px] font-medium"
                style={{
                  backgroundColor: 'var(--status-danger-bg)',
                  color: 'var(--status-danger)',
                }}
              >
                <Square size={11} fill="currentColor" />
                Stop
              </button>
            ) : (
              <button
                type="button"
                onClick={() => void handleStartBrowser()}
                title="Start browser"
                className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-[11.5px] font-medium"
                style={{
                  backgroundColor: 'var(--accent-computer)',
                  color: '#FFFFFF',
                }}
              >
                <Play size={11} fill="currentColor" />
                Start
              </button>
            )}
          </div>
        )}

        {/* Viewport Container */}
        <div
          ref={viewportRef}
          className="relative flex-1 min-h-[220px] flex items-center justify-center overflow-hidden"
          style={{ backgroundColor: '#18191C' }}
          tabIndex={canInteract && source === 'screencast' ? 0 : -1}
          onKeyDown={handleImageKeyDown}
        >
          {source === 'vnc' ? (
            <div ref={vncHostRef} className="w-full h-full" />
          ) : frameDataUrl ? (
            <img
              ref={imgRef}
              src={frameDataUrl}
              alt={activeTitle || 'Live Browser'}
              onMouseDown={() => {
                if (canInteract) viewportRef.current?.focus();
              }}
              onClick={(e) => handleImagePointer(e, 'click')}
              onDoubleClick={(e) => handleImagePointer(e, 'dblclick')}
              onAuxClick={(e) => {
                if (e.button === 1 && canInteract) {
                  e.preventDefault();
                  handleImagePointer(e, 'click', 'middle');
                }
              }}
              onContextMenu={(e) => {
                if (canInteract) {
                  e.preventDefault();
                  handleImagePointer(e, 'click', 'right');
                }
              }}
              onWheel={handleImageWheel}
              className={`max-w-full max-h-full object-contain select-none ${
                canInteract ? 'cursor-pointer' : 'cursor-default'
              }`}
              draggable={false}
            />
          ) : (
            <div className="text-center p-6 space-y-3">
              <Globe size={28} className="mx-auto text-[#868C98]" />
              <div className="text-[13px] text-[#D1D5DB]">
                {browserRunning ? 'Waiting for first frame…' : 'Live Browser is stopped'}
              </div>
              {!browserRunning && (
                <button
                  type="button"
                  onClick={() => void handleStartBrowser()}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12.5px] font-medium text-white"
                  style={{ backgroundColor: 'var(--accent-computer)' }}
                >
                  <Play size={12} fill="currentColor" />
                  Launch Live Browser
                </button>
              )}
            </div>
          )}

          {/* Explicit Connection State Overlay */}
          {connState !== 'ready' && (
            <div
              className="absolute inset-0 flex flex-col items-center justify-center gap-3 p-5 text-center"
              style={{ backgroundColor: 'rgba(24, 25, 28, 0.88)' }}
            >
              {connState === 'starting' ? (
                <Loader2 size={24} className="animate-spin text-[#A78BFA]" />
              ) : (
                <WifiOff size={24} className="text-[#F59E0B]" />
              )}
              <div className="space-y-1 max-w-xs">
                <div className="text-[13.5px] font-medium text-white capitalize">
                  {connState === 'starting'
                    ? 'Starting display'
                    : connState === 'reconnecting'
                      ? 'Reconnecting'
                      : 'Unavailable'}
                </div>
                <div className="text-[12px] text-[#A1A7B5]">{statusMessage}</div>
              </div>
              {connState !== 'starting' && (
                <button
                  type="button"
                  onClick={reconnect}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12.5px] font-medium bg-white text-[#111318] hover:opacity-90"
                >
                  <RefreshCw size={13} />
                  Retry
                </button>
              )}
            </div>
          )}
        </div>
      </div>
    );
  },
);
