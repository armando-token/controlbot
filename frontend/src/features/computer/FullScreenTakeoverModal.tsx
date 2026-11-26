import React, { useCallback, useEffect, useRef, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import {
  CheckCircle2,
  ClipboardPaste,
  Globe,
  Hand,
  Monitor,
  ShieldAlert,
  X,
} from 'lucide-react';
import { computerApi, toWsUrl } from '../../lib/api';
import type { ComputerStatus } from '../../lib/types';
import { useComputerStore } from '../../stores/computerStore';
import { useUiStore } from '../../stores/uiStore';
import { LiveVncCanvas, type LiveVncHandle } from './LiveVncCanvas';

// Standard X11 KeySyms for modifier bar
const XK_Control_L = 0xffe3;
const XK_Alt_L = 0xffe9;
const XK_Escape = 0xff1b;
const XK_Tab = 0xff09;
const XK_c = 0x0063;
const XK_v = 0x0076;

const CONTROL_RECONNECT_BACKOFF_MS = [1000, 2000, 4000, 8000, 15000] as const;
const MAX_CONTROL_RECONNECT_ATTEMPTS = 6;

export const FullScreenTakeoverModal: React.FC = () => {
  const queryClient = useQueryClient();
  const vmId = useUiStore((s) => s.fullscreenComputerVmId);
  const setFullscreenVmId = useUiStore((s) => s.setFullscreenComputerVmId);
  const pushToast = useUiStore((s) => s.pushToast);

  const status = useComputerStore((s) => (vmId ? s.byVmId[vmId] : undefined));
  const setStatus = useComputerStore((s) => s.setStatus);
  const preferredSource = useComputerStore((s) => s.preferredSource);
  const setPreferredSource = useComputerStore((s) => s.setPreferredSource);
  const addTeachStep = useComputerStore((s) => s.addTeachStep);

  const canvasRef = useRef<LiveVncHandle | null>(null);
  const controlWsRef = useRef<WebSocket | null>(null);
  const viewportContainerRef = useRef<HTMLDivElement | null>(null);
  const lastViewportSentRef = useRef<string>('');

  const [clipboardText, setClipboardText] = useState('');
  const [secondsLeft, setSecondsLeft] = useState<number | null>(null);

  const isTakeover = status?.control_owner === 'human_takeover';

  const sendViewportResize = useCallback((force = false) => {
    const ws = controlWsRef.current;
    const el = viewportContainerRef.current;
    if (!ws || ws.readyState !== WebSocket.OPEN || !el) return;
    const rect = el.getBoundingClientRect();
    if (rect.width <= 0 || rect.height <= 0) return;
    const width = Math.max(320, Math.min(3840, Math.round(rect.width)));
    const height = Math.max(240, Math.min(2160, Math.round(rect.height)));
    const key = `${width}x${height}`;
    if (!force && lastViewportSentRef.current === key) return;
    lastViewportSentRef.current = key;
    ws.send(JSON.stringify({ op: 'viewport.resize', width, height }));
  }, []);

  // Capture-phase Escape handler so Escape closes the modal even when focus is inside <canvas> (noVNC) or <input>
  useEffect(() => {
    if (!vmId) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape' && !e.isComposing) {
        e.preventDefault();
        e.stopPropagation();
        useUiStore.getState().setFullscreenComputerVmId(null);
      }
    };
    window.addEventListener('keydown', onKeyDown, true);
    return () => window.removeEventListener('keydown', onKeyDown, true);
  }, [vmId]);

  // Control plane WebSocket for lease heartbeat (15s), viewport resize, clipboard push, teach steps, lease revoke
  useEffect(() => {
    if (!vmId) return;
    let cancelled = false;
    let heartbeatTimer: number | null = null;
    let reconnectTimer: number | null = null;
    let attempt = 0;
    lastViewportSentRef.current = '';

    const clearHeartbeat = () => {
      if (heartbeatTimer !== null) {
        window.clearInterval(heartbeatTimer);
        heartbeatTimer = null;
      }
    };

    const scheduleReconnect = () => {
      if (cancelled || attempt >= MAX_CONTROL_RECONNECT_ATTEMPTS) return;
      const delay =
        CONTROL_RECONNECT_BACKOFF_MS[
          Math.min(attempt, CONTROL_RECONNECT_BACKOFF_MS.length - 1)
        ] ?? 15000;
      attempt += 1;
      if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
      reconnectTimer = window.setTimeout(() => {
        if (!cancelled) {
          void openControl();
        }
      }, delay);
    };

    const openControl = async () => {
      try {
        const tokenRes = await computerApi.vncToken(vmId);
        if (cancelled) return;
        const ws = new WebSocket(toWsUrl(tokenRes.ws_control_url));
        controlWsRef.current = ws;

        ws.onopen = () => {
          if (cancelled) {
            try {
              ws.close();
            } catch {
              // ignore
            }
            return;
          }
          attempt = 0;
          lastViewportSentRef.current = '';
          sendViewportResize(true);
          clearHeartbeat();
          heartbeatTimer = window.setInterval(() => {
            const cur = useComputerStore.getState().byVmId[vmId];
            if (ws.readyState === WebSocket.OPEN && cur?.lease_id) {
              ws.send(JSON.stringify({ op: 'lease.heartbeat', lease_id: cur.lease_id }));
            }
          }, 15_000);
        };

        ws.onmessage = (ev) => {
          try {
            const msg = JSON.parse(String(ev.data)) as Record<string, unknown>;
            if (msg.op === 'teach.step_captured') {
              const rawStep =
                msg.step && typeof msg.step === 'object'
                  ? (msg.step as Record<string, unknown>)
                  : null;
              addTeachStep({
                index: Number(rawStep?.step_index ?? msg.step_index ?? 0),
                description: String(rawStep?.description ?? msg.description ?? 'Action recorded'),
                action:
                  typeof rawStep?.action === 'string'
                    ? rawStep.action
                    : typeof msg.action === 'string'
                      ? msg.action
                      : undefined,
                url:
                  typeof rawStep?.url === 'string'
                    ? rawStep.url
                    : typeof msg.url === 'string'
                      ? msg.url
                      : undefined,
              });
            } else if (msg.op === 'lease.revoked') {
              void computerApi.status(vmId).then(setStatus);
              pushToast({
                tone: 'info',
                title: 'Control handed back',
                description: String(msg.reason || 'Takeover lease ended'),
              });
            } else if (msg.op === 'lease.heartbeat.ack' && typeof msg.lease_expires_at === 'string') {
              const cur = useComputerStore.getState().byVmId[vmId];
              if (cur) {
                setStatus({
                  ...cur,
                  lease_expires_at: msg.lease_expires_at,
                  ...(typeof msg.lease_id === 'string' ? { lease_id: msg.lease_id } : {}),
                });
              }
            } else if (msg.op === 'computer.state' && msg.status && typeof msg.status === 'object') {
              setStatus(msg.status as ComputerStatus);
            }
          } catch {
            // ignore
          }
        };

        ws.onclose = (ev) => {
          clearHeartbeat();
          if (controlWsRef.current === ws) {
            controlWsRef.current = null;
          }
          if (!cancelled && ev.code !== 4401) {
            scheduleReconnect();
          }
        };

        ws.onerror = () => {
          // onclose handles bounded backoff reconnect
        };
      } catch {
        if (!cancelled) {
          scheduleReconnect();
        }
      }
    };

    void openControl();

    return () => {
      cancelled = true;
      clearHeartbeat();
      if (reconnectTimer !== null) {
        window.clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      if (controlWsRef.current) {
        try {
          controlWsRef.current.close();
        } catch {
          // ignore
        }
        controlWsRef.current = null;
      }
    };
  }, [vmId, addTeachStep, setStatus, pushToast, sendViewportResize]);

  // Sync viewport dimensions on open, layout/mode changes, and container resize
  useEffect(() => {
    if (!vmId) return;
    const el = viewportContainerRef.current;
    if (!el) return;

    let debounceTimer: number | null = null;
    const rafId = window.requestAnimationFrame(() => {
      sendViewportResize(false);
    });

    const ro = new ResizeObserver(() => {
      if (debounceTimer !== null) window.clearTimeout(debounceTimer);
      debounceTimer = window.setTimeout(() => {
        sendViewportResize(false);
      }, 150);
    });
    ro.observe(el);

    return () => {
      window.cancelAnimationFrame(rafId);
      if (debounceTimer !== null) window.clearTimeout(debounceTimer);
      ro.disconnect();
    };
  }, [vmId, preferredSource, isTakeover, sendViewportResize]);

  // Countdown display for lease TTL
  useEffect(() => {
    if (!status?.lease_expires_at || !isTakeover) {
      setSecondsLeft(null);
      return;
    }
    const tick = () => {
      const ms = new Date(status.lease_expires_at!).getTime() - Date.now();
      setSecondsLeft(Math.max(0, Math.floor(ms / 1000)));
    };
    tick();
    const id = window.setInterval(tick, 1000);
    return () => window.clearInterval(id);
  }, [status?.lease_expires_at, isTakeover]);

  const takeoverMutation = useMutation({
    mutationFn: () => computerApi.takeover(vmId || 'default'),
    onSuccess: (st) => {
      setStatus(st);
      void queryClient.invalidateQueries({ queryKey: ['computer-status', vmId] });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not take control', description: err.message });
    },
  });

  const handbackMutation = useMutation({
    mutationFn: () => computerApi.handback(vmId || 'default'),
    onSuccess: (st) => {
      setStatus(st);
      void queryClient.invalidateQueries({ queryKey: ['computer-status', vmId] });
      setFullscreenVmId(null);
      pushToast({
        tone: 'success',
        title: 'Control returned to your Bot',
        description: 'Authenticated sessions and cookies remain active on the VM.',
      });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Handback failed', description: err.message });
    },
  });

  if (!vmId) return null;

  const pushClipboard = (e: React.FormEvent) => {
    e.preventDefault();
    if (!clipboardText) return;
    canvasRef.current?.pasteClipboard(clipboardText);
    const ws = controlWsRef.current;
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ op: 'clipboard.push', text: clipboardText }));
    }
    pushToast({ tone: 'success', title: 'Sent text to remote clipboard' });
    setClipboardText('');
  };

  return (
    <div
      className="fixed inset-0 z-50 flex flex-col p-3"
      style={{ backgroundColor: 'rgba(15, 23, 42, 0.55)', backdropFilter: 'blur(4px)' }}
      role="dialog"
      aria-modal="true"
      aria-label="Full-screen computer view"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) {
          setFullscreenVmId(null);
        }
      }}
    >
      {/* Perimeter frame — 2px amber #D97706 border when human is in control */}
      <div
        className="flex-1 min-h-0 flex flex-col rounded-2xl overflow-hidden transition-all"
        style={{
          backgroundColor: 'var(--bg-elevated)',
          border: isTakeover
            ? '2px solid #D97706'
            : '1px solid var(--border-strong)',
          boxShadow: isTakeover
            ? '0 0 0 4px rgba(217, 119, 6, 0.18), var(--shadow-lg)'
            : 'var(--shadow-lg)',
        }}
      >
        {/* Top Bar */}
        <div
          className="px-4 py-2.5 flex flex-wrap items-center justify-between gap-3 shrink-0"
          style={{
            backgroundColor: isTakeover ? 'var(--accent-takeover-tint)' : 'var(--bg-sidebar)',
            borderBottom: '1px solid var(--border-subtle)',
          }}
        >
          <div className="flex items-center gap-3">
            {isTakeover ? (
              <span
                className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[12.5px] font-semibold text-white"
                style={{ backgroundColor: '#D97706' }}
              >
                <Hand size={13.5} strokeWidth={2.2} />
                You&apos;re in control
                {secondsLeft !== null && (
                  <span className="font-mono text-[11.5px] opacity-90 ml-1 tabular-nums">
                    ({Math.floor(secondsLeft / 60)}:{String(secondsLeft % 60).padStart(2, '0')})
                  </span>
                )}
              </span>
            ) : (
              <span
                className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[12.5px] font-medium"
                style={{
                  backgroundColor: 'var(--accent-computer-tint)',
                  color: 'var(--accent-computer)',
                }}
              >
                <Monitor size={13.5} />
                Preview mode (read-only)
              </span>
            )}

            {/* Source toggle */}
            <div
              className="inline-flex rounded-lg p-0.5"
              style={{
                backgroundColor: 'var(--bg-canvas)',
                border: '1px solid var(--border-subtle)',
              }}
            >
              <button
                type="button"
                onClick={() => setPreferredSource('vnc')}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-[12px] font-medium"
                style={{
                  backgroundColor: preferredSource === 'vnc' ? 'var(--bg-active)' : 'transparent',
                }}
              >
                <Monitor size={12.5} />
                VM Desktop
              </button>
              <button
                type="button"
                onClick={() => setPreferredSource('screencast')}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-md text-[12px] font-medium"
                style={{
                  backgroundColor:
                    preferredSource === 'screencast' ? 'var(--bg-active)' : 'transparent',
                }}
              >
                <Globe size={12.5} />
                Live Browser
              </button>
            </div>
          </div>

          <div className="flex items-center gap-2">
            {isTakeover ? (
              <button
                type="button"
                onClick={() => handbackMutation.mutate()}
                disabled={handbackMutation.isPending}
                className="inline-flex items-center gap-1.5 px-4 py-1.5 rounded-lg text-[13px] font-semibold text-white transition-opacity disabled:opacity-50"
                style={{ backgroundColor: '#15803D' }}
              >
                <CheckCircle2 size={15} strokeWidth={2.2} />
                {handbackMutation.isPending ? 'Handing back…' : "I'm done"}
              </button>
            ) : (
              <button
                type="button"
                onClick={() => takeoverMutation.mutate()}
                disabled={takeoverMutation.isPending}
                className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-[13px] font-medium text-white"
                style={{ backgroundColor: '#D97706' }}
              >
                <Hand size={14} />
                {takeoverMutation.isPending ? 'Acquiring…' : 'Take control'}
              </button>
            )}

            <button
              type="button"
              onClick={() => setFullscreenVmId(null)}
              title="Exit full screen"
              aria-label="Exit full screen"
              className="p-1.5 rounded-lg hover:bg-[var(--bg-active)]"
              style={{ color: 'var(--text-secondary)' }}
            >
              <X size={18} />
            </button>
          </div>
        </div>

        {/* Takeover Modifier & Clipboard Bar */}
        {isTakeover && (
          <div
            className="px-4 py-2 flex flex-wrap items-center justify-between gap-2 shrink-0 text-[12px]"
            style={{
              backgroundColor: 'var(--bg-canvas)',
              borderBottom: '1px solid var(--border-subtle)',
            }}
          >
            <div className="flex flex-wrap items-center gap-1.5">
              <span className="text-[11.5px] font-medium mr-1" style={{ color: 'var(--text-muted)' }}>
                Quick keys:
              </span>
              {[
                {
                  label: 'Ctrl+C',
                  keys: [
                    { keysym: XK_Control_L, code: 'ControlLeft' },
                    { keysym: XK_c, code: 'KeyC' },
                  ],
                },
                {
                  label: 'Ctrl+V',
                  keys: [
                    { keysym: XK_Control_L, code: 'ControlLeft' },
                    { keysym: XK_v, code: 'KeyV' },
                  ],
                },
                { label: 'Esc', keys: [{ keysym: XK_Escape, code: 'Escape' }] },
                { label: 'Tab', keys: [{ keysym: XK_Tab, code: 'Tab' }] },
                {
                  label: 'Alt+Tab',
                  keys: [
                    { keysym: XK_Alt_L, code: 'AltLeft' },
                    { keysym: XK_Tab, code: 'Tab' },
                  ],
                },
              ].map((btn) => (
                <button
                  key={btn.label}
                  type="button"
                  onClick={() => canvasRef.current?.sendKeyCombo(btn.keys)}
                  className="px-2 py-1 rounded-md font-mono text-[11.5px] hover:bg-[var(--bg-active)]"
                  style={{
                    backgroundColor: 'var(--bg-subtle)',
                    border: '1px solid var(--border-subtle)',
                  }}
                >
                  {btn.label}
                </button>
              ))}
            </div>

            <form onSubmit={pushClipboard} className="flex items-center gap-1.5">
              <input
                type="text"
                value={clipboardText}
                onChange={(e) => setClipboardText(e.target.value)}
                placeholder="Push text to VM clipboard…"
                className="w-56 px-2.5 py-1 rounded-lg text-[12px] outline-none"
                style={{
                  backgroundColor: 'var(--bg-sidebar)',
                  border: '1px solid var(--border-strong)',
                }}
              />
              <button
                type="submit"
                disabled={!clipboardText}
                className="inline-flex items-center gap-1 px-2.5 py-1 rounded-lg text-[12px] font-medium disabled:opacity-40"
                style={{
                  backgroundColor: 'var(--bg-subtle)',
                  color: 'var(--text-primary)',
                }}
              >
                <ClipboardPaste size={13} />
                Send
              </button>
            </form>
          </div>
        )}

        {/* Live Canvas */}
        <div ref={viewportContainerRef} className="flex-1 min-h-0">
          <LiveVncCanvas
            ref={canvasRef}
            vmId={vmId}
            source={preferredSource}
            interactive={isTakeover}
          />
        </div>

        {/* Agent Lock Notice */}
        {isTakeover && (
          <div
            className="px-4 py-1.5 flex items-center gap-2 text-[11.5px] shrink-0"
            style={{
              backgroundColor: 'var(--bg-sidebar)',
              borderTop: '1px solid var(--border-subtle)',
              color: 'var(--text-secondary)',
            }}
          >
            <ShieldAlert size={13} style={{ color: '#D97706' }} />
            <span>
              Automation Lock active — agent commands are paused while you drive. Click{' '}
              <strong>I&apos;m done</strong> to return control.
            </span>
          </div>
        )}
      </div>
    </div>
  );
};
