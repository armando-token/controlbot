import React, { useEffect, useRef, useState } from 'react';
import { Terminal } from '@xterm/xterm';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import '@xterm/xterm/css/xterm.css';
import { Ban, Eraser, RefreshCw, TerminalSquare } from 'lucide-react';
import { computerApi, toWsUrl } from '../../lib/api';
import type { Bot } from '../../lib/types';

const RECONNECT_BACKOFF_MS = [1000, 2000, 4000, 8000, 15000] as const;
const MAX_RECONNECT_ATTEMPTS = 5;

interface TerminalTabProps {
  vmId?: string;
  projectName?: string | null;
  bot?: Bot | null;
}

export const TerminalTab: React.FC<TerminalTabProps> = ({
  vmId = 'default',
  projectName,
  bot,
}) => {
  const activeProject = (bot?.project_name ?? projectName ?? '').trim();

  const containerRef = useRef<HTMLDivElement | null>(null);
  const termRef = useRef<Terminal | null>(null);
  const fitRef = useRef<FitAddon | null>(null);
  const wsRef = useRef<WebSocket | null>(null);
  const attemptRef = useRef(0);

  const [status, setStatus] = useState<'connecting' | 'connected' | 'disconnected'>('connecting');
  const [notice, setNotice] = useState<{ tone: 'info' | 'error'; text: string } | null>(null);
  const [reconnectNonce, setReconnectNonce] = useState(0);

  const sendResize = () => {
    const term = termRef.current;
    const fit = fitRef.current;
    if (!term || !fit) return;
    try {
      fit.fit();
      const ws = wsRef.current;
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ op: 'resize', cols: term.cols, rows: term.rows }));
      }
    } catch {
      // ignore layout race
    }
  };

  // Lifecycle for xterm.js instance: preserved across WS reconnects for the same (vmId, activeProject)
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    attemptRef.current = 0;

    const term = new Terminal({
      cursorBlink: true,
      fontSize: 12.5,
      fontFamily: '"Geist Mono", "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace',
      theme: {
        background: '#18191C',
        foreground: '#E5E7EB',
        cursor: '#A78BFA',
        selectionBackground: 'rgba(124, 58, 237, 0.35)',
        black: '#18191C',
        red: '#F87171',
        green: '#4ADE80',
        yellow: '#FBBF24',
        blue: '#60A5FA',
        magenta: '#C084FC',
        cyan: '#22D3EE',
        white: '#F3F4F6',
      },
      allowProposedApi: true,
    });

    const fit = new FitAddon();
    const links = new WebLinksAddon();
    term.loadAddon(fit);
    term.loadAddon(links);
    term.open(container);
    fit.fit();

    termRef.current = term;
    fitRef.current = fit;

    let rafId: number | null = null;
    const ro = new ResizeObserver(() => {
      if (rafId !== null) window.cancelAnimationFrame(rafId);
      rafId = window.requestAnimationFrame(() => {
        rafId = null;
        sendResize();
      });
    });
    ro.observe(container);

    const dataDisposable = term.onData((data) => {
      const ws = wsRef.current;
      if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(new TextEncoder().encode(data));
      }
    });

    return () => {
      if (rafId !== null) window.cancelAnimationFrame(rafId);
      ro.disconnect();
      dataDisposable.dispose();
      term.dispose();
      termRef.current = null;
      fitRef.current = null;
    };
  }, [vmId, activeProject]);

  // WebSocket PTY connection lifecycle with backoff reconnect and fresh cap_token fetch
  useEffect(() => {
    let cancelled = false;
    let reconnectTimer: number | null = null;

    const scheduleReconnect = (code?: number) => {
      if (cancelled) return;
      if (attemptRef.current >= MAX_RECONNECT_ATTEMPTS) {
        setStatus('disconnected');
        const exhaustedMsg =
          code === 4401
            ? 'Authentication / capability token rejected (4401) — click Reconnect.'
            : 'PTY disconnected after retries — click Reconnect.';
        setNotice({ tone: 'error', text: exhaustedMsg });
        termRef.current?.writeln(`\r\n\x1b[31m[${exhaustedMsg}]\x1b[0m`);
        return;
      }
      const delay =
        RECONNECT_BACKOFF_MS[Math.min(attemptRef.current, RECONNECT_BACKOFF_MS.length - 1)] ??
        15000;
      attemptRef.current += 1;
      setStatus('connecting');
      termRef.current?.writeln(
        `\x1b[90m[Reconnecting PTY in ${Math.round(delay / 1000)}s…]\x1b[0m`,
      );
      if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
      reconnectTimer = window.setTimeout(() => {
        if (!cancelled) void connect();
      }, delay);
    };

    const connect = async () => {
      setStatus('connecting');
      if (attemptRef.current === 0) {
        const label = activeProject ? ` (${activeProject})` : '';
        termRef.current?.writeln(`\x1b[90mConnecting to bot@cloud:~${label} PTY...\x1b[0m`);
      }
      try {
        const tokenRes = await computerApi.vncToken(vmId);
        if (cancelled) return;

        const sessionId = `pty_${Date.now().toString(36)}`;
        let ptyPath =
          tokenRes.ws_pty_url ||
          `/ws/v1/computers/${encodeURIComponent(vmId)}/pty/${sessionId}?cap_token=${encodeURIComponent(tokenRes.cap_token)}`;
        if (ptyPath.includes('{session_id}')) {
          ptyPath = ptyPath.replace('{session_id}', sessionId);
        }
        if (activeProject) {
          const sep = ptyPath.includes('?') ? '&' : '?';
          ptyPath = `${ptyPath}${sep}project=${encodeURIComponent(activeProject)}`;
        }

        const ws = new WebSocket(toWsUrl(ptyPath));
        ws.binaryType = 'arraybuffer';
        wsRef.current = ws;

        ws.onopen = () => {
          if (cancelled) return;
          attemptRef.current = 0;
          setStatus('connected');
          setNotice(null);
          sendResize();
        };

        ws.onmessage = (ev) => {
          if (cancelled) return;
          const term = termRef.current;
          if (!term) return;
          if (ev.data instanceof ArrayBuffer) {
            term.write(new Uint8Array(ev.data));
          } else if (typeof ev.data === 'string') {
            term.write(ev.data);
          }
        };

        ws.onclose = (ev) => {
          if (wsRef.current === ws) {
            wsRef.current = null;
          }
          if (cancelled) return;

          if (ev.code === 1000) {
            setStatus('disconnected');
            setNotice({ tone: 'info', text: 'PTY session exited cleanly (1000).' });
            termRef.current?.writeln('\r\n\x1b[90m[Session exited (1000)]\x1b[0m');
            return;
          }

          if (ev.code === 4401) {
            const msg = 'PTY authentication / capability token rejected or expired (4401).';
            setNotice({ tone: 'error', text: msg });
            termRef.current?.writeln(`\r\n\x1b[31m[${msg}]\x1b[0m`);
            scheduleReconnect(4401);
            return;
          }

          if (ev.code === 1008) {
            const msg = activeProject
              ? `Invalid or inaccessible project "${activeProject}" (1008).`
              : 'Invalid workspace project (1008).';
            setStatus('disconnected');
            setNotice({ tone: 'error', text: msg });
            termRef.current?.writeln(`\r\n\x1b[31m[${msg}]\x1b[0m`);
            return;
          }

          termRef.current?.writeln(`\r\n\x1b[33m[PTY disconnected (code ${ev.code})]\x1b[0m`);
          scheduleReconnect(ev.code);
        };

        ws.onerror = () => {
          if (!cancelled) {
            setNotice({ tone: 'error', text: 'PTY WebSocket connection error.' });
          }
        };
      } catch (err) {
        if (!cancelled) {
          const msg = err instanceof Error ? err.message : 'Unable to connect';
          setNotice({ tone: 'error', text: `Terminal error: ${msg}` });
          termRef.current?.writeln(`\r\n\x1b[31mTerminal error: ${msg}\x1b[0m`);
          scheduleReconnect();
        }
      }
    };

    void connect();

    return () => {
      cancelled = true;
      if (reconnectTimer !== null) window.clearTimeout(reconnectTimer);
      if (wsRef.current) {
        try {
          wsRef.current.close();
        } catch {
          // ignore
        }
        wsRef.current = null;
      }
    };
  }, [vmId, activeProject, reconnectNonce]);

  const handleReconnect = () => {
    attemptRef.current = 0;
    setNotice(null);
    setReconnectNonce((n) => n + 1);
  };

  const sendSigInt = () => {
    const ws = wsRef.current;
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ op: 'signal', sig: 'SIGINT' }));
    }
  };

  const clearTerm = () => {
    termRef.current?.clear();
  };

  return (
    <div className="h-full flex flex-col p-3 gap-2.5">
      {/* Terminal Card — Protected Dark Surface (#18191C) inside Light Mode */}
      <div
        className="flex-1 min-h-0 flex flex-col rounded-xl overflow-hidden"
        style={{
          backgroundColor: 'var(--bg-terminal)',
          border: '1px solid var(--border-strong)',
          boxShadow: 'var(--shadow-sm)',
        }}
      >
        <div
          className="flex items-center justify-between gap-2 px-3 py-2 shrink-0 text-[12px]"
          style={{
            backgroundColor: 'rgba(255, 255, 255, 0.04)',
            borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
            color: '#D1D5DB',
          }}
        >
          <div className="flex items-center gap-2 min-w-0">
            <TerminalSquare size={14} className="text-[#A78BFA] shrink-0" />
            <span className="font-mono truncate">
              bot@cloud: ~{activeProject ? `/${activeProject}` : ''}
            </span>
            <span
              role="status"
              aria-label={`Terminal status: ${status}`}
              className="w-2 h-2 rounded-full shrink-0"
              style={{
                backgroundColor:
                  status === 'connected'
                    ? '#4ADE80'
                    : status === 'connecting'
                      ? '#FBBF24'
                      : '#F87171',
              }}
              title={status}
            />
          </div>

          <div className="flex items-center gap-1 shrink-0">
            <button
              type="button"
              onClick={sendSigInt}
              disabled={status !== 'connected'}
              title="Send Ctrl+C (SIGINT)"
              aria-label="Send Ctrl+C (SIGINT)"
              className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-[11.5px] hover:bg-white/10 disabled:opacity-40"
            >
              <Ban size={12} />
              Ctrl+C
            </button>
            <button
              type="button"
              onClick={clearTerm}
              title="Clear terminal"
              aria-label="Clear terminal"
              className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-[11.5px] hover:bg-white/10"
            >
              <Eraser size={12} />
              Clear
            </button>
            <button
              type="button"
              onClick={handleReconnect}
              title="Reconnect PTY"
              aria-label="Reconnect PTY"
              className="inline-flex items-center gap-1 px-2 py-1 rounded-md text-[11.5px] hover:bg-white/10"
            >
              <RefreshCw size={12} />
              Reconnect
            </button>
          </div>
        </div>

        {notice && (
          <div
            role="alert"
            className="px-3 py-1.5 text-[11.5px] flex items-center justify-between gap-2 shrink-0"
            style={{
              backgroundColor:
                notice.tone === 'error'
                  ? 'rgba(248, 113, 113, 0.14)'
                  : 'rgba(255, 255, 255, 0.06)',
              borderBottom:
                notice.tone === 'error'
                  ? '1px solid rgba(248, 113, 113, 0.28)'
                  : '1px solid rgba(255, 255, 255, 0.08)',
              color: notice.tone === 'error' ? '#FCA5A5' : '#D1D5DB',
            }}
          >
            <span className="truncate">{notice.text}</span>
            <button
              type="button"
              onClick={handleReconnect}
              className="underline font-medium shrink-0 hover:text-white"
            >
              Reconnect
            </button>
          </div>
        )}

        <div ref={containerRef} className="flex-1 min-h-0 p-2 overflow-hidden" />
      </div>
    </div>
  );
};
