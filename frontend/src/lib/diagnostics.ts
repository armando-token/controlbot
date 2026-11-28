import { withAuthToken } from './api';

export interface ClientErrorReport {
  kind: string;
  message: string;
  stack?: string | null;
  component_stack?: string | null;
  url?: string | null;
  page_url?: string | null;
  method?: string | null;
  status_code?: number | null;
  request_id?: string | null;
  extra?: Record<string, unknown>;
}

const SENSITIVE_PARAMS = new Set([
  'token',
  'cap_token',
  'access_token',
  'auth',
  'key',
  'api_key',
  'secret',
  'password',
  'webhook_key',
]);

let installed = false;
let sending = false;
const recentTimestamps: number[] = [];
const MAX_REPORTS_PER_WINDOW = 30;
const WINDOW_MS = 10_000;

export function scrubUrlForLog(raw: string): string {
  if (!raw) return '';
  try {
    const parsed = new URL(raw, typeof window !== 'undefined' ? window.location.origin : 'http://localhost');
    const keys = Array.from(parsed.searchParams.keys());
    for (const k of keys) {
      const low = k.toLowerCase();
      if (
        SENSITIVE_PARAMS.has(low) ||
        low.includes('token') ||
        low.includes('secret') ||
        low.includes('password') ||
        low.includes('key')
      ) {
        parsed.searchParams.set(k, '[REDACTED]');
      }
    }
    if (raw.startsWith('/')) {
      return `${parsed.pathname}${parsed.search}${parsed.hash}`.slice(0, 600);
    }
    return parsed.toString().slice(0, 600);
  } catch {
    return raw.replace(/([?&](?:token|cap_token|key|secret)=)[^&#]*/gi, '$1[REDACTED]').slice(0, 600);
  }
}

function allowReportNow(): boolean {
  const now = Date.now();
  while (recentTimestamps.length > 0 && now - (recentTimestamps[0] ?? 0) > WINDOW_MS) {
    recentTimestamps.shift();
  }
  if (recentTimestamps.length >= MAX_REPORTS_PER_WINDOW) {
    return false;
  }
  recentTimestamps.push(now);
  return true;
}

function stringifyArg(arg: unknown): string {
  if (typeof arg === 'string') return arg;
  if (arg instanceof Error) return `${arg.name}: ${arg.message}`;
  try {
    return JSON.stringify(arg);
  } catch {
    return String(arg);
  }
}

export function reportClientError(report: ClientErrorReport): void {
  if (typeof window === 'undefined' || sending) return;
  if (report.url && report.url.includes('/api/v1/diagnostics/')) return;
  if (!allowReportNow()) return;

  sending = true;
  try {
    const payload = {
      kind: report.kind.slice(0, 64),
      message: report.message.slice(0, 2000),
      stack: report.stack ? report.stack.slice(0, 8000) : null,
      component_stack: report.component_stack ? report.component_stack.slice(0, 4000) : null,
      url: report.url ? scrubUrlForLog(report.url) : null,
      page_url: scrubUrlForLog(report.page_url ?? window.location.href),
      method: report.method ? report.method.slice(0, 16) : null,
      status_code: typeof report.status_code === 'number' ? report.status_code : null,
      request_id: report.request_id ? report.request_id.slice(0, 128) : null,
      extra: report.extra ?? {},
    };
    const endpoint = withAuthToken('/api/v1/diagnostics/client-error');
    void fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
      keepalive: true,
    }).catch(() => {
      // Silently swallow telemetry failures to prevent recursive errors.
    });
  } catch {
    // Ignore synchronous serialization errors.
  } finally {
    sending = false;
  }
}

export function installGlobalDiagnostics(): void {
  if (typeof window === 'undefined' || installed) return;
  installed = true;

  window.addEventListener(
    'error',
    (event: Event) => {
      if (event instanceof ErrorEvent) {
        const err = event.error as Error | undefined;
        reportClientError({
          kind: 'window_error',
          message: event.message || err?.message || 'Uncaught window error',
          stack: err?.stack ?? `${event.filename || 'unknown'}:${event.lineno}:${event.colno}`,
          url: event.filename || null,
        });
        return;
      }
      const target = event.target as HTMLElement | null;
      if (target && (target.tagName === 'SCRIPT' || target.tagName === 'LINK' || target.tagName === 'IMG')) {
        const src =
          (target as HTMLScriptElement).src ||
          (target as HTMLLinkElement).href ||
          (target as HTMLImageElement).src ||
          '';
        reportClientError({
          kind: 'resource_load_error',
          message: `Failed to load <${target.tagName.toLowerCase()}> resource`,
          url: src || null,
        });
      }
    },
    true,
  );

  window.addEventListener('unhandledrejection', (event: PromiseRejectionEvent) => {
    const reason = event.reason;
    const isErr = reason instanceof Error;
    reportClientError({
      kind: 'unhandled_rejection',
      message: isErr ? `${reason.name}: ${reason.message}` : stringifyArg(reason),
      stack: isErr ? reason.stack ?? null : null,
    });
  });

  const origConsoleError = console.error.bind(console);
  console.error = (...args: unknown[]) => {
    origConsoleError(...args);
    const firstErr = args.find((a): a is Error => a instanceof Error);
    const msg = args.map(stringifyArg).join(' ').slice(0, 1800);
    reportClientError({
      kind: 'console_error',
      message: msg || 'console.error invoked',
      stack: firstErr?.stack ?? null,
    });
  };
}
