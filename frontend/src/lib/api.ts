import type {
  AgyModelsResponse,
  AppSettings,
  ApprovalCard,
  ApprovalDecision,
  Artifact,
  Attachment,
  AutoReviewRule,
  Bot,
  Channel,
  ComputerStatus,
  ConnectedApp,
  DraftCard,
  LibraryResponse,
  LocalProjectsResponse,
  MemoryCreateRequest,
  MemoryItem,
  MemoryKind,
  MemoryPatchRequest,
  MemoryScope,
  Message,
  RosterResponse,
  Routine,
  RoutineRun,
  RuntimeTaskSnapshot,
  SearchResults,
  Section,
  SecureFormCard,
  ShareScope,
  Skill,
  SystemInfo,
  ThreadMessagesResponse,
  UsageStats,
  VaultSecretMeta,
  VncTokenResponse,
  WorkspaceFileRead,
  WorkspaceFilesListing,
} from './types';
import { reportClientError } from './diagnostics';

export class ApiError extends Error {
  status: number;
  detail: string;

  constructor(status: number, detail: string) {
    super(detail || `Request failed (${status})`);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

export function getAuthToken(): string | null {
  if (typeof window === 'undefined') return null;
  const params = new URLSearchParams(window.location.search);
  const token = params.get('token');
  return token && token.trim() ? token.trim() : null;
}

export function withAuthToken(url: string): string {
  const token = getAuthToken();
  if (!token) return url;
  const hasQuery = url.includes('?');
  if (/(?:[?&])token=/.test(url)) return url;
  const sep = hasQuery ? '&' : '?';
  return `${url}${sep}token=${encodeURIComponent(token)}`;
}

export function toWsUrl(pathOrUrl: string): string {
  const authed = withAuthToken(pathOrUrl);
  if (/^wss?:\/\//i.test(authed)) return authed;
  if (/^https?:\/\//i.test(authed)) {
    return authed.replace(/^http/i, 'ws');
  }
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const normalized = authed.startsWith('/') ? authed : `/${authed}`;
  return `${proto}//${window.location.host}${normalized}`;
}

export function newIdempotencyKey(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return `idem_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
}

async function parseErrorDetail(res: Response): Promise<string> {
  try {
    const text = await res.text();
    if (!text) return res.statusText || `HTTP ${res.status}`;
    const parsed = JSON.parse(text);
    if (typeof parsed === 'string') return parsed;
    if (typeof parsed?.detail === 'string') return parsed.detail;
    if (Array.isArray(parsed?.detail)) {
      return parsed.detail
        .map((e: { msg?: string; loc?: string[] }) => e?.msg || JSON.stringify(e))
        .join('; ');
    }
    return text.slice(0, 260);
  } catch {
    return res.statusText || `HTTP ${res.status}`;
  }
}

export async function apiFetch<T>(
  url: string,
  options: RequestInit & { idempotencyKey?: string } = {},
): Promise<T> {
  const { idempotencyKey, headers, body, ...rest } = options;
  const finalHeaders = new Headers(headers);
  if (
    body !== undefined &&
    body !== null &&
    !(body instanceof FormData) &&
    !(body instanceof Blob) &&
    !(body instanceof ArrayBuffer) &&
    !finalHeaders.has('Content-Type')
  ) {
    finalHeaders.set('Content-Type', 'application/json');
  }
  if (idempotencyKey) {
    finalHeaders.set('Idempotency-Key', idempotencyKey);
  }

  let res: Response;
  try {
    res = await fetch(withAuthToken(url), {
      ...rest,
      headers: finalHeaders,
      body,
    });
  } catch (err) {
    if (err instanceof Error && err.name === 'AbortError') {
      throw err;
    }
    const message = err instanceof Error ? `${err.name}: ${err.message}` : String(err);
    reportClientError({
      kind: 'fetch_network_error',
      message,
      stack: err instanceof Error ? err.stack ?? null : null,
      url,
      method: (rest.method ?? 'GET').toUpperCase(),
    });
    throw err;
  }

  if (!res.ok) {
    const detail = await parseErrorDetail(res);
    reportClientError({
      kind: 'api_http_error',
      message: detail,
      url,
      method: (rest.method ?? 'GET').toUpperCase(),
      status_code: res.status,
      request_id: res.headers.get('x-request-id'),
    });
    throw new ApiError(res.status, detail);
  }

  if (res.status === 204) {
    return undefined as T;
  }

  const contentType = res.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    return (await res.json()) as T;
  }
  return (await res.text()) as unknown as T;
}

export const botsApi = {
  list: () => apiFetch<RosterResponse>('/api/v1/bots'),
  create: (payload: {
    name: string;
    avatar_shape?: string;
    avatar_color?: string;
    avatar_eyes_large?: boolean;
    engine_id?: string;
    model_id?: string;
    thinking_level?: string;
    project_name?: string | null;
    role_prompt?: string;
    about?: string;
    section_id?: string | null;
  }) =>
    apiFetch<Bot>('/api/v1/bots', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  update: (botId: string, patch: Partial<Bot>) =>
    apiFetch<Bot>(`/api/v1/bots/${encodeURIComponent(botId)}`, {
      method: 'PATCH',
      body: JSON.stringify(patch),
    }),
  remove: (botId: string) =>
    apiFetch<{ deleted: boolean; bot_id: string }>(
      `/api/v1/bots/${encodeURIComponent(botId)}`,
      { method: 'DELETE' },
    ),
  cloneTemplate: (botId: string) =>
    apiFetch<{ artifact: Artifact; message: Message }>(
      `/api/v1/bots/${encodeURIComponent(botId)}/clone-template`,
      { method: 'POST' },
    ),
};

export const sectionsApi = {
  create: (name: string) =>
    apiFetch<Section>('/api/v1/sections', {
      method: 'POST',
      body: JSON.stringify({ name }),
    }),
  update: (sectionId: string, patch: Partial<Pick<Section, 'name' | 'sort_order'>>) =>
    apiFetch<Section>(`/api/v1/sections/${encodeURIComponent(sectionId)}`, {
      method: 'PATCH',
      body: JSON.stringify(patch),
    }),
  remove: (sectionId: string) =>
    apiFetch<{ deleted: boolean }>(
      `/api/v1/sections/${encodeURIComponent(sectionId)}`,
      { method: 'DELETE' },
    ),
};

export const channelsApi = {
  create: (payload: { name: string; bot_ids: string[]; section_id?: string | null }) =>
    apiFetch<Channel>('/api/v1/channels', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  update: (channelId: string, patch: Partial<Channel>) =>
    apiFetch<Channel>(`/api/v1/channels/${encodeURIComponent(channelId)}`, {
      method: 'PATCH',
      body: JSON.stringify(patch),
    }),
  remove: (channelId: string) =>
    apiFetch<{ deleted: boolean }>(
      `/api/v1/channels/${encodeURIComponent(channelId)}`,
      { method: 'DELETE' },
    ),
};

export const threadsApi = {
  messages: (threadId: string, opts?: { limit?: number; beforeId?: string }) => {
    const params = new URLSearchParams();
    params.set('limit', String(opts?.limit ?? 50));
    if (opts?.beforeId) params.set('before_id', opts.beforeId);
    return apiFetch<ThreadMessagesResponse>(
      `/api/v1/threads/${encodeURIComponent(threadId)}/messages?${params.toString()}`,
    );
  },
  send: (
    threadId: string,
    payload: {
      content: string;
      reply_to_id?: string | null;
      mentions?: string[];
      attachment_ids?: string[];
      include_browser_context?: boolean | null;
      model_id?: string | null;
      override_model_id?: string | null;
      thinking_level?: string | null;
      override_thinking_level?: string | null;
      page_context_id?: string | null;
      skill_ids?: string[];
    },
    options?: { signal?: AbortSignal },
  ) =>
    apiFetch<{ user_message: Message; turn_id: string; status: string }>(
      `/api/v1/threads/${encodeURIComponent(threadId)}/messages`,
      {
        method: 'POST',
        body: JSON.stringify(payload),
        signal: options?.signal,
      },
    ),
  interrupt: (threadId: string) =>
    apiFetch<{ interrupted: boolean; thread_id: string }>(
      `/api/v1/threads/${encodeURIComponent(threadId)}/interrupt`,
      { method: 'POST' },
    ),
  react: (messageId: string, emoji: string) =>
    apiFetch<Message>(`/api/v1/messages/${encodeURIComponent(messageId)}/reactions`, {
      method: 'POST',
      body: JSON.stringify({ emoji }),
    }),
  toPage: (messageId: string, title?: string) =>
    apiFetch<{ page: Artifact; message: Message }>(
      `/api/v1/messages/${encodeURIComponent(messageId)}/to-page`,
      {
        method: 'POST',
        body: JSON.stringify(title ? { title } : {}),
      },
    ),
};

export const attachmentsApi = {
  upload: async (file: File, threadId?: string): Promise<Attachment> => {
    const params = new URLSearchParams();
    params.set('filename', file.name);
    if (threadId) params.set('thread_id', threadId);
    const form = new FormData();
    form.append('file', file, file.name);
    return apiFetch<Attachment>(`/api/v1/attachments?${params.toString()}`, {
      method: 'POST',
      body: form,
    });
  },
  downloadUrl: (attachmentId: string) =>
    withAuthToken(`/api/v1/attachments/${encodeURIComponent(attachmentId)}`),
};

export const libraryApi = {
  list: (botId: string, opts?: { type?: string; pinned?: boolean; q?: string }) => {
    const params = new URLSearchParams();
    params.set('type', opts?.type ?? 'all');
    params.set('pinned', String(Boolean(opts?.pinned)));
    if (opts?.q) params.set('q', opts.q);
    return apiFetch<LibraryResponse>(
      `/api/v1/bots/${encodeURIComponent(botId)}/library?${params.toString()}`,
    );
  },
  togglePin: (artifactId: string, pinned: boolean) =>
    apiFetch<Artifact>(`/api/v1/artifacts/${encodeURIComponent(artifactId)}/pin`, {
      method: 'PATCH',
      body: JSON.stringify({ pinned }),
    }),
  remove: (artifactId: string) =>
    apiFetch<{ deleted: boolean }>(
      `/api/v1/artifacts/${encodeURIComponent(artifactId)}`,
      { method: 'DELETE' },
    ),
};

export const pagesApi = {
  create: (payload: {
    bot_id?: string | null;
    channel_id?: string | null;
    thread_id?: string | null;
    title: string;
    content_md: string;
    share_scope?: ShareScope;
  }) =>
    apiFetch<Artifact>('/api/v1/pages', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  get: (pageId: string) =>
    apiFetch<Artifact>(`/api/v1/pages/${encodeURIComponent(pageId)}`),
  update: (
    pageId: string,
    patch: Partial<Pick<Artifact, 'title' | 'content_md' | 'share_scope' | 'pinned'>>,
  ) =>
    apiFetch<Artifact>(`/api/v1/pages/${encodeURIComponent(pageId)}`, {
      method: 'PATCH',
      body: JSON.stringify(patch),
    }),
};

export const hitlApi = {
  resolveApproval: (
    approvalId: string,
    decision: ApprovalDecision,
    extra?: { rule_text?: string },
  ) =>
    apiFetch<ApprovalCard>(
      `/api/v1/approvals/${encodeURIComponent(approvalId)}/resolve`,
      {
        method: 'POST',
        idempotencyKey: newIdempotencyKey(),
        body: JSON.stringify({ decision, ...extra }),
      },
    ),
  resolveDraft: (
    draftId: string,
    action: 'send' | 'discard',
    fields?: Record<string, unknown>,
  ) =>
    apiFetch<DraftCard>(`/api/v1/drafts/${encodeURIComponent(draftId)}/resolve`, {
      method: 'POST',
      idempotencyKey: newIdempotencyKey(),
      body: JSON.stringify({ action, fields }),
    }),
  secureFill: (payload: {
    form_id: string;
    bot_id?: string | null;
    domain: string;
    values?: Record<string, string>;
    save_to_vault?: boolean;
    secret_name?: string;
    secret_id?: string | null;
    action?: 'submit' | 'cancel';
  }) =>
    apiFetch<{
      filled: boolean;
      saved_secret_id: string | null;
      message: string;
      status?: string;
      reason?: string;
      url?: string | null;
    }>('/api/v1/vault/secure-fill', {
      method: 'POST',
      idempotencyKey: newIdempotencyKey(),
      body: JSON.stringify({
        ...payload,
        values: payload.values ?? {},
        save_to_vault: payload.save_to_vault ?? false,
      }),
    }),
  createApproval: (payload: Partial<ApprovalCard>) =>
    apiFetch<ApprovalCard>('/api/v1/approvals', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  createSecureForm: (payload: Partial<SecureFormCard>) =>
    apiFetch<SecureFormCard>('/api/v1/secure-forms', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
};

export const vaultApi = {
  list: (botId?: string) => {
    const query = botId ? `?bot_id=${encodeURIComponent(botId)}` : '';
    return apiFetch<{ secrets: VaultSecretMeta[] }>(`/api/v1/vault/secrets${query}`);
  },
  create: (payload: {
    bot_id?: string | null;
    name: string;
    domain?: string | null;
    kind?: string;
    username?: string;
    secret_value?: string;
    value?: string;
    fields?: Record<string, string>;
  }) =>
    apiFetch<VaultSecretMeta>('/api/v1/vault/secrets', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  remove: (secretId: string) =>
    apiFetch<{ deleted: boolean }>(
      `/api/v1/vault/secrets/${encodeURIComponent(secretId)}`,
      { method: 'DELETE' },
    ),
};

export const routinesApi = {
  list: (botId: string) =>
    apiFetch<{ routines: Routine[] }>(
      `/api/v1/bots/${encodeURIComponent(botId)}/routines`,
    ),
  create: (
    botId: string,
    payload: {
      name: string;
      instruction: string;
      schedule_type: 'cron' | 'webhook' | 'manual';
      cron_expr?: string | null;
      timezone?: string;
      visibility?: 'only_me' | 'team';
    },
  ) =>
    apiFetch<Routine>(`/api/v1/bots/${encodeURIComponent(botId)}/routines`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  update: (
    routineId: string,
    patch: Partial<Routine> & { regenerate_webhook_key?: boolean },
  ) =>
    apiFetch<Routine>(`/api/v1/routines/${encodeURIComponent(routineId)}`, {
      method: 'PATCH',
      body: JSON.stringify(patch),
    }),
  remove: (routineId: string) =>
    apiFetch<{ deleted: boolean }>(
      `/api/v1/routines/${encodeURIComponent(routineId)}`,
      { method: 'DELETE' },
    ),
  test: (routineId: string) =>
    apiFetch<RoutineRun>(`/api/v1/routines/${encodeURIComponent(routineId)}/test`, {
      method: 'POST',
    }),
  runs: (routineId: string) =>
    apiFetch<{ runs: RoutineRun[] }>(
      `/api/v1/routines/${encodeURIComponent(routineId)}/runs`,
    ),
};

export const skillsApi = {
  list: (botId?: string) => {
    const query = botId ? `?bot_id=${encodeURIComponent(botId)}` : '';
    return apiFetch<{ skills: Skill[] }>(`/api/v1/skills${query}`);
  },
  create: (payload: {
    bot_id?: string | null;
    name: string;
    description?: string;
    content_md?: string;
    instruction_md?: string;
    source?: 'custom' | 'taught' | 'system' | string;
  }) =>
    apiFetch<Skill>('/api/v1/skills', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  remove: (skillId: string) =>
    apiFetch<{ deleted: boolean }>(`/api/v1/skills/${encodeURIComponent(skillId)}`, {
      method: 'DELETE',
    }),
};

export const settingsApi = {
  get: () => apiFetch<AppSettings>('/api/v1/settings'),
  update: (patch: Partial<AppSettings>) =>
    apiFetch<AppSettings>('/api/v1/settings', {
      method: 'PATCH',
      body: JSON.stringify(patch),
    }),
  getAutoReview: () =>
    apiFetch<{ rules: AutoReviewRule[] }>('/api/v1/settings/auto-review'),
  putAutoReview: (rules: AutoReviewRule[]) =>
    apiFetch<{ rules: AutoReviewRule[] }>('/api/v1/settings/auto-review', {
      method: 'PUT',
      body: JSON.stringify({ rules }),
    }),
};

export const appsApi = {
  list: () => apiFetch<{ apps: ConnectedApp[] }>('/api/v1/apps'),
  update: (
    appId: string,
    patch: Partial<
      Pick<ConnectedApp, 'enabled' | 'connected' | 'status' | 'account_label' | 'config'>
    >,
  ) =>
    apiFetch<ConnectedApp>(`/api/v1/apps/${encodeURIComponent(appId)}`, {
      method: 'PATCH',
      body: JSON.stringify(patch),
    }),
};

export interface MemoryListParams {
  scope?: MemoryScope | '';
  scope_id?: string;
  kind?: MemoryKind | '';
  q?: string;
  include_expired?: boolean;
  user_id?: string;
  actor_role?: string;
  agent_role?: string;
  thread_id?: string;
  project_area?: string;
}

export interface MemoryExportParams {
  format?: 'json' | 'md';
  scope?: MemoryScope | '';
  scope_id?: string;
  kind?: MemoryKind | '';
  q?: string;
  include_expired?: boolean;
}

function buildMemoryExportPath(opts?: MemoryExportParams): string {
  const params = new URLSearchParams();
  params.set('format', opts?.format ?? 'json');
  if (opts?.scope) params.set('scope', opts.scope);
  if (opts?.scope_id) params.set('scope_id', opts.scope_id);
  if (opts?.kind) params.set('kind', opts.kind);
  if (opts?.q) params.set('q', opts.q);
  if (opts?.include_expired) params.set('include_expired', 'true');
  return `/api/v1/memory/export?${params.toString()}`;
}

export const memoryApi = {
  list: (opts?: MemoryListParams) => {
    const params = new URLSearchParams();
    if (opts?.scope) params.set('scope', opts.scope);
    if (opts?.scope_id) params.set('scope_id', opts.scope_id);
    if (opts?.kind) params.set('kind', opts.kind);
    if (opts?.q) params.set('q', opts.q);
    if (opts?.include_expired) params.set('include_expired', 'true');
    if (opts?.user_id) params.set('user_id', opts.user_id);
    if (opts?.actor_role) params.set('actor_role', opts.actor_role);
    if (opts?.agent_role) params.set('agent_role', opts.agent_role);
    if (opts?.thread_id) params.set('thread_id', opts.thread_id);
    if (opts?.project_area) params.set('project_area', opts.project_area);
    const qs = params.toString();
    return apiFetch<{ items: MemoryItem[] }>(`/api/v1/memory${qs ? `?${qs}` : ''}`);
  },
  create: (payload: MemoryCreateRequest) =>
    apiFetch<MemoryItem>('/api/v1/memory', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  update: (itemId: string, patch: MemoryPatchRequest) =>
    apiFetch<MemoryItem>(`/api/v1/memory/${encodeURIComponent(itemId)}`, {
      method: 'PATCH',
      body: JSON.stringify(patch),
    }),
  remove: (itemId: string, opts?: { actor_role?: string }) => {
    const params = new URLSearchParams();
    if (opts?.actor_role) params.set('actor_role', opts.actor_role);
    const qs = params.toString();
    return apiFetch<{ deleted: boolean; id?: string }>(
      `/api/v1/memory/${encodeURIComponent(itemId)}${qs ? `?${qs}` : ''}`,
      { method: 'DELETE' },
    );
  },
  exportUrl: (opts?: MemoryExportParams) => withAuthToken(buildMemoryExportPath(opts)),
  exportData: (opts?: MemoryExportParams) =>
    apiFetch<string | { items: MemoryItem[] }>(buildMemoryExportPath(opts)),
};

export const usageApi = {
  get: () => apiFetch<UsageStats>('/api/v1/usage'),
};

export const searchApi = {
  query: (q: string) =>
    apiFetch<SearchResults>(`/api/v1/search?q=${encodeURIComponent(q)}`),
};

export const computerApi = {
  status: (vmId = 'default') =>
    apiFetch<ComputerStatus>(`/api/v1/computers/${encodeURIComponent(vmId)}/status`),
  vncToken: (vmId = 'default') =>
    apiFetch<VncTokenResponse>(`/api/v1/computers/${encodeURIComponent(vmId)}/vnc-token`, {
      method: 'POST',
    }),
  takeover: (vmId = 'default', reason = 'manual_takeover') =>
    apiFetch<ComputerStatus>(`/api/v1/computers/${encodeURIComponent(vmId)}/takeover`, {
      method: 'POST',
      idempotencyKey: newIdempotencyKey(),
      body: JSON.stringify({ reason }),
    }),
  handback: (vmId = 'default') =>
    apiFetch<ComputerStatus>(`/api/v1/computers/${encodeURIComponent(vmId)}/handback`, {
      method: 'POST',
    }),
  action: (vmId: string, payload: Record<string, unknown>) =>
    apiFetch<{ status: ComputerStatus; browser_status?: unknown; context?: unknown }>(
      `/api/v1/computers/${encodeURIComponent(vmId)}/actions`,
      {
        method: 'POST',
        body: JSON.stringify(payload),
      },
    ),
  listFiles: (vmId = 'default', path = '', project = '') => {
    const params = new URLSearchParams();
    if (path) params.set('path', path);
    if (project) params.set('project', project);
    return apiFetch<WorkspaceFilesListing>(
      `/api/v1/computers/${encodeURIComponent(vmId)}/files?${params.toString()}`,
    );
  },
  readFile: (vmId = 'default', path: string, project = '') => {
    const params = new URLSearchParams({ path });
    if (project) params.set('project', project);
    return apiFetch<WorkspaceFileRead>(
      `/api/v1/computers/${encodeURIComponent(vmId)}/file?${params.toString()}`,
    );
  },
  downloadFileUrl: (vmId = 'default', path: string, project = '') => {
    const params = new URLSearchParams({ path });
    if (project) params.set('project', project);
    return withAuthToken(
      `/api/v1/computers/${encodeURIComponent(vmId)}/file/download?${params.toString()}`,
    );
  },
  uploadFile: (vmId = 'default', file: File, path = '', project = '') => {
    const params = new URLSearchParams({ name: file.name });
    if (path) params.set('path', path);
    if (project) params.set('project', project);
    return apiFetch<{ rel_path: string; size_bytes: number }>(
      `/api/v1/computers/${encodeURIComponent(vmId)}/files/upload?${params.toString()}`,
      {
        method: 'POST',
        headers: {
          'Content-Type': file.type || 'application/octet-stream',
        },
        body: file,
      },
    );
  },
  mkdir: (vmId = 'default', path: string, project = '') =>
    apiFetch<{ rel_path: string }>(
      `/api/v1/computers/${encodeURIComponent(vmId)}/files/mkdir`,
      {
        method: 'POST',
        body: JSON.stringify({ path, project }),
      },
    ),
  writeFile: (vmId = 'default', path: string, content: string, project = '') =>
    apiFetch<{ rel_path: string; size_bytes: number }>(
      `/api/v1/computers/${encodeURIComponent(vmId)}/files/write`,
      {
        method: 'POST',
        body: JSON.stringify({ path, content, project }),
      },
    ),
  deleteFile: (vmId = 'default', path: string, project = '') => {
    const params = new URLSearchParams({ path });
    if (project) params.set('project', project);
    return apiFetch<{ deleted: boolean }>(
      `/api/v1/computers/${encodeURIComponent(vmId)}/files?${params.toString()}`,
      { method: 'DELETE' },
    );
  },
  teachStart: (vmId = 'default', payload: { bot_id?: string | null; name: string }) =>
    apiFetch<ComputerStatus>(`/api/v1/computers/${encodeURIComponent(vmId)}/teach/start`, {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  teachStop: (vmId = 'default', payload?: { bot_id?: string | null }) =>
    apiFetch<{
      status: ComputerStatus;
      skill: Skill;
      artifact?: Artifact;
      message?: Message;
    }>(`/api/v1/computers/${encodeURIComponent(vmId)}/teach/stop`, {
      method: 'POST',
      body: JSON.stringify(payload ?? {}),
    }),
};

export const legacyApi = {
  agyModels: (refresh = false) =>
    apiFetch<AgyModelsResponse>(`/api/agy/models${refresh ? '?refresh=true' : ''}`),
  projects: () => apiFetch<LocalProjectsResponse>('/api/projects'),
  systemInfo: () => apiFetch<SystemInfo>('/api/system/info'),
  tasks: () => apiFetch<{ tasks: RuntimeTaskSnapshot[] }>('/api/tasks'),
  submitTask: (payload: {
    query: string;
    facility_id?: string;
    user_id?: string;
    profile_id?: string;
    read_only?: boolean;
  }) =>
    apiFetch<{ run_id: string; status: string }>('/api/tasks', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),
  cancelTask: (runId: string, reason = 'cancelled_by_user') =>
    apiFetch<unknown>(`/api/tasks/${encodeURIComponent(runId)}/cancel`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    }),
  resumeTask: (runId: string, humanInput: Record<string, unknown>) =>
    apiFetch<unknown>(`/api/tasks/${encodeURIComponent(runId)}/resume`, {
      method: 'POST',
      body: JSON.stringify({ human_input: humanInput }),
    }),
  startBrowser: (url?: string) =>
    apiFetch<Record<string, unknown>>('/api/browser/start', {
      method: 'POST',
      body: JSON.stringify(url ? { url } : {}),
    }),
  stopBrowser: () =>
    apiFetch<Record<string, unknown>>('/api/browser/stop', {
      method: 'POST',
    }),
};
