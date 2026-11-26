export type AvatarShape =
  | 'square'
  | 'sparkle'
  | 'clover'
  | 'flower'
  | 'heart'
  | 'house'
  | 'star';

export type BotLifecycleState =
  | 'idle'
  | 'acknowledging'
  | 'working'
  | 'waiting_human'
  | 'error';

export type ThinkingLevel = 'off' | 'low' | 'medium' | 'high' | 'max';

export type EngineId = 'agy' | 'controlbot_runtime';

export type ThemeMode = 'light' | 'dark' | 'system';

export type AccentMode = 'bot_color' | 'black';

export type InspectorTab = 'details' | 'library' | 'computer';

export type ControlOwner =
  | 'agent'
  | 'human_takeover'
  | 'disconnected'
  | 'reconnecting';

export interface Section {
  id: string;
  name: string;
  sort_order: number;
  created_at: string;
}

export interface Bot {
  id: string;
  thread_id: string;
  name: string;
  role_prompt: string;
  about: string;
  avatar_shape: AvatarShape;
  avatar_color: string;
  avatar_eyes_large: boolean;
  engine_id: EngineId;
  model_id: string;
  thinking_level: ThinkingLevel;
  project_name: string | null;
  pinned: boolean;
  section_id: string | null;
  hidden: boolean;
  is_primary: boolean;
  is_team_bot: boolean;
  unread_count: number;
  needs_attention: boolean;
  status_state: BotLifecycleState;
  status_subtext: string;
  computer_active: boolean;
  timezone: string;
  drafts_enabled: boolean;
  conversation_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface Channel {
  id: string;
  thread_id: string;
  name: string;
  bot_ids: string[];
  pinned: boolean;
  section_id: string | null;
  hidden: boolean;
  unread_count: number;
  created_at: string;
  updated_at: string;
}

export interface RosterResponse {
  bots: Bot[];
  sections: Section[];
  channels: Channel[];
}

export interface Attachment {
  id: string;
  filename: string;
  mime_type: string;
  size_bytes: number;
  thread_id?: string | null;
  created_at?: string;
}

export interface ToolCallItem {
  call_id: string;
  tool_name: string;
  category: 'browser' | 'terminal' | 'file' | 'mcp' | 'search' | string;
  status: 'running' | 'ok' | 'error' | string;
  summary: string;
  output_preview?: string;
}

export interface ArtifactRef {
  id: string;
  type: ArtifactType;
  title: string;
  version: number;
  superseded_by_id: string | null;
}

export interface MemoryDiff {
  action: 'saved' | 'updated' | 'forgotten' | string;
  text: string;
}

export type VerdictState =
  | 'verified'
  | 'contradicted'
  | 'not_documented'
  | 'partial_evidence'
  | 'stale_data'
  | 'asset_not_found'
  | 'needs_clarification';

export interface AirlockProvenance {
  plant_sources?: string[];
  web_sources?: string[];
  airlock_audit_id?: string | null;
  projected_fields?: Record<string, string>;
  planta_summary?: string;
  web_summary?: string;
  [key: string]: unknown;
}

export interface ExcelVerification {
  passed?: boolean;
  verdict?: VerdictState;
  formulas_total?: number;
  formulas_ok?: number;
  formula_errors?: string[];
  errors?: string[];
  recalc_engine?: 'libreoffice' | 'ooxml_evaluator' | string;
  mixed_currency?: boolean;
  mixed_currencies_detected?: boolean;
  mixed_currency_details?: string[];
  badge?: string;
  verified?: boolean;
  [key: string]: unknown;
}

export interface ClarificationCandidate {
  id?: string;
  label?: string;
  canonical_label?: string;
  asset_id?: string;
  area?: string;
  location_display?: string;
  description?: string;
  confidence?: number;
  score?: number | string;
  [key: string]: unknown;
}

export interface NearestAsset {
  id?: string;
  name?: string;
  canonical_label?: string;
  tag?: string;
  area?: string;
  location_display?: string;
  distance?: number;
  score?: number | string;
  [key: string]: unknown;
}

export interface StaleInfo {
  observed_at?: string;
  age_seconds?: number;
  ttl_seconds?: number;
  reason?: string;
  [key: string]: unknown;
}

export interface DegradedBanner {
  code?: string;
  message: string;
  severity?: 'info' | 'warn' | 'error' | string;
  [key: string]: unknown;
}

export interface ReconcileSplit {
  agreements?: string[];
  contradictions?: Array<string | Record<string, unknown>>;
  partial_evidence?: string[];
  missing_attributes?: string[];
  [key: string]: unknown;
}

export interface MessageMetadata {
  verdict?: VerdictState;
  lane?: 'general' | 'industrial' | 'mixed' | string;
  domain_profile?: string;
  agreements?: string[];
  contradictions?: Array<string | Record<string, unknown>>;
  partial_evidence?: string[];
  missing_attributes?: string[];
  airlock_provenance?: AirlockProvenance | null;
  excel_verification?: ExcelVerification | null;
  clarification_candidates?: ClarificationCandidate[];
  nearest_assets?: NearestAsset[];
  stale_info?: StaleInfo | null;
  degraded_banner?: DegradedBanner | string | null;
  reconcile?: ReconcileSplit | null;
  citations?: string[];
  [key: string]: unknown;
}

export interface Message {
  id: string;
  thread_id: string;
  sender_type: 'user' | 'bot' | 'system';
  sender_bot_id: string | null;
  sender_name: string;
  content: string;
  thinking_text: string;
  reply_to_id: string | null;
  mentions: string[];
  attachments: Attachment[];
  tool_calls: ToolCallItem[];
  artifacts: ArtifactRef[];
  reactions: Record<string, number>;
  memory_diffs: MemoryDiff[];
  conversation_id: string | null;
  model_id: string | null;
  status: 'streaming' | 'done' | 'error' | 'interrupted' | string;
  metadata?: MessageMetadata | Record<string, unknown> | null;
  metadata_json?: MessageMetadata | Record<string, unknown> | null;
  created_at: string;
}

export type ArtifactType = 'page' | 'media' | 'link' | 'file' | 'app' | 'skill';

export type ShareScope = 'private' | 'team' | 'public';

export interface Artifact {
  id: string;
  bot_id: string | null;
  thread_id: string | null;
  message_id: string | null;
  type: ArtifactType;
  title: string;
  content_md: string;
  url: string | null;
  file_path: string | null;
  mime_type: string;
  size_bytes: number;
  pinned: boolean;
  share_scope: ShareScope;
  version: number;
  superseded_by_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface LibraryResponse {
  items: Artifact[];
  grouped: {
    pinned: Artifact[];
    today: Artifact[];
    this_week: Artifact[];
    older: Artifact[];
  };
}

export type ApprovalKind =
  | 'standard'
  | 'terminal'
  | 'ask_first'
  | 'reconnect'
  | 'takeover';

export type ApprovalStatus =
  | 'pending'
  | 'allowed_once'
  | 'allowed_always'
  | 'denied'
  | 'skipped'
  | 'expired';

export type ApprovalDecision = 'allow_once' | 'always_allow' | 'deny' | 'skip';

export interface ApprovalCard {
  id: string;
  bot_id: string;
  thread_id: string;
  kind: ApprovalKind;
  title: string;
  target: string;
  risk_banner: string | null;
  arguments: Record<string, unknown>;
  status: ApprovalStatus;
  allow_always_allowed: boolean;
  waiting_for_user: string | null;
  decision_by: string | null;
  expires_at: string | null;
  created_at: string;
  resolved_at: string | null;
}

export interface DraftFields {
  from?: string;
  to?: string;
  bcc?: string;
  subject?: string;
  body?: string;
  attachments?: string[];
  remove_signature?: boolean;
  [key: string]: unknown;
}

export interface DraftCard {
  id: string;
  bot_id: string;
  thread_id: string;
  channel_type: 'email' | 'slack' | 'x' | string;
  fields: DraftFields;
  status: 'pending' | 'sent' | 'discarded' | string;
  created_at: string;
  resolved_at: string | null;
}

export interface SecureFormField {
  name: string;
  label: string;
  secret: boolean;
  required?: boolean;
  placeholder?: string;
  type?: string;
}

export interface SecureFormCard {
  id: string;
  bot_id: string;
  thread_id: string;
  kind: 'form' | 'secret' | string;
  domain: string;
  title: string;
  fields: SecureFormField[];
  allow_vault_save: boolean;
  status: 'pending' | 'submitted' | 'cancelled' | 'filled' | 'saved' | string;
  created_at: string;
  resolved_at: string | null;
}

export interface ThreadMessagesResponse {
  thread_id: string;
  messages: Message[];
  approvals: ApprovalCard[];
  drafts: DraftCard[];
  secure_forms: SecureFormCard[];
  has_more: boolean;
}

export interface Routine {
  id: string;
  bot_id: string;
  name: string;
  instruction: string;
  schedule_type: 'cron' | 'webhook' | 'manual';
  cron_expr: string | null;
  timezone: string;
  enabled: boolean;
  webhook_key: string;
  webhook_url: string;
  visibility: 'only_me' | 'team';
  last_run_at: string | null;
  created_at: string;
  updated_at: string;
}

export interface RoutineRun {
  id: string;
  routine_id: string;
  bot_id: string;
  trigger: 'schedule' | 'manual' | 'webhook' | string;
  status: 'running' | 'succeeded' | 'failed' | string;
  summary: string | null;
  error: string | null;
  message_id?: string | null;
  started_at: string;
  finished_at: string | null;
}

export interface Skill {
  id: string;
  bot_id: string | null;
  name: string;
  slug: string;
  description: string;
  content_md?: string;
  instruction_md: string;
  source?: 'custom' | 'taught' | 'system' | string;
  created_at: string;
  updated_at?: string;
}

export interface VaultSecretMeta {
  id: string;
  bot_id: string | null;
  name: string;
  domain: string | null;
  kind: string;
  username_hint?: string;
  field_names?: string[];
  created_at: string;
  updated_at?: string;
}

export interface AutoReviewRule {
  id: string;
  mode: 'allow_auto' | 'ask_first';
  text: string;
  locked_by_admin?: boolean;
}

export interface AppSettings {
  theme: ThemeMode;
  accent_mode: AccentMode;
  display_name?: string;
  default_engine_id?: EngineId;
  default_engine: EngineId;
  default_model_id?: string;
  default_model: string;
  default_thinking_level: ThinkingLevel;
  default_project_name?: string | null;
  allow_hydrogen: boolean;
  include_browser_context?: boolean;
  notifications_enabled: boolean;
  sound_enabled?: boolean;
  auto_open_computer?: boolean;
  timezone: string;
  updated_at?: string;
  [key: string]: unknown;
}

export interface ConnectedApp {
  id: string;
  name: string;
  category: string;
  description: string;
  enabled?: boolean;
  connected: boolean;
  status?: string;
  account_label: string;
  config?: Record<string, unknown>;
  scopes?: string[];
  updated_at?: string;
}

export interface UsageStats {
  bots_count: number;
  channels_count: number;
  messages_count: number;
  pages_count: number;
  routines_count: number;
  routine_runs_count: number;
  approvals_count: number;
  active_turns: number;
}

export interface SearchResults {
  bots: Bot[];
  channels: Channel[];
  messages: Message[];
  pages: Artifact[];
  routines: Routine[];
  skills: Skill[];
}

export interface ComputerStatus {
  vm_id: string;
  status: 'off' | 'starting' | 'ready' | 'reconnecting' | 'error' | string;
  control_owner: ControlOwner;
  lease_id: string | null;
  lease_expires_at: string | null;
  vnc_available: boolean;
  browser_running: boolean;
  active_url: string;
  active_tab_title: string;
  active_step_summary: string | null;
  is_teaching_task: boolean;
  teach_name: string | null;
  teach_steps_count: number;
  display_mode: 'vnc' | 'browser' | string;
}

export interface VncTokenResponse {
  cap_token: string;
  expires_at: string;
  ttl_seconds: number;
  ws_vnc_url: string;
  ws_screencast_url: string;
  ws_control_url: string;
  ws_pty_url: string;
}

export interface WorkspaceFileEntry {
  name: string;
  rel_path: string;
  is_dir: boolean;
  size_bytes: number;
  updated_at?: string;
}

export interface WorkspaceFilesListing {
  project: string;
  rel_path: string;
  parent_path: string | null;
  entries: WorkspaceFileEntry[];
}

export interface WorkspaceFileRead {
  project: string;
  rel_path: string;
  size_bytes: number;
  truncated: boolean;
  content: string;
}

export interface AgyModel {
  id: string;
  label: string;
  is_hydrogen: boolean;
}

export interface AgyModelsResponse {
  available: boolean;
  default_model: string;
  models: AgyModel[];
}

export interface LocalProject {
  name: string;
  path: string;
  is_git: boolean;
  has_readme: boolean;
  updated_at: string;
}

export interface LocalProjectsResponse {
  projects_root: string;
  projects: LocalProject[];
}

export interface SystemInfo {
  service?: string;
  runtime_mode?: string;
  backend_mode?: string;
  llm_origin?: string | null;
  llm_model_id?: string | null;
  db_path?: string | null;
  facility?: Record<string, unknown> | null;
  [key: string]: unknown;
}

export interface RuntimeTaskSnapshot {
  run: {
    run_id: string;
    task_id: string;
    status: string;
    created_at?: string;
    updated_at?: string;
    transition_reason?: string | null;
    required_action?: string | null;
  };
  task: {
    task_id: string;
    query: string;
    user_id: string;
    profile_id: string;
    scope?: {
      facility_id?: string;
    };
  };
  status: string;
  transition_reason?: string | null;
  required_action?: string | null;
}

export interface ServerSseEnvelope {
  id: string;
  ts: string;
  bot_id?: string | null;
  thread_id?: string | null;
  turn_id?: string | null;
  type: string;
  payload: Record<string, unknown>;
}

export type MemoryScope =
  | 'user'
  | 'agent_role'
  | 'thread'
  | 'project_area'
  | 'org_approved';

export type MemoryKind =
  | 'preference'
  | 'approved_procedure'
  | 'dated_observation'
  | 'source_reference';

export type MemoryProvenance = 'operator' | 'agent' | 'untrusted' | 'system' | string;

export interface MemoryItem {
  id: string;
  scope: MemoryScope;
  scope_id: string;
  kind: MemoryKind;
  title: string;
  content: string;
  revision: number;
  observed_at: string | null;
  valid_until: string | null;
  provenance: MemoryProvenance;
  created_by?: string | null;
  created_at: string;
  updated_at: string;
}

export interface MemoryCreateRequest {
  scope: MemoryScope;
  scope_id: string;
  kind: MemoryKind;
  title: string;
  content: string;
  observed_at?: string | null;
  valid_until?: string | null;
  provenance?: MemoryProvenance;
  actor_role?: string;
}

export interface MemoryPatchRequest {
  revision: number;
  title?: string;
  content?: string;
  valid_until?: string | null;
  actor_role?: string;
}
