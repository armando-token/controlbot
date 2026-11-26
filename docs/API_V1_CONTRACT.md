# Grok Bot UX/UI — API v1 & Event Contract

This document is the single source of truth shared between the FastAPI backend (`src/web/v1/`), the Computer Gateway (`src/web/v1/computer.py`, `src/web/v1/rfb_gate.py`), and the React 19 frontend (`frontend/`).

## Rules
- **NEVER touch `src/contracts/`** (frozen since M1).
- **Auth Token Preservation**: All frontend `fetch`, `EventSource`, and `WebSocket` URLs MUST append any `?token=...` present in `window.location.search`.
- **Idempotency**: Mutating HITL and takeover endpoints accept `Idempotency-Key` header. Repeated resolution on an already-resolved item or duplicate key returns `409 Conflict`.
- **Redaction**: Never return plaintext vault secrets or unredacted sensitive credentials. All responses pass `redact_payload_strict` / secret checks.
- **No Dead Buttons**: Every UI button, toggle, menu item, and shortcut MUST invoke a real endpoint listed below or an implemented client behavior.

---

## 1. Data Shapes (JSON)

### Section
```json
{ "id": "sec_...", "name": "Operations", "sort_order": 0, "created_at": "2026-11-26T00:00:00Z" }
```

### Bot
```json
{
  "id": "bot_chief",
  "thread_id": "thr_bot_chief",
  "name": "Chief of Staff",
  "role_prompt": "You coordinate tasks...",
  "about": "",
  "avatar_shape": "sparkle",
  "avatar_color": "#7C3AED",
  "avatar_eyes_large": false,
  "engine_id": "agy",
  "model_id": "gemini-4-carbon-low",
  "thinking_level": "medium",
  "project_name": "Grokbotclon",
  "pinned": true,
  "section_id": null,
  "hidden": false,
  "is_primary": true,
  "is_team_bot": false,
  "unread_count": 0,
  "needs_attention": false,
  "status_state": "idle",
  "status_subtext": "Nothing is blocked",
  "computer_active": false,
  "timezone": "UTC",
  "drafts_enabled": true,
  "conversation_id": null,
  "created_at": "...",
  "updated_at": "..."
}
```
Allowed `avatar_shape`: `"square" | "sparkle" | "clover" | "flower" | "heart" | "house" | "star"`.
Allowed `status_state`: `"idle" | "acknowledging" | "working" | "waiting_human" | "error"`.
Allowed `thinking_level`: `"off" | "low" | "medium" | "high" | "max"`.
Allowed `engine_id`: `"agy" | "controlbot_runtime"`.

### Channel (Group Chat, 2–6 bots)
```json
{
  "id": "chn_...",
  "thread_id": "thr_chn_...",
  "name": "Operations Room",
  "bot_ids": ["bot_chief", "bot_ops"],
  "pinned": false,
  "section_id": null,
  "hidden": false,
  "unread_count": 0,
  "created_at": "...",
  "updated_at": "..."
}
```

### Message
```json
{
  "id": "msg_...",
  "thread_id": "thr_...",
  "sender_type": "user",
  "sender_bot_id": null,
  "sender_name": "You",
  "content": "Hello",
  "thinking_text": "",
  "reply_to_id": null,
  "mentions": [],
  "attachments": [{ "id": "att_...", "filename": "a.txt", "mime_type": "text/plain", "size_bytes": 120 }],
  "tool_calls": [{ "call_id": "tc_1", "tool_name": "run_command", "category": "terminal", "status": "ok", "summary": "...", "output_preview": "" }],
  "artifacts": [{ "id": "art_...", "type": "page", "title": "...", "version": 1, "superseded_by_id": null }],
  "reactions": { "👍": 1 },
  "memory_diffs": [{ "action": "saved", "text": "..." }],
  "metadata": {
    "verdict": "verified",
    "lane": "mixed",
    "domain_profile": "general_office",
    "agreements": ["..."],
    "contradictions": [],
    "partial_evidence": [],
    "missing_attributes": [],
    "clarification_candidates": [{ "asset_id": "...", "canonical_label": "...", "area": "...", "location_display": "...", "score": 0.92 }],
    "nearest_assets": [{ "asset_id": "...", "canonical_label": "...", "area": "...", "location_display": "...", "score": "0.85" }],
    "stale_info": { "observed_at": "...", "age_seconds": 3600, "ttl_seconds": 900 },
    "degraded_banner": { "code": "...", "message": "...", "severity": "warn" },
    "excel_verification": { "passed": true, "verdict": "verified", "formulas_total": 12, "formulas_ok": 12, "recalc_engine": "libreoffice", "badge": "verified", "errors": [], "mixed_currencies_detected": false, "mixed_currency_details": [] },
    "airlock_provenance": { "plant_sources": ["..."], "web_sources": ["..."], "airlock_audit_id": "..." },
    "reconcile": { "agreements": [], "contradictions": [], "partial_evidence": [] },
    "citations": ["https://..."]
  },
  "metadata_json": null,
  "conversation_id": null,
  "model_id": null,
  "status": "done",
  "created_at": "..."
}
```
Allowed `metadata.verdict` / `metadata_json.verdict` (`VerdictState`): `"verified" | "contradicted" | "not_documented" | "partial_evidence" | "stale_data" | "asset_not_found" | "needs_clarification"`. Note: live SSE `message.completed` events emit `"metadata"`, while persisted/serialized records may carry `"metadata_json"` or `"metadata"`.

### Artifact / Page
```json
{
  "id": "art_...",
  "bot_id": "bot_chief",
  "thread_id": "thr_bot_chief",
  "message_id": "msg_...",
  "type": "page",
  "title": "Weekly Ops Brief",
  "content_md": "# Brief\n...",
  "url": null,
  "file_path": null,
  "mime_type": "text/markdown",
  "size_bytes": 420,
  "pinned": false,
  "share_scope": "private",
  "version": 1,
  "superseded_by_id": null,
  "created_at": "...",
  "updated_at": "..."
}
```
Allowed `type`: `"page" | "media" | "link" | "file" | "app" | "skill"`.
Allowed `share_scope`: `"private" | "team" | "public"`.

### ApprovalCard
```json
{
  "id": "apr_...",
  "bot_id": "bot_chief",
  "thread_id": "thr_bot_chief",
  "kind": "standard",
  "title": "Run shell diagnostic command",
  "target": "vm:default",
  "risk_banner": "This can't be undone",
  "arguments": { "command": "..." },
  "status": "pending",
  "allow_always_allowed": true,
  "waiting_for_user": null,
  "decision_by": null,
  "expires_at": null,
  "created_at": "...",
  "resolved_at": null
}
```
Allowed `kind`: `"standard" | "terminal" | "ask_first" | "reconnect" | "takeover"`.
Allowed `status`: `"pending" | "allowed_once" | "allowed_always" | "denied" | "skipped" | "expired"`.
Allowed resolution `decision` (`ApprovalDecision`): `"allow_once" | "always_allow" | "deny" | "skip"`.

### DraftCard
```json
{
  "id": "drf_...",
  "bot_id": "bot_chief",
  "thread_id": "thr_bot_chief",
  "channel_type": "email",
  "fields": { "from": "bot@controlbot.local", "to": "ops@example.com", "bcc": "", "subject": "Update", "body": "...", "attachments": [], "remove_signature": false },
  "status": "pending",
  "created_at": "...",
  "resolved_at": null
}
```

### SecureFormCard
```json
{
  "id": "sfm_...",
  "bot_id": "bot_chief",
  "thread_id": "thr_bot_chief",
  "kind": "form",
  "domain": "example.com",
  "title": "Sign in to example.com",
  "fields": [
    { "name": "username", "label": "Username or email", "secret": false, "required": true, "placeholder": "you@example.com", "type": "text" },
    { "name": "password", "label": "Password", "secret": true, "required": true }
  ],
  "allow_vault_save": true,
  "status": "pending",
  "created_at": "...",
  "resolved_at": null
}
```
Allowed `status`: `"pending" | "submitted" | "cancelled"` (UI also recognizes legacy `"filled" | "saved"`).

### Routine & RoutineRun
```json
{
  "id": "rtn_...",
  "bot_id": "bot_chief",
  "name": "Morning system check",
  "instruction": "Inspect server health and summarize.",
  "schedule_type": "cron",
  "cron_expr": "0 9 * * *",
  "timezone": "UTC",
  "enabled": true,
  "webhook_key": "whk_...",
  "webhook_url": "/api/v1/webhooks/routines/rtn_...",
  "visibility": "only_me",
  "last_run_at": null,
  "created_at": "...",
  "updated_at": "..."
}
```
Allowed `schedule_type`: `"cron" | "webhook" | "manual"`.
Allowed `visibility`: `"only_me" | "team"`.

`RoutineRun`:
```json
{
  "id": "run_...",
  "routine_id": "rtn_...",
  "bot_id": "bot_chief",
  "trigger": "schedule",
  "status": "succeeded",
  "summary": "...",
  "error": null,
  "message_id": "msg_...",
  "started_at": "...",
  "finished_at": "..."
}
```

### ComputerStatus
```json
{
  "vm_id": "default",
  "status": "ready",
  "control_owner": "agent",
  "lease_id": null,
  "lease_expires_at": null,
  "vnc_available": true,
  "browser_running": false,
  "active_url": "",
  "active_tab_title": "",
  "active_step_summary": null,
  "is_teaching_task": false,
  "teach_name": null,
  "teach_steps_count": 0,
  "display_mode": "vnc"
}
```
Allowed `display_mode`: `"vnc" | "browser"` (note: UI transport preference `preferredSource` is `"vnc" | "screencast"`).

### VaultSecretMeta
```json
{
  "id": "sec_...",
  "bot_id": "bot_chief",
  "name": "Portal login",
  "domain": "example.com",
  "kind": "credential",
  "username_hint": "ops@example.com",
  "field_names": ["username", "password"],
  "created_at": "...",
  "updated_at": "..."
}
```

### Skill
```json
{
  "id": "skl_...",
  "bot_id": "bot_chief",
  "name": "Daily Report",
  "slug": "daily-report",
  "description": "Summarize daily metrics.",
  "content_md": "# Steps\n...",
  "instruction_md": "# Steps\n...",
  "source": "custom",
  "created_at": "...",
  "updated_at": "..."
}
```
Allowed `source`: `"custom" | "taught" | "system"`.

### AppSettings
```json
{
  "theme": "light",
  "accent_mode": "bot_color",
  "display_name": "Operator",
  "default_engine_id": "agy",
  "default_engine": "agy",
  "default_model_id": "gemini-4-carbon-low",
  "default_model": "gemini-4-carbon-low",
  "default_thinking_level": "medium",
  "default_project_name": "Grokbotclon",
  "allow_hydrogen": false,
  "include_browser_context": false,
  "notifications_enabled": true,
  "sound_enabled": true,
  "auto_open_computer": false,
  "timezone": "UTC",
  "updated_at": "..."
}
```

### ConnectedApp
```json
{
  "id": "app_slack",
  "name": "Slack",
  "category": "communication",
  "description": "...",
  "enabled": true,
  "connected": true,
  "status": "connected",
  "account_label": "Ops Workspace",
  "config": {},
  "scopes": ["channels:read"],
  "updated_at": "..."
}
```

### MemoryItem
```json
{
  "id": "mem_...",
  "scope": "user",
  "scope_id": "operator",
  "kind": "preference",
  "title": "Output format",
  "content": "Prefer concise tables.",
  "revision": 1,
  "observed_at": null,
  "valid_until": null,
  "provenance": "operator",
  "created_by": "operator",
  "created_at": "...",
  "updated_at": "..."
}
```
Allowed `scope`: `"user" | "agent_role" | "thread" | "project_area" | "org_approved"`.
Allowed `kind`: `"preference" | "approved_procedure" | "dated_observation" | "source_reference"`.

---

## 2. REST Endpoints (`/api/v1`)

### Roster, Bots, Sections, Channels
- `GET /api/v1/bots` -> `{ bots, sections, channels }`
- `POST /api/v1/bots` -> `201 Bot`
- `PATCH /api/v1/bots/{bot_id}` -> `200 Bot`
- `DELETE /api/v1/bots/{bot_id}` -> `200 { deleted: true, bot_id }`
- `POST /api/v1/bots/{bot_id}/clone-template` -> `201 { artifact, message }`
- `POST /api/v1/sections` -> `201 Section`
- `PATCH /api/v1/sections/{section_id}` -> `200 Section`
- `DELETE /api/v1/sections/{section_id}` -> `200 { deleted: true }`
- `POST /api/v1/channels` -> `201 Channel`
- `PATCH /api/v1/channels/{channel_id}` -> `200 Channel`
- `DELETE /api/v1/channels/{channel_id}` -> `200 { deleted: true }`

### Threads & Messages
- `GET /api/v1/threads/{thread_id}/messages?limit=50&before_id=` -> `{ thread_id, messages, approvals, drafts, secure_forms, has_more }`
- `POST /api/v1/threads/{thread_id}/messages` (`{ content, reply_to_id?, mentions?, attachment_ids?, page_context_id?, override_model_id?, override_thinking_level?, include_browser_context?, model_id?, thinking_level?, skill_ids? }`) -> `202 { user_message, turn_id, status }`
- `POST /api/v1/threads/{thread_id}/interrupt` -> `200 { interrupted, thread_id }`
- `POST /api/v1/messages/{message_id}/reactions` -> `200 Message` (emits `message.reaction` SSE)
- `POST /api/v1/messages/{message_id}/to-page` -> `201 { page, message }`

### Attachments, Library, Pages
- `POST /api/v1/attachments?filename=...&thread_id=...` (raw body OR multipart form `file`) -> `201 Attachment`
- `GET /api/v1/attachments/{attachment_id}` -> file bytes (`X-Content-Type-Options: nosniff`, sandboxed CSP / attachment disposition for active MIME types)
- `GET /api/v1/bots/{bot_id}/library?type=all&pinned=false&q=` -> `{ items, grouped: { pinned, today, this_week, older } }` (excludes superseded versions)
- `POST /api/v1/pages` (`{ bot_id?, channel_id?, thread_id?, title, content_md, share_scope? }`) -> `201 Artifact`
- `GET /api/v1/pages/{page_id}` -> `200 Artifact`
- `PATCH /api/v1/pages/{page_id}` -> `200 Artifact`
- `PATCH /api/v1/artifacts/{artifact_id}/pin` -> `200 Artifact`
- `DELETE /api/v1/artifacts/{artifact_id}` -> `200 { deleted: true }` (emits `artifact.deleted` SSE)

### HITL, Drafts, Vault, Auto-Review
- `POST /api/v1/approvals` -> `201 ApprovalCard`
- `POST /api/v1/approvals/{approval_id}/resolve` (`Idempotency-Key`, `{ decision: ApprovalDecision, rule_text? }`) -> `200 ApprovalCard` (or `409`)
- `POST /api/v1/drafts` -> `201 DraftCard`
- `POST /api/v1/drafts/{draft_id}/resolve` (`Idempotency-Key`) -> `200 DraftCard` (or `409`)
- `POST /api/v1/secure-forms` -> `201 SecureFormCard`
- `POST /api/v1/vault/secure-fill` (`{ form_id, bot_id?, domain, values?, save_to_vault?, secret_name?, secret_id?, action?: "submit" | "cancel" }`) -> `200 { filled, saved_secret_id, message, status?, reason?, url? }` (or `409` / `filled: false` keeping `pending` when browser inactive or domain mismatches)
- `GET /api/v1/vault/secrets?bot_id=` -> `{ secrets }`
- `POST /api/v1/vault/secrets` (`{ bot_id?, name, domain?, username?, secret_value?, value?, fields?, kind? }`) -> `201 VaultSecretMeta`
- `DELETE /api/v1/vault/secrets/{secret_id}` -> `200 { deleted: true }`
- `GET /api/v1/settings/auto-review` -> `{ rules }`
- `PUT /api/v1/settings/auto-review` -> `{ rules }`

### Routines & Skills
- `GET /api/v1/bots/{bot_id}/routines` -> `{ routines }`
- `POST /api/v1/bots/{bot_id}/routines` (`{ name, instruction, schedule_type: "cron" | "webhook" | "manual", cron_expr?, timezone?, visibility?: "only_me" | "team" }`) -> `201 Routine`
- `PATCH /api/v1/routines/{routine_id}` (supports `regenerate_webhook_key?: boolean`) -> `200 Routine`
- `DELETE /api/v1/routines/{routine_id}` -> `200 { deleted: true }`
- `POST /api/v1/routines/{routine_id}/test` -> `202 RoutineRun`
- `POST /api/v1/webhooks/routines/{routine_id}` (`Authorization: Bearer <webhook_key>`) -> `202 RoutineRun`
- `GET /api/v1/routines/{routine_id}/runs` -> `{ runs }`
- `GET /api/v1/skills?bot_id=` -> `{ skills }`
- `POST /api/v1/skills` (`{ bot_id?, name, description?, content_md?, instruction_md?, source?: "custom" | "taught" | "system" }`) -> `201 Skill`
- `DELETE /api/v1/skills/{skill_id}` -> `200 { deleted: true }`

### Settings, Apps, Usage, Search
- `GET /api/v1/settings` -> `AppSettings`
- `PATCH /api/v1/settings` -> `AppSettings`
- `GET /api/v1/apps` -> `{ apps }`
- `PATCH /api/v1/apps/{app_id}` (`{ enabled?, connected?, status?, account_label?, config? }`) -> `200 ConnectedApp`
- `GET /api/v1/usage` -> `{ bots_count, channels_count, messages_count, pages_count, routines_count, routine_runs_count, approvals_count, active_turns }`
- `GET /api/v1/search?q=` -> `{ bots, channels, messages, pages, routines, skills }`

### Memory (`/api/v1/memory`)
- `GET /api/v1/memory?scope=&scope_id=&kind=&q=&include_expired=false` -> `200 { items }`
- `POST /api/v1/memory` (`{ scope, scope_id, kind, title, content, observed_at?, valid_until?, provenance?, actor_role? }`) -> `201 MemoryItem` (redacts secrets; rejects `provenance="untrusted"` for `approved_procedure` with `403`; enforces `Manager` role for `approved_procedure` with `403`)
- `PATCH /api/v1/memory/{item_id}` (`{ revision, title?, content?, valid_until?, actor_role? }`) -> `200 MemoryItem` or `409 Conflict` on revision mismatch
- `DELETE /api/v1/memory/{item_id}?actor_role=` -> `200 { deleted: true, id }` (purges both `memory_items` and `memory_fts`; `actor_role` defaults to `"Operator"` and requires `"Manager"` to delete `approved_procedure` items, else `403`)
- `GET /api/v1/memory/export?format=json|md&scope=&scope_id=&kind=&q=&include_expired=false` -> JSON or Markdown export (secrets redacted)

### System (`/api/system/info`)
- `GET /api/system/info` -> `{ service, runtime_mode, backend_mode, llm_origin, llm_model_id, db_path, facility }`

### Computer & Workspace Files
- `GET /api/v1/computers/{vm_id}/status` -> `ComputerStatus`
- `POST /api/v1/computers/{vm_id}/vnc-token` -> `{ cap_token, expires_at, ttl_seconds, ws_vnc_url, ws_screencast_url, ws_control_url, ws_pty_url }`
- `POST /api/v1/computers/{vm_id}/takeover` (`Idempotency-Key`) -> `200 ComputerStatus`
- `POST /api/v1/computers/{vm_id}/handback` -> `200 ComputerStatus`
- `POST /api/v1/computers/{vm_id}/actions` -> `200 { status, browser_status, context }` (or `409` if `actor=="agent"` during `human_takeover`)
- `GET /api/v1/computers/{vm_id}/files?path=&project=` -> `{ project, rel_path, parent_path, entries }`
- `GET /api/v1/computers/{vm_id}/file?path=&project=` -> `{ project, rel_path, size_bytes, truncated, content }`
- `GET /api/v1/computers/{vm_id}/file/download?path=&project=` -> file bytes
- `POST /api/v1/computers/{vm_id}/files/upload?path=&name=&project=` -> `201 { rel_path, size_bytes }`
- `POST /api/v1/computers/{vm_id}/files/mkdir` -> `201 { rel_path }`
- `POST /api/v1/computers/{vm_id}/files/write` -> `200 { rel_path, size_bytes }`
- `DELETE /api/v1/computers/{vm_id}/files?path=&project=` -> `200 { deleted: true }`
- `POST /api/v1/computers/{vm_id}/teach/start` -> `200 ComputerStatus`
- `POST /api/v1/computers/{vm_id}/teach/stop` -> `200 { status, skill, artifact, message }`

---

## 3. SSE Stream (`GET /api/v1/events/stream`)
Supports `Last-Event-ID` header and `?last_event_id=...`. Emits initial `: connected` comment and `retry:` directive. `EventBus` emits durable event IDs in `evt_{seq:06d}_{epoch}` wire format (e.g. `evt_000001_a1b2c3d4`); reconnect cursors also accept `<epoch>:<seq>` (e.g. `ep_20261126:1`), legacy `evt_<seq>`, and numeric `<seq>` formats.
Envelope:
```json
{
  "id": "evt_000001_a1b2c3d4",
  "ts": "2026-11-26T06:30:00Z",
  "bot_id": "bot_chief",
  "thread_id": "thr_bot_chief",
  "turn_id": "trn_...",
  "type": "message.delta",
  "payload": {}
}
```
Event `type` values:
- `stream.resync`: `{ reason?, epoch?, last_event_id? }` (emitted on epoch mismatch / predated `Last-Event-ID` / slow-consumer overflow so clients refresh cached queries and HITL state)
- `bot.presence`: `{ state, step_label?, subtext, computer_active }`
- `turn.started`: `{ turn_id, message_id, model_id, engine_id, sender_bot_id, sender_name }`
- `thinking.delta`: `{ message_id, text_delta, collapsed_summary? }`
- `message.delta`: `{ message_id, text_delta }`
- `message.completed`: `{ message_id, message }`
- `message.reaction`: `{ message_id, reactions, message? }`
- `tool.call.updated`: `{ message_id, call_id, tool_name, category, status, summary, output_preview? }`
- `hitl.approval.requested` | `hitl.approval.resolved` | `hitl.approval.expired`: `{ approval }`
- `hitl.draft.created` | `hitl.draft.updated`: `{ draft }`
- `hitl.secure_form.requested` | `hitl.secure_form.resolved`: `{ form }`
- `computer.state`: `ComputerStatus`
- `artifact.page.updated`: `{ artifact, supersedes_message_id? }`
- `artifact.deleted`: `{ artifact_id, thread_id?, artifact? }`
- `routine.run.status`: `{ routine_id, run }`
- `handoff.dispatched`: `{ from_bot_id, to_bot_id, from_name, to_name, summary }`

---

## 4. WebSockets (`/ws/v1/computers/{vm_id}/...`)
- `WS /ws/v1/computers/{vm_id}/vnc?cap_token=...`: Binary RFB frames to `127.0.0.1:5900` with Python RFB Input Gate (`0x04/0x05/0x06` dropped unless `control_owner == "human_takeover"`) and transparent backend DES authentication.
- `WS /ws/v1/computers/{vm_id}/screencast?cap_token=...`: JSON frames `{ type: "frame", data, url, title, width, height }` and `{ type: "status", ... }` + interactive mouse/keyboard/navigate commands (`wheel` uses `{ type: "wheel", dx, dy }`). Takeover lock is strictly enforced (`force_interactive` removed).
- `WS /ws/v1/computers/{vm_id}/control?cap_token=...`: JSON control plane (`lease.heartbeat` -> `lease.heartbeat.ack`, `viewport.resize` -> `viewport.resize.ack`, `clipboard.push`, `browser.tab_changed`, `teach.step_captured` with `step: { step_index, action, description, url, ts }`, `lease.revoked`).
- `WS /ws/v1/computers/{vm_id}/pty/{session_id}?cap_token=...&project=...`: Raw UTF-8 text frames for terminal stdout/stdin (no JSON-sniffing on stdout) + control JSON `{ op: "resize", cols, rows }` and `{ op: "signal", sig: "SIGINT" }`.
