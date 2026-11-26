"""Pydantic v2 request schemas for Grok Bot UX/UI `/api/v1` endpoints."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

AvatarShape = Literal["square", "sparkle", "clover", "flower", "heart", "house", "star"]
StatusState = Literal["idle", "acknowledging", "working", "waiting_human", "error"]
ThinkingLevel = Literal["off", "low", "medium", "high", "max"]
EngineId = Literal["agy", "controlbot_runtime"]
ArtifactType = Literal["page", "media", "link", "file", "app", "skill"]
ShareScope = Literal["private", "team", "public"]
ApprovalKind = Literal["standard", "terminal", "ask_first", "reconnect", "takeover"]
ApprovalDecision = Literal["allow_once", "always_allow", "deny", "skip"]
DraftAction = Literal["send", "discard", "update"]
ScheduleType = Literal["cron", "webhook", "manual"]
RoutineVisibility = Literal["only_me", "team"]
AutoReviewBucket = Literal["allow_auto", "ask_first"]
ThemeMode = Literal["system", "light", "dark"]

MAX_ROSTER_ITEMS = 50
MAX_ROUTINES_PER_BOT = 50
MAX_AUTO_REVIEW_RULES_PER_BUCKET = 20
MAX_AUTO_REVIEW_RULE_LEN = 1000


def _strip_non_empty(value: str, field_name: str) -> str:
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{field_name} must not be empty.")
    return cleaned


def _dedupe_bot_ids(bot_ids: list[str]) -> list[str]:
    seen: set[str] = set()
    cleaned: list[str] = []
    for raw in bot_ids:
        item = raw.strip()
        if not item or item in seen:
            continue
        seen.add(item)
        cleaned.append(item)
    if len(cleaned) < 2 or len(cleaned) > 6:
        raise ValueError("Channel bot_ids must contain between 2 and 6 unique bot IDs.")
    return cleaned


class V1Schema(BaseModel):
    """Base schema rejecting unknown extra keys softly or strictly as appropriate."""

    model_config = ConfigDict(extra="ignore", str_strip_whitespace=False)


class BotCreateRequest(V1Schema):
    name: str = Field(min_length=1, max_length=80)
    role_prompt: str = Field(default="", max_length=8000)
    about: str = Field(default="", max_length=2000)
    avatar_shape: AvatarShape = "sparkle"
    avatar_color: str = Field(default="#7C3AED", min_length=4, max_length=32)
    avatar_eyes_large: bool = False
    engine_id: EngineId = "agy"
    model_id: str = Field(default="gemini-4-carbon-low", min_length=1, max_length=120)
    thinking_level: ThinkingLevel = "medium"
    project_name: str | None = Field(default="Grokbotclon", max_length=160)
    pinned: bool = False
    section_id: str | None = None
    is_primary: bool = False
    is_team_bot: bool = False
    timezone: str = Field(default="UTC", min_length=1, max_length=64)
    drafts_enabled: bool = True

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        return _strip_non_empty(value, "name")


class BotPatchRequest(V1Schema):
    name: str | None = Field(default=None, min_length=1, max_length=80)
    role_prompt: str | None = Field(default=None, max_length=8000)
    about: str | None = Field(default=None, max_length=2000)
    avatar_shape: AvatarShape | None = None
    avatar_color: str | None = Field(default=None, min_length=4, max_length=32)
    avatar_eyes_large: bool | None = None
    engine_id: EngineId | None = None
    model_id: str | None = Field(default=None, min_length=1, max_length=120)
    thinking_level: ThinkingLevel | None = None
    project_name: str | None = Field(default=None, max_length=160)
    pinned: bool | None = None
    section_id: str | None = None
    hidden: bool | None = None
    is_primary: bool | None = None
    is_team_bot: bool | None = None
    unread_count: int | None = Field(default=None, ge=0)
    needs_attention: bool | None = None
    status_state: StatusState | None = None
    status_subtext: str | None = Field(default=None, max_length=240)
    computer_active: bool | None = None
    timezone: str | None = Field(default=None, min_length=1, max_length=64)
    drafts_enabled: bool | None = None
    conversation_id: str | None = Field(default=None, max_length=128)

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _strip_non_empty(value, "name")


class SectionCreateRequest(V1Schema):
    name: str = Field(min_length=1, max_length=80)
    sort_order: int = Field(default=0, ge=0, le=10000)

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        return _strip_non_empty(value, "name")


class SectionPatchRequest(V1Schema):
    name: str | None = Field(default=None, min_length=1, max_length=80)
    sort_order: int | None = Field(default=None, ge=0, le=10000)

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _strip_non_empty(value, "name")


class ChannelCreateRequest(V1Schema):
    name: str = Field(min_length=1, max_length=80)
    bot_ids: list[str] = Field(min_length=2, max_length=6)
    pinned: bool = False
    section_id: str | None = None

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        return _strip_non_empty(value, "name")

    @field_validator("bot_ids")
    @classmethod
    def _validate_bot_ids(cls, value: list[str]) -> list[str]:
        return _dedupe_bot_ids(value)


class ChannelPatchRequest(V1Schema):
    name: str | None = Field(default=None, min_length=1, max_length=80)
    bot_ids: list[str] | None = Field(default=None, min_length=2, max_length=6)
    pinned: bool | None = None
    section_id: str | None = None
    hidden: bool | None = None
    unread_count: int | None = Field(default=None, ge=0)

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _strip_non_empty(value, "name")

    @field_validator("bot_ids")
    @classmethod
    def _validate_bot_ids(cls, value: list[str] | None) -> list[str] | None:
        if value is None:
            return None
        return _dedupe_bot_ids(value)


class MessageCreateRequest(V1Schema):
    content: str = Field(min_length=1, max_length=32000)
    reply_to_id: str | None = None
    mentions: list[str] = Field(default_factory=list, max_length=20)
    attachment_ids: list[str] = Field(default_factory=list, max_length=20)
    include_browser_context: bool | None = None
    page_context_id: str | None = Field(default=None, max_length=80)
    model_id: str | None = Field(default=None, max_length=120)
    override_model_id: str | None = Field(default=None, max_length=120)
    thinking_level: ThinkingLevel | None = None
    override_thinking_level: ThinkingLevel | None = None
    skill_ids: list[str] = Field(default_factory=list, max_length=10)

    @field_validator("content")
    @classmethod
    def _validate_content(cls, value: str) -> str:
        return _strip_non_empty(value, "content")

    @model_validator(mode="after")
    def _normalize_overrides(self) -> MessageCreateRequest:
        if self.model_id is None and self.override_model_id is not None:
            self.model_id = self.override_model_id
        if self.thinking_level is None and self.override_thinking_level is not None:
            self.thinking_level = self.override_thinking_level
        return self


class ReactionRequest(V1Schema):
    emoji: str = Field(min_length=1, max_length=16)
    action: Literal["toggle", "add", "remove"] = "toggle"

    @field_validator("emoji")
    @classmethod
    def _validate_emoji(cls, value: str) -> str:
        return _strip_non_empty(value, "emoji")


class MessageToPageRequest(V1Schema):
    title: str | None = Field(default=None, max_length=200)
    share_scope: ShareScope = "private"


class PageCreateRequest(V1Schema):
    bot_id: str | None = Field(default=None, min_length=1, max_length=80)
    channel_id: str | None = Field(default=None, min_length=1, max_length=80)
    thread_id: str | None = Field(default=None, min_length=1, max_length=120)
    message_id: str | None = None
    title: str = Field(min_length=1, max_length=200)
    content_md: str = Field(default="", max_length=200000)
    pinned: bool = False
    share_scope: ShareScope = "private"

    @field_validator("title")
    @classmethod
    def _validate_title(cls, value: str) -> str:
        return _strip_non_empty(value, "title")

    @field_validator("bot_id", "channel_id", "thread_id")
    @classmethod
    def _strip_optional_target(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        return cleaned or None

    @model_validator(mode="after")
    def _require_target(self) -> PageCreateRequest:
        if not self.bot_id and not self.channel_id and not self.thread_id:
            raise ValueError("At least one of bot_id, channel_id, or thread_id is required.")
        return self


class PagePatchRequest(V1Schema):
    title: str | None = Field(default=None, min_length=1, max_length=200)
    content_md: str | None = Field(default=None, max_length=200000)
    pinned: bool | None = None
    share_scope: ShareScope | None = None

    @field_validator("title")
    @classmethod
    def _validate_title(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _strip_non_empty(value, "title")


class ArtifactPinRequest(V1Schema):
    pinned: bool


class ApprovalCreateRequest(V1Schema):
    bot_id: str = Field(min_length=1, max_length=80)
    thread_id: str = Field(min_length=1, max_length=120)
    kind: ApprovalKind = "standard"
    title: str = Field(min_length=1, max_length=240)
    target: str = Field(default="vm:default", max_length=160)
    risk_banner: str | None = Field(default=None, max_length=240)
    arguments: dict[str, Any] = Field(default_factory=dict)
    allow_always_allowed: bool = True
    waiting_for_user: str | None = Field(default=None, max_length=120)
    expires_in_minutes: int | None = Field(default=30, ge=1, le=1440)

    @field_validator("title")
    @classmethod
    def _validate_title(cls, value: str) -> str:
        return _strip_non_empty(value, "title")


class ApprovalResolveRequest(V1Schema):
    decision: ApprovalDecision
    decision_by: str = Field(default="operator", min_length=1, max_length=80)
    rule_text: str | None = Field(default=None, max_length=MAX_AUTO_REVIEW_RULE_LEN)


class DraftCreateRequest(V1Schema):
    bot_id: str = Field(min_length=1, max_length=80)
    thread_id: str = Field(min_length=1, max_length=120)
    channel_type: str = Field(default="email", min_length=1, max_length=40)
    fields: dict[str, Any] = Field(default_factory=dict)


class DraftResolveRequest(V1Schema):
    action: DraftAction | None = None
    decision: DraftAction | None = None
    fields: dict[str, Any] | None = None

    @model_validator(mode="after")
    def _resolve_action(self) -> DraftResolveRequest:
        if self.action is None and self.decision is not None:
            self.action = self.decision
        if self.action is None:
            self.action = "send"
        return self


class SecureFormFieldSchema(V1Schema):
    name: str = Field(min_length=1, max_length=80)
    label: str = Field(min_length=1, max_length=120)
    secret: bool = False

    @field_validator("name", "label")
    @classmethod
    def _validate_non_empty(cls, value: str) -> str:
        return _strip_non_empty(value, "field")


class SecureFormCreateRequest(V1Schema):
    bot_id: str = Field(min_length=1, max_length=80)
    thread_id: str = Field(min_length=1, max_length=120)
    kind: str = Field(default="form", min_length=1, max_length=40)
    domain: str = Field(default="", max_length=240)
    title: str = Field(min_length=1, max_length=200)
    fields: list[SecureFormFieldSchema] = Field(min_length=1, max_length=20)
    allow_vault_save: bool = True

    @field_validator("title")
    @classmethod
    def _validate_title(cls, value: str) -> str:
        return _strip_non_empty(value, "title")


class SecureFillRequest(V1Schema):
    form_id: str | None = None
    bot_id: str | None = None
    action: Literal["submit", "cancel"] = "submit"
    domain: str = Field(default="", max_length=240)
    values: dict[str, str] = Field(default_factory=dict)
    fields: dict[str, str] | None = None
    save_to_vault: bool = False
    vault_name: str | None = Field(default=None, max_length=120)
    secret_name: str | None = Field(default=None, max_length=120)
    secret_id: str | None = None

    @model_validator(mode="after")
    def _merge_fields(self) -> SecureFillRequest:
        if not self.values and self.fields:
            self.values = dict(self.fields)
        if not self.vault_name and self.secret_name:
            self.vault_name = self.secret_name
        return self


class SecureFormSubmitRequest(V1Schema):
    action: Literal["submit", "cancel"] = "submit"
    fields: dict[str, str] | None = None
    values: dict[str, str] = Field(default_factory=dict)
    save_to_vault: bool = False
    vault_name: str | None = Field(default=None, max_length=120)
    secret_name: str | None = Field(default=None, max_length=120)
    secret_id: str | None = None

    @model_validator(mode="after")
    def _sync_fields(self) -> SecureFormSubmitRequest:
        if not self.values and self.fields:
            self.values = dict(self.fields)
        elif self.fields is None and self.values:
            self.fields = dict(self.values)
        if not self.vault_name and self.secret_name:
            self.vault_name = self.secret_name
        elif not self.secret_name and self.vault_name:
            self.secret_name = self.vault_name
        return self


class VaultSecretCreateRequest(V1Schema):
    bot_id: str | None = None
    name: str = Field(min_length=1, max_length=120)
    domain: str = Field(default="", max_length=240)
    username: str = Field(default="", max_length=200)
    secret_value: str = Field(default="", max_length=8000)
    value: str = Field(default="", max_length=8000)
    fields: dict[str, str] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        return _strip_non_empty(value, "name")

    @model_validator(mode="after")
    def _ensure_payload(self) -> VaultSecretCreateRequest:
        if not self.secret_value and self.value:
            self.secret_value = self.value
        if not self.fields and not self.secret_value and not self.username:
            raise ValueError("Vault secret requires either fields or secret_value.")
        return self


class AutoReviewRuleInput(V1Schema):
    id: str | None = None
    bucket: AutoReviewBucket | None = None
    mode: AutoReviewBucket | None = None
    rule_type: AutoReviewBucket | None = None
    rule_text: str | None = Field(default=None, max_length=MAX_AUTO_REVIEW_RULE_LEN)
    text: str | None = Field(default=None, max_length=MAX_AUTO_REVIEW_RULE_LEN)

    @model_validator(mode="after")
    def _normalize_rule(self) -> AutoReviewRuleInput:
        resolved_bucket = self.bucket or self.mode or self.rule_type
        if resolved_bucket is None:
            raise ValueError("bucket (or mode / rule_type) is required.")
        self.bucket = resolved_bucket
        raw_text = self.rule_text if self.rule_text is not None else (self.text or "")
        cleaned = _strip_non_empty(raw_text, "rule_text")
        if len(cleaned) > MAX_AUTO_REVIEW_RULE_LEN:
            raise ValueError(
                f"rule_text must be at most {MAX_AUTO_REVIEW_RULE_LEN} characters."
            )
        self.rule_text = cleaned
        return self


class AutoReviewPutRequest(V1Schema):
    rules: list[AutoReviewRuleInput] = Field(default_factory=list)

    @model_validator(mode="after")
    def _enforce_bucket_limits(self) -> AutoReviewPutRequest:
        allow_count = sum(1 for r in self.rules if r.bucket == "allow_auto")
        ask_count = sum(1 for r in self.rules if r.bucket == "ask_first")
        if allow_count > MAX_AUTO_REVIEW_RULES_PER_BUCKET:
            raise ValueError(
                f"At most {MAX_AUTO_REVIEW_RULES_PER_BUCKET} allow_auto rules are allowed."
            )
        if ask_count > MAX_AUTO_REVIEW_RULES_PER_BUCKET:
            raise ValueError(
                f"At most {MAX_AUTO_REVIEW_RULES_PER_BUCKET} ask_first rules are allowed."
            )
        return self


class RoutineCreateRequest(V1Schema):
    name: str = Field(min_length=1, max_length=120)
    instruction: str = Field(min_length=1, max_length=8000)
    schedule_type: ScheduleType = "cron"
    cron_expr: str | None = Field(default="0 9 * * *", max_length=120)
    timezone: str = Field(default="UTC", min_length=1, max_length=64)
    enabled: bool = True
    visibility: RoutineVisibility = "only_me"

    @field_validator("name", "instruction")
    @classmethod
    def _validate_non_empty(cls, value: str) -> str:
        return _strip_non_empty(value, "field")


class RoutinePatchRequest(V1Schema):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    instruction: str | None = Field(default=None, min_length=1, max_length=8000)
    schedule_type: ScheduleType | None = None
    cron_expr: str | None = Field(default=None, max_length=120)
    timezone: str | None = Field(default=None, min_length=1, max_length=64)
    enabled: bool | None = None
    visibility: RoutineVisibility | None = None
    regenerate_webhook_key: bool | None = None

    @field_validator("name", "instruction")
    @classmethod
    def _validate_optional_non_empty(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _strip_non_empty(value, "field")


class SkillCreateRequest(V1Schema):
    bot_id: str | None = None
    name: str = Field(min_length=1, max_length=120)
    description: str = Field(default="", max_length=500)
    content_md: str = Field(default="", max_length=16000)
    instruction_md: str = Field(default="", max_length=16000)
    source: Literal["custom", "taught", "system"] = "custom"

    @field_validator("name")
    @classmethod
    def _validate_name(cls, value: str) -> str:
        return _strip_non_empty(value, "name")

    @model_validator(mode="after")
    def _resolve_content(self) -> SkillCreateRequest:
        raw = self.content_md.strip() or self.instruction_md.strip()
        if not raw:
            raise ValueError("content_md (or instruction_md) must not be empty.")
        self.content_md = raw
        return self


class SettingsPatchRequest(V1Schema):
    theme: ThemeMode | None = None
    accent_mode: Literal["bot_color", "black"] | None = None
    default_model_id: str | None = Field(default=None, min_length=1, max_length=120)
    default_model: str | None = Field(default=None, min_length=1, max_length=120)
    default_engine_id: EngineId | None = None
    default_engine: EngineId | None = None
    default_thinking_level: ThinkingLevel | None = None
    default_project_name: str | None = Field(default=None, max_length=160)
    allow_hydrogen: bool | None = None
    include_browser_context: bool | None = None
    notifications_enabled: bool | None = None
    sound_enabled: bool | None = None
    auto_open_computer: bool | None = None
    timezone: str | None = Field(default=None, min_length=1, max_length=64)
    display_name: str | None = Field(default=None, min_length=1, max_length=80)


class ConnectedAppPatchRequest(V1Schema):
    enabled: bool | None = None
    connected: bool | None = None
    status: str | None = Field(default=None, min_length=1, max_length=40)
    account_label: str | None = Field(default=None, max_length=80)
    config: dict[str, Any] | None = None

    @field_validator("account_label")
    @classmethod
    def _strip_account_label(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return value.strip()

    @model_validator(mode="after")
    def _normalize_enabled(self) -> ConnectedAppPatchRequest:
        if self.enabled is None and self.connected is not None:
            self.enabled = self.connected
        return self


MemoryScopeInput = Literal[
    "user",
    "agent_role",
    "thread",
    "project_area",
    "project",
    "project/area",
    "org_approved",
]
MemoryKindInput = Literal[
    "preference",
    "approved_procedure",
    "dated_observation",
    "source_reference",
]


class MemoryCreateRequest(V1Schema):
    scope: MemoryScopeInput
    scope_id: str = Field(min_length=1, max_length=160)
    kind: MemoryKindInput
    title: str = Field(min_length=1, max_length=200)
    content: str = Field(min_length=1, max_length=32000)
    tags: str = Field(default="", max_length=500)
    observed_at: str | None = None
    valid_until: str | None = None
    provenance: str = Field(default="operator", max_length=64)
    actor_role: str = Field(default="Operator", max_length=64)
    created_by: str = Field(default="operator", max_length=80)

    @field_validator("scope_id", "title", "content")
    @classmethod
    def _validate_non_empty(cls, value: str) -> str:
        return _strip_non_empty(value, "field")

    @model_validator(mode="after")
    def _normalize_scope(self) -> MemoryCreateRequest:
        if self.scope in {"project", "project/area"}:
            self.scope = "project_area"
        return self


class MemoryPatchRequest(V1Schema):
    revision: int = Field(ge=1)
    title: str | None = Field(default=None, min_length=1, max_length=200)
    content: str | None = Field(default=None, min_length=1, max_length=32000)
    tags: str | None = Field(default=None, max_length=500)
    observed_at: str | None = None
    valid_until: str | None = None
    provenance: str | None = Field(default=None, max_length=64)
    actor_role: str | None = Field(default=None, max_length=64)

    @field_validator("title", "content")
    @classmethod
    def _validate_optional_non_empty(cls, value: str | None) -> str | None:
        if value is None:
            return None
        return _strip_non_empty(value, "field")
