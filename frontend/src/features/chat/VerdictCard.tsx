import React from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  FileSpreadsheet,
  Globe,
  HelpCircle,
  Loader2,
  RefreshCw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  XCircle,
} from 'lucide-react';
import { threadsApi } from '../../lib/api';
import type {
  AirlockProvenance,
  ClarificationCandidate,
  ExcelVerification,
  Message,
  MessageMetadata,
  NearestAsset,
  ReconcileSplit,
  StaleInfo,
  VerdictState,
} from '../../lib/types';
import { useUiStore } from '../../stores/uiStore';

interface VerdictCardProps {
  threadId: string;
  message: Message;
}

interface NormalizedDegradedBanner {
  message: string;
  severity?: string;
  code?: string;
}

interface NormalizedStaleInfo {
  source?: string;
  asset_id?: string;
  observed_at?: string;
  age_seconds?: number;
  max_ttl_seconds?: number;
  age_display?: string;
  ttl_display?: string;
  message?: string;
}

interface ContradictionClaim {
  source?: string;
  asset_id?: string;
  field?: string;
  value?: unknown;
  observed_at?: string;
}

interface NormalizedContradiction {
  summary: string;
  claims: ContradictionClaim[];
  unresolved?: boolean;
}

function asRecord(val: unknown): Record<string, unknown> | null {
  if (!val || typeof val !== 'object' || Array.isArray(val)) return null;
  return val as Record<string, unknown>;
}

function asStringArray(val: unknown): string[] {
  if (!Array.isArray(val)) return [];
  return val
    .map((item) => {
      if (typeof item === 'string') return item.trim();
      if (item && typeof item === 'object') {
        const rec = item as Record<string, unknown>;
        if (typeof rec.label === 'string') return rec.label;
        if (typeof rec.text === 'string') return rec.text;
        if (typeof rec.message === 'string') return rec.message;
      }
      return String(item ?? '').trim();
    })
    .filter(Boolean);
}

function parseMetadata(msg: Message): MessageMetadata | null {
  const candidates: unknown[] = [msg.metadata, msg.metadata_json];
  for (const raw of candidates) {
    if (!raw) continue;
    if (typeof raw === 'string') {
      const trimmed = raw.trim();
      if (!trimmed) continue;
      try {
        const parsed = asRecord(JSON.parse(trimmed));
        if (parsed && Object.keys(parsed).length > 0) {
          return parsed as MessageMetadata;
        }
      } catch {
        // Ignore malformed JSON and continue to fallback
      }
    } else {
      const rec = asRecord(raw);
      if (rec && Object.keys(rec).length > 0) {
        return rec as MessageMetadata;
      }
    }
  }
  return null;
}

function normalizeDegradedBanner(raw: unknown): NormalizedDegradedBanner | null {
  if (!raw) return null;
  if (typeof raw === 'string') {
    const trimmed = raw.trim();
    return trimmed ? { message: trimmed, severity: 'warn' } : null;
  }
  const rec = asRecord(raw);
  if (!rec) return null;
  const msg = typeof rec.message === 'string' ? rec.message.trim() : '';
  if (!msg) return null;
  return {
    message: msg,
    severity: typeof rec.severity === 'string' ? rec.severity : 'warn',
    code: typeof rec.code === 'string' ? rec.code : undefined,
  };
}

function formatDurationSeconds(sec: number): string {
  if (!Number.isFinite(sec) || sec < 0) return '';
  if (sec < 60) return `${Math.round(sec)} s`;
  if (sec < 3600) return `${Math.round(sec / 60)} min`;
  return `${(sec / 3600).toFixed(1)} h`;
}

function normalizeStaleInfo(raw: unknown): NormalizedStaleInfo | null {
  const rec = asRecord(raw) as (StaleInfo & Record<string, unknown>) | null;
  if (!rec) return null;
  const ageSeconds = typeof rec.age_seconds === 'number' ? rec.age_seconds : undefined;
  const maxTtlSeconds =
    typeof rec.max_ttl_seconds === 'number'
      ? rec.max_ttl_seconds
      : typeof rec.ttl_seconds === 'number'
        ? rec.ttl_seconds
        : undefined;
  const ageDisplay =
    typeof rec.age_display === 'string' && rec.age_display.trim()
      ? rec.age_display.trim()
      : ageSeconds !== undefined
        ? formatDurationSeconds(ageSeconds)
        : undefined;
  const ttlDisplay =
    typeof rec.ttl_display === 'string' && rec.ttl_display.trim()
      ? rec.ttl_display.trim()
      : maxTtlSeconds !== undefined
        ? formatDurationSeconds(maxTtlSeconds)
        : undefined;
  const message =
    typeof rec.message === 'string' && rec.message.trim()
      ? rec.message.trim()
      : typeof rec.reason === 'string' && rec.reason.trim()
        ? rec.reason.trim()
        : undefined;

  return {
    source: typeof rec.source === 'string' ? rec.source : undefined,
    asset_id: typeof rec.asset_id === 'string' ? rec.asset_id : undefined,
    observed_at: typeof rec.observed_at === 'string' ? rec.observed_at : undefined,
    age_seconds: ageSeconds,
    max_ttl_seconds: maxTtlSeconds,
    age_display: ageDisplay,
    ttl_display: ttlDisplay,
    message,
  };
}

function normalizeContradictions(raw: unknown): NormalizedContradiction[] {
  if (!Array.isArray(raw)) return [];
  const out: NormalizedContradiction[] = [];
  for (const item of raw) {
    if (typeof item === 'string') {
      const trimmed = item.trim();
      if (trimmed) out.push({ summary: trimmed, claims: [] });
      continue;
    }
    const rec = asRecord(item);
    if (!rec) continue;
    const summary =
      (typeof rec.summary === 'string' && rec.summary) ||
      (typeof rec.detail === 'string' && rec.detail) ||
      (typeof rec.claim === 'string' && rec.claim) ||
      [rec.source_a, rec.source_b].filter((v) => typeof v === 'string').join(' vs ') ||
      'Conflicting evidence detected';
    const claims: ContradictionClaim[] = Array.isArray(rec.claims)
      ? rec.claims
          .map((c) => asRecord(c))
          .filter((c): c is Record<string, unknown> => Boolean(c))
          .map((c) => ({
            source: typeof c.source === 'string' ? c.source : undefined,
            asset_id: typeof c.asset_id === 'string' ? c.asset_id : undefined,
            field: typeof c.field === 'string' ? c.field : undefined,
            value: c.value,
            observed_at: typeof c.observed_at === 'string' ? c.observed_at : undefined,
          }))
      : [];
    out.push({
      summary,
      claims,
      unresolved: typeof rec.unresolved === 'boolean' ? rec.unresolved : undefined,
    });
  }
  return out;
}

const VERDICT_META: Record<
  VerdictState,
  { label: string; bg: string; fg: string; border: string }
> = {
  verified: {
    label: 'Verified',
    bg: 'var(--status-ok-bg)',
    fg: 'var(--status-ok)',
    border: 'rgba(22, 163, 74, 0.25)',
  },
  contradicted: {
    label: 'Contradicted',
    bg: 'var(--status-danger-bg)',
    fg: 'var(--status-danger)',
    border: 'rgba(220, 38, 38, 0.25)',
  },
  not_documented: {
    label: 'Not documented',
    bg: 'var(--bg-subtle)',
    fg: 'var(--text-secondary)',
    border: 'var(--border-subtle)',
  },
  partial_evidence: {
    label: 'Partial evidence',
    bg: 'var(--status-warn-bg)',
    fg: 'var(--status-warn)',
    border: 'rgba(217, 119, 6, 0.28)',
  },
  stale_data: {
    label: 'Stale data',
    bg: 'var(--status-warn-bg)',
    fg: 'var(--status-warn)',
    border: 'rgba(217, 119, 6, 0.28)',
  },
  asset_not_found: {
    label: 'Asset not found',
    bg: 'var(--status-danger-bg)',
    fg: 'var(--status-danger)',
    border: 'rgba(220, 38, 38, 0.25)',
  },
  needs_clarification: {
    label: 'Needs clarification',
    bg: 'var(--accent-computer-tint)',
    fg: 'var(--accent-computer)',
    border: 'rgba(124, 58, 237, 0.28)',
  },
};

export const VerdictCard: React.FC<VerdictCardProps> = ({ threadId, message }) => {
  const queryClient = useQueryClient();
  const pushToast = useUiStore((s) => s.pushToast);

  const followUpMutation = useMutation({
    mutationFn: (content: string) => threadsApi.send(threadId, { content }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['thread-messages', threadId] });
      void queryClient.invalidateQueries({ queryKey: ['roster'] });
    },
    onError: (err: Error) => {
      pushToast({
        tone: 'error',
        title: 'Could not send verification action',
        description: err.message,
      });
    },
  });

  const meta = parseMetadata(message);
  if (!meta) return null;

  const rawRecord = meta as Record<string, unknown>;
  const verdict = typeof meta.verdict === 'string' ? (meta.verdict as VerdictState) : undefined;
  const lane = typeof meta.lane === 'string' ? meta.lane : undefined;
  const domainProfile = typeof meta.domain_profile === 'string' ? meta.domain_profile : undefined;
  const degradedBanner = normalizeDegradedBanner(meta.degraded_banner);
  const staleInfo = normalizeStaleInfo(meta.stale_info);

  const clarificationCandidates: ClarificationCandidate[] = Array.isArray(
    meta.clarification_candidates,
  )
    ? meta.clarification_candidates
    : [];
  const nearestAssets: NearestAsset[] = Array.isArray(meta.nearest_assets)
    ? meta.nearest_assets.slice(0, 3)
    : [];

  const airlock: AirlockProvenance | null = asRecord(meta.airlock_provenance) as AirlockProvenance | null;
  const excel: ExcelVerification | null = asRecord(meta.excel_verification) as ExcelVerification | null;

  const reconcileObj = (asRecord(rawRecord.reconcile_split) ??
    asRecord(meta.reconcile)) as ReconcileSplit | null;
  const agreements = asStringArray(reconcileObj?.agreements ?? meta.agreements);
  const contradictions = normalizeContradictions(
    reconcileObj?.contradictions ?? meta.contradictions,
  );
  const partialEvidence = asStringArray(
    reconcileObj?.partial_evidence ?? meta.partial_evidence,
  );
  const missingAttributes = asStringArray(
    reconcileObj?.missing_attributes ?? meta.missing_attributes,
  );
  const citations = asStringArray(meta.citations);

  const hasGovernanceData = Boolean(
    verdict ||
      degradedBanner ||
      staleInfo ||
      clarificationCandidates.length > 0 ||
      nearestAssets.length > 0 ||
      airlock ||
      excel ||
      agreements.length > 0 ||
      contradictions.length > 0 ||
      partialEvidence.length > 0 ||
      missingAttributes.length > 0 ||
      citations.length > 0,
  );

  if (!hasGovernanceData) return null;

  const verdictStyle = verdict ? VERDICT_META[verdict] : undefined;
  const busy = followUpMutation.isPending;

  const excelErrors = asStringArray(excel?.errors ?? excel?.formula_errors);
  const excelMixedCurrency = Boolean(
    excel?.mixed_currencies_detected ?? excel?.mixed_currency,
  );
  const excelMixedDetails = asStringArray(excel?.mixed_currency_details);
  const excelPassed = Boolean(
    excel &&
      (excel.passed === true ||
        excel.verified === true ||
        (excel.verdict === 'verified' && excelErrors.length === 0 && !excelMixedCurrency)),
  );

  return (
    <div
      className="mt-2.5 rounded-xl p-3 space-y-2.5 text-[12.5px]"
      style={{
        backgroundColor: 'var(--bg-sidebar)',
        border: '1px solid var(--border-subtle)',
      }}
      data-testid="verdict-card"
    >
      {/* Header row: Verdict badge + lane + domain_profile */}
      {(verdictStyle || lane || domainProfile) && (
        <div className="flex flex-wrap items-center gap-1.5">
          {verdictStyle && (
            <span
              className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11.5px] font-semibold"
              style={{
                backgroundColor: verdictStyle.bg,
                color: verdictStyle.fg,
                border: `1px solid ${verdictStyle.border}`,
              }}
            >
              {verdict === 'verified' ? (
                <CheckCircle2 size={12} />
              ) : verdict === 'contradicted' || verdict === 'asset_not_found' ? (
                <XCircle size={12} />
              ) : verdict === 'needs_clarification' ? (
                <HelpCircle size={12} />
              ) : (
                <AlertTriangle size={12} />
              )}
              <span>{verdictStyle.label}</span>
            </span>
          )}
          {lane && (
            <span
              className="px-2 py-0.5 rounded-full text-[11px] font-medium capitalize"
              style={{
                backgroundColor: 'var(--bg-subtle)',
                color: 'var(--text-secondary)',
                border: '1px solid var(--border-subtle)',
              }}
            >
              Lane: {lane}
            </span>
          )}
          {domainProfile && (
            <span
              className="px-2 py-0.5 rounded-full text-[11px] font-mono"
              style={{
                backgroundColor: 'var(--bg-subtle)',
                color: 'var(--text-muted)',
                border: '1px solid var(--border-subtle)',
              }}
            >
              {domainProfile}
            </span>
          )}
        </div>
      )}

      {/* Degraded / Partial Source Banner */}
      {degradedBanner && (
        <div
          className="flex items-start gap-2 px-2.5 py-2 rounded-lg text-[12px]"
          style={{
            backgroundColor:
              degradedBanner.severity === 'error'
                ? 'var(--status-danger-bg)'
                : 'var(--status-warn-bg)',
            color:
              degradedBanner.severity === 'error'
                ? 'var(--status-danger)'
                : 'var(--status-warn)',
            border: '1px solid rgba(217, 119, 6, 0.25)',
          }}
        >
          <ShieldAlert size={14} className="shrink-0 mt-0.5" />
          <div className="min-w-0 flex-1">
            {degradedBanner.code && (
              <span className="font-mono text-[11px] mr-1.5">[{degradedBanner.code}]</span>
            )}
            <span>{degradedBanner.message}</span>
          </div>
        </div>
      )}

      {/* Stale Data Info + Refresh Live CTA */}
      {(staleInfo || verdict === 'stale_data') && (
        <div
          className="flex flex-wrap items-center justify-between gap-2 px-2.5 py-2 rounded-lg text-[12px]"
          style={{
            backgroundColor: 'var(--status-warn-bg)',
            color: 'var(--text-primary)',
            border: '1px solid rgba(217, 119, 6, 0.25)',
          }}
        >
          <div className="flex items-start gap-2 min-w-0 flex-1">
            <Clock size={14} className="shrink-0 mt-0.5" style={{ color: 'var(--status-warn)' }} />
            <div className="space-y-0.5 min-w-0">
              <div className="font-medium" style={{ color: 'var(--status-warn)' }}>
                {staleInfo?.message || 'Reading exceeds freshness TTL'}
              </div>
              <div className="text-[11px] flex flex-wrap gap-x-3 gap-y-0.5" style={{ color: 'var(--text-secondary)' }}>
                {staleInfo?.age_display && <span>Age: {staleInfo.age_display}</span>}
                {staleInfo?.ttl_display && <span>TTL: {staleInfo.ttl_display}</span>}
                {staleInfo?.observed_at && <span>Observed: {staleInfo.observed_at}</span>}
                {staleInfo?.source && <span>Source: {staleInfo.source}</span>}
                {staleInfo?.asset_id && <span className="font-mono">{staleInfo.asset_id}</span>}
              </div>
            </div>
          </div>
          <button
            type="button"
            disabled={busy}
            onClick={() => {
              const target = staleInfo?.asset_id ? ` for ${staleInfo.asset_id}` : '';
              const src = staleInfo?.source ? ` from ${staleInfo.source}` : '';
              followUpMutation.mutate(`Refresh live reading${target}${src}.`);
            }}
            className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11.5px] font-medium transition-opacity hover:opacity-90 disabled:opacity-50"
            style={{
              backgroundColor: 'var(--bg-canvas)',
              color: 'var(--text-primary)',
              border: '1px solid var(--border-strong)',
            }}
          >
            {busy ? <Loader2 size={12} className="animate-spin" /> : <RefreshCw size={12} />}
            <span>Refresh live</span>
          </button>
        </div>
      )}

      {/* Needs Clarification: Candidate Picker + General Web Research CTA */}
      {(verdict === 'needs_clarification' || clarificationCandidates.length > 0) && (
        <div
          className="p-2.5 rounded-lg space-y-2"
          style={{
            backgroundColor: 'var(--bg-canvas)',
            border: '1px solid var(--border-subtle)',
          }}
        >
          <div className="text-[11.5px] font-semibold" style={{ color: 'var(--text-primary)' }}>
            Select matching asset or confirm lane
          </div>
          {clarificationCandidates.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {clarificationCandidates.map((cand, idx) => {
                const label =
                  cand.canonical_label || cand.label || cand.asset_id || `Candidate ${idx + 1}`;
                const metaParts = [
                  cand.area,
                  cand.location_display,
                  cand.score !== undefined ? `score ${cand.score}` : undefined,
                  cand.confidence !== undefined
                    ? `${Math.round(cand.confidence * 100)}%`
                    : undefined,
                ].filter(Boolean);
                return (
                  <button
                    key={cand.id ?? cand.asset_id ?? `${label}-${idx}`}
                    type="button"
                    disabled={busy}
                    onClick={() => {
                      const idSuffix = cand.asset_id ? ` (${cand.asset_id})` : '';
                      followUpMutation.mutate(`Use asset ${label}${idSuffix}`);
                    }}
                    className="text-left px-2.5 py-1.5 rounded-lg text-[12px] transition-colors hover:bg-[var(--bg-active)] disabled:opacity-50"
                    style={{
                      backgroundColor: 'var(--bg-subtle)',
                      border: '1px solid var(--border-strong)',
                      color: 'var(--text-primary)',
                    }}
                  >
                    <div className="font-medium">{label}</div>
                    {metaParts.length > 0 && (
                      <div className="text-[11px]" style={{ color: 'var(--text-muted)' }}>
                        {metaParts.join(' · ')}
                      </div>
                    )}
                    {cand.description && (
                      <div className="text-[11px] truncate max-w-[260px]" style={{ color: 'var(--text-secondary)' }}>
                        {cand.description}
                      </div>
                    )}
                  </button>
                );
              })}
            </div>
          )}
          <div className="flex flex-wrap items-center gap-2 pt-0.5">
            <button
              type="button"
              disabled={busy}
              onClick={() => followUpMutation.mutate('Run as general web research.')}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11.5px] font-medium hover:bg-[var(--bg-active)] disabled:opacity-50"
              style={{
                backgroundColor: 'var(--bg-subtle)',
                color: 'var(--text-secondary)',
                border: '1px solid var(--border-subtle)',
              }}
            >
              <Globe size={12} />
              <span>Run as general web research</span>
            </button>
          </div>
        </div>
      )}

      {/* Asset Not Found: Top-3 Nearest Tags + Alias Hint */}
      {(verdict === 'asset_not_found' || nearestAssets.length > 0) && (
        <div
          className="p-2.5 rounded-lg space-y-2"
          style={{
            backgroundColor: 'var(--bg-canvas)',
            border: '1px solid rgba(220, 38, 38, 0.2)',
          }}
        >
          <div className="flex items-center gap-1.5 text-[11.5px] font-semibold" style={{ color: 'var(--status-danger)' }}>
            <Search size={12.5} />
            <span>Exact tag not found — nearest plant assets</span>
          </div>
          {nearestAssets.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {nearestAssets.map((asset, idx) => {
                const assetId =
                  typeof asset.asset_id === 'string' && asset.asset_id.trim()
                    ? asset.asset_id.trim()
                    : '';
                const name =
                  asset.canonical_label ||
                  assetId ||
                  asset.name ||
                  asset.tag ||
                  asset.id ||
                  `Tag ${idx + 1}`;
                const details = [
                  asset.area,
                  asset.location_display,
                  asset.score !== undefined ? `score ${asset.score}` : undefined,
                  asset.distance !== undefined ? `dist ${asset.distance}` : undefined,
                ].filter(Boolean);
                return (
                  <button
                    key={asset.id ?? (assetId || undefined) ?? asset.tag ?? `${name}-${idx}`}
                    type="button"
                    disabled={busy}
                    onClick={() =>
                      followUpMutation.mutate(`Query nearest asset: ${name}`)
                    }
                    className="text-left px-2.5 py-1.5 rounded-lg text-[12px] hover:bg-[var(--bg-active)] disabled:opacity-50"
                    style={{
                      backgroundColor: 'var(--bg-subtle)',
                      border: '1px solid var(--border-strong)',
                      color: 'var(--text-primary)',
                    }}
                  >
                    <div className="font-mono font-medium">{name}</div>
                    {details.length > 0 && (
                      <div className="text-[11px]" style={{ color: 'var(--text-muted)' }}>
                        {details.join(' · ')}
                      </div>
                    )}
                  </button>
                );
              })}
            </div>
          )}
          <div className="text-[11px]" style={{ color: 'var(--text-muted)' }}>
            Tip: If none of these match, reply with the exact tag alias, loop ID, or unit area.
          </div>
        </div>
      )}

      {/* Planta vs Web Airlock Provenance */}
      {airlock && (
        <div
          className="p-2.5 rounded-lg space-y-2"
          style={{
            backgroundColor: 'var(--bg-canvas)',
            border: '1px solid var(--border-subtle)',
          }}
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div className="inline-flex items-center gap-1.5 text-[11.5px] font-semibold" style={{ color: 'var(--text-primary)' }}>
              <ShieldCheck size={13} style={{ color: 'var(--accent-computer)' }} />
              <span>Planta vs Web Airlock</span>
            </div>
            {airlock.airlock_audit_id && (
              <span
                className="text-[10.5px] font-mono px-1.5 py-0.5 rounded"
                style={{ backgroundColor: 'var(--bg-subtle)', color: 'var(--text-muted)' }}
              >
                {airlock.airlock_audit_id}
              </span>
            )}
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11.5px]">
            <div
              className="p-2 rounded-lg space-y-1"
              style={{ backgroundColor: 'var(--bg-sidebar)', border: '1px solid var(--border-subtle)' }}
            >
              <div className="font-semibold" style={{ color: 'var(--text-primary)' }}>
                Planta (Local OT)
              </div>
              {airlock.planta_summary && (
                <div style={{ color: 'var(--text-secondary)' }}>{airlock.planta_summary}</div>
              )}
              {(airlock.plant_sources ?? []).length > 0 ? (
                <ul className="list-disc pl-4 space-y-0.5" style={{ color: 'var(--text-secondary)' }}>
                  {(airlock.plant_sources ?? []).map((src, idx) => (
                    <li key={`${src}-${idx}`} className="break-words">
                      {src}
                    </li>
                  ))}
                </ul>
              ) : (
                !airlock.planta_summary && (
                  <div style={{ color: 'var(--text-muted)' }}>No local plant readings</div>
                )
              )}
            </div>
            <div
              className="p-2 rounded-lg space-y-1"
              style={{ backgroundColor: 'var(--bg-sidebar)', border: '1px solid var(--border-subtle)' }}
            >
              <div className="font-semibold" style={{ color: 'var(--text-primary)' }}>
                Web (Sanitized Spec)
              </div>
              {airlock.web_summary && (
                <div style={{ color: 'var(--text-secondary)' }}>{airlock.web_summary}</div>
              )}
              {(airlock.web_sources ?? []).length > 0 ? (
                <ul className="list-disc pl-4 space-y-0.5" style={{ color: 'var(--text-secondary)' }}>
                  {(airlock.web_sources ?? []).map((src, idx) => (
                    <li key={`${src}-${idx}`} className="break-words">
                      {src}
                    </li>
                  ))}
                </ul>
              ) : (
                !airlock.web_summary && (
                  <div style={{ color: 'var(--text-muted)' }}>No external web citations</div>
                )
              )}
              {airlock.projected_fields && Object.keys(airlock.projected_fields).length > 0 && (
                <div className="flex flex-wrap gap-1 pt-1">
                  {Object.entries(airlock.projected_fields).map(([k, v]) => (
                    <span
                      key={k}
                      className="px-1.5 py-0.5 rounded text-[10.5px] font-mono"
                      style={{ backgroundColor: 'var(--bg-subtle)', color: 'var(--text-secondary)' }}
                    >
                      {k}: {String(v)}
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Acuerdos / Contradicciones / Evidencia parcial */}
      {(agreements.length > 0 ||
        contradictions.length > 0 ||
        partialEvidence.length > 0 ||
        missingAttributes.length > 0) && (
        <div
          className="p-2.5 rounded-lg space-y-2"
          style={{
            backgroundColor: 'var(--bg-canvas)',
            border: '1px solid var(--border-subtle)',
          }}
        >
          {agreements.length > 0 && (
            <div className="space-y-1">
              <div className="text-[11.5px] font-semibold" style={{ color: 'var(--status-ok)' }}>
                Acuerdos / Agreements ({agreements.length})
              </div>
              <ul className="list-disc pl-4 space-y-0.5 text-[12px]" style={{ color: 'var(--text-secondary)' }}>
                {agreements.map((item, idx) => (
                  <li key={`agr-${idx}`}>{item}</li>
                ))}
              </ul>
            </div>
          )}

          {contradictions.length > 0 && (
            <div className="space-y-1">
              <div className="text-[11.5px] font-semibold" style={{ color: 'var(--status-danger)' }}>
                Contradicciones / Contradictions ({contradictions.length})
              </div>
              <div className="space-y-1.5">
                {contradictions.map((c, idx) => (
                  <div
                    key={`con-${idx}`}
                    className="p-2 rounded-lg text-[12px] space-y-1"
                    style={{
                      backgroundColor: 'var(--status-danger-bg)',
                      border: '1px solid rgba(220, 38, 38, 0.2)',
                    }}
                  >
                    <div className="font-medium" style={{ color: 'var(--status-danger)' }}>
                      {c.summary}
                    </div>
                    {c.claims.length > 0 && (
                      <div className="flex flex-wrap gap-1.5">
                        {c.claims.map((cl, cIdx) => (
                          <span
                            key={`claim-${cIdx}`}
                            className="px-1.5 py-0.5 rounded text-[11px] font-mono"
                            style={{
                              backgroundColor: 'var(--bg-canvas)',
                              color: 'var(--text-primary)',
                            }}
                          >
                            {[cl.source, cl.field, cl.value !== undefined ? String(cl.value) : undefined]
                              .filter(Boolean)
                              .join(': ')}
                          </span>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {(partialEvidence.length > 0 || missingAttributes.length > 0) && (
            <div className="space-y-1.5">
              <div className="text-[11.5px] font-semibold" style={{ color: 'var(--status-warn)' }}>
                Evidencia parcial / Missing attributes
              </div>
              {partialEvidence.length > 0 && (
                <ul className="list-disc pl-4 space-y-0.5 text-[12px]" style={{ color: 'var(--text-secondary)' }}>
                  {partialEvidence.map((item, idx) => (
                    <li key={`pe-${idx}`}>{item}</li>
                  ))}
                </ul>
              )}
              {missingAttributes.length > 0 && (
                <div className="flex flex-wrap gap-1">
                  {missingAttributes.map((attr, idx) => (
                    <span
                      key={`ma-${idx}`}
                      className="px-1.5 py-0.5 rounded text-[11px] font-mono"
                      style={{
                        backgroundColor: 'var(--status-warn-bg)',
                        color: 'var(--status-warn)',
                      }}
                    >
                      Missing: {attr}
                    </span>
                  ))}
                </div>
              )}
              <button
                type="button"
                disabled={busy}
                onClick={() => {
                  const missing = missingAttributes.length > 0 ? missingAttributes : partialEvidence;
                  followUpMutation.mutate(
                    `Request missing evidence for: ${missing.join(', ')}`,
                  );
                }}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-[11.5px] font-medium hover:bg-[var(--bg-active)] disabled:opacity-50"
                style={{
                  backgroundColor: 'var(--bg-subtle)',
                  color: 'var(--text-primary)',
                  border: '1px solid var(--border-strong)',
                }}
              >
                <Sparkles size={12} />
                <span>Request missing evidence</span>
              </button>
            </div>
          )}
        </div>
      )}

      {/* Excel Verification */}
      {excel && (
        <div
          className="p-2.5 rounded-lg space-y-1.5"
          style={{
            backgroundColor: excelPassed ? 'var(--status-ok-bg)' : 'var(--status-danger-bg)',
            border: excelPassed
              ? '1px solid rgba(22, 163, 74, 0.25)'
              : '1px solid rgba(220, 38, 38, 0.25)',
          }}
        >
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div
              className="inline-flex items-center gap-1.5 font-semibold text-[12px]"
              style={{ color: excelPassed ? 'var(--status-ok)' : 'var(--status-danger)' }}
            >
              <FileSpreadsheet size={14} />
              <span>
                {excel.badge ||
                  (excelPassed
                    ? excel.formulas_total != null
                      ? `Fórmulas recalculadas: ${excel.formulas_ok ?? excel.formulas_total}/${excel.formulas_total} OK`
                      : 'Excel formulas verified'
                    : 'Excel verification failed')}
              </span>
            </div>
            {excel.recalc_engine && (
              <span
                className="px-1.5 py-0.5 rounded text-[10.5px] font-mono"
                style={{ backgroundColor: 'var(--bg-canvas)', color: 'var(--text-secondary)' }}
              >
                {excel.recalc_engine}
              </span>
            )}
          </div>
          {excelErrors.length > 0 && (
            <ul className="list-disc pl-4 space-y-0.5 text-[11.5px]" style={{ color: 'var(--status-danger)' }}>
              {excelErrors.map((errMsg, idx) => (
                <li key={`xerr-${idx}`}>{errMsg}</li>
              ))}
            </ul>
          )}
          {excelMixedCurrency && (
            <div className="text-[11.5px]" style={{ color: 'var(--status-danger)' }}>
              Mixed currencies detected
              {excelMixedDetails.length > 0 ? `: ${excelMixedDetails.join('; ')}` : ''}
            </div>
          )}
        </div>
      )}

      {/* Citations */}
      {citations.length > 0 && (
        <div className="flex flex-wrap items-center gap-1 pt-0.5">
          <span className="text-[11px] font-medium mr-1" style={{ color: 'var(--text-muted)' }}>
            Citations:
          </span>
          {citations.map((cit, idx) => (
            <span
              key={`cit-${idx}`}
              className="px-2 py-0.5 rounded-full text-[11px] font-mono"
              style={{
                backgroundColor: 'var(--bg-canvas)',
                color: 'var(--text-secondary)',
                border: '1px solid var(--border-subtle)',
              }}
            >
              {cit}
            </span>
          ))}
        </div>
      )}
    </div>
  );
};
