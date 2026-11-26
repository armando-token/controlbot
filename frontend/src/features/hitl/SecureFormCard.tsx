import React, { useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { Eye, EyeOff, KeyRound, Lock, ShieldCheck, XCircle } from 'lucide-react';
import { ApiError, hitlApi, vaultApi } from '../../lib/api';
import type { SecureFormCard as SecureFormCardType } from '../../lib/types';
import { useHitlStore } from '../../stores/hitlStore';
import { useUiStore } from '../../stores/uiStore';

interface SecureFormCardProps {
  card: SecureFormCardType;
}

export const SecureFormCard: React.FC<SecureFormCardProps> = ({ card }) => {
  const queryClient = useQueryClient();
  const upsertSecureForm = useHitlStore((s) => s.upsertSecureForm);
  const activeTarget = useUiStore((s) => s.activeTarget);
  const pushToast = useUiStore((s) => s.pushToast);

  const [values, setValues] = useState<Record<string, string>>({});
  const [revealed, setRevealed] = useState<Record<string, boolean>>({});
  const [saveToVault, setSaveToVault] = useState(card.allow_vault_save);
  const [selectedSecretId, setSelectedSecretId] = useState('');

  const isPending = card.status === 'pending';
  const isCancelled = card.status === 'cancelled';
  const botId =
    card.bot_id || (activeTarget?.kind === 'bot' ? activeTarget.id : undefined);

  const vaultQuery = useQuery({
    queryKey: ['vault-secrets', botId ?? 'all'],
    queryFn: () => vaultApi.list(botId),
    enabled: isPending,
  });

  const sortedSecrets = useMemo(() => {
    const list = vaultQuery.data?.secrets ?? [];
    const targetDomain = (card.domain || '').toLowerCase().trim();
    if (!targetDomain) return list;
    return [...list].sort((a, b) => {
      const aMatch = (a.domain || '').toLowerCase().includes(targetDomain) ? 0 : 1;
      const bMatch = (b.domain || '').toLowerCase().includes(targetDomain) ? 0 : 1;
      return aMatch - bMatch;
    });
  }, [vaultQuery.data?.secrets, card.domain]);

  const handleFillSuccess = (res: {
    filled: boolean;
    saved_secret_id: string | null;
    message: string;
    status?: string;
  }) => {
    if (res.status === 'cancelled') {
      setValues({});
      setSelectedSecretId('');
      upsertSecureForm({
        ...card,
        status: 'cancelled',
        resolved_at: new Date().toISOString(),
      });
      void queryClient.invalidateQueries({ queryKey: ['thread-messages', card.thread_id] });
      pushToast({
        tone: 'info',
        title: 'Form cancelled',
        description: res.message || 'No credentials were submitted.',
      });
      return;
    }

    if (res.status === 'submitted' || res.filled || card.kind === 'secret') {
      setValues({});
      setSelectedSecretId('');
      upsertSecureForm({
        ...card,
        status: 'submitted',
        resolved_at: new Date().toISOString(),
      });
      void queryClient.invalidateQueries({ queryKey: ['thread-messages', card.thread_id] });
      void queryClient.invalidateQueries({ queryKey: ['vault-secrets'] });
      pushToast({
        tone: 'success',
        title: 'Submitted securely',
        description: res.message || 'Secret values were never shown to your Bot.',
      });
      return;
    }

    pushToast({
      tone: 'warn',
      title: 'Could not fill form',
      description:
        res.message ||
        'Browser is inactive or on a different domain. Open the target page and try again.',
    });
  };

  const handleMutationError = (title: string, err: Error) => {
    if (err instanceof ApiError && err.status === 409) {
      pushToast({
        tone: 'warn',
        title: 'Could not complete form',
        description: err.detail || 'This form could not be completed in the current state.',
      });
      void queryClient.invalidateQueries({ queryKey: ['thread-messages', card.thread_id] });
    } else {
      pushToast({ tone: 'error', title, description: err.message });
    }
  };

  const submitMutation = useMutation({
    mutationFn: () =>
      hitlApi.secureFill({
        form_id: card.id,
        bot_id: botId ?? null,
        domain: card.domain,
        values,
        save_to_vault: saveToVault,
        secret_name: card.title || card.domain,
        action: 'submit',
      }),
    onSuccess: handleFillSuccess,
    onError: (err: Error) => handleMutationError('Secure fill failed', err),
  });

  const vaultFillMutation = useMutation({
    mutationFn: (secretId: string) =>
      hitlApi.secureFill({
        form_id: card.id,
        bot_id: botId ?? null,
        domain: card.domain,
        values: {},
        save_to_vault: false,
        secret_id: secretId,
        action: 'submit',
      }),
    onSuccess: handleFillSuccess,
    onError: (err: Error) => handleMutationError('Vault fill failed', err),
  });

  const cancelMutation = useMutation({
    mutationFn: () =>
      hitlApi.secureFill({
        form_id: card.id,
        bot_id: botId ?? null,
        domain: card.domain,
        values: {},
        save_to_vault: false,
        action: 'cancel',
      }),
    onSuccess: (res) => {
      setValues({});
      setSelectedSecretId('');
      upsertSecureForm({
        ...card,
        status: 'cancelled',
        resolved_at: new Date().toISOString(),
      });
      void queryClient.invalidateQueries({ queryKey: ['thread-messages', card.thread_id] });
      pushToast({
        tone: 'info',
        title: 'Form cancelled',
        description: res.message || 'No credentials were submitted.',
      });
    },
    onError: (err: Error) => handleMutationError('Could not cancel form', err),
  });

  const anyPending =
    submitMutation.isPending || vaultFillMutation.isPending || cancelMutation.isPending;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!isPending || anyPending) return;
    if (selectedSecretId) {
      vaultFillMutation.mutate(selectedSecretId);
      return;
    }
    submitMutation.mutate();
  };

  return (
    <div
      className="my-2.5 rounded-xl overflow-hidden"
      style={{
        backgroundColor: 'var(--bg-canvas)',
        border: isPending
          ? '1px solid var(--border-strong)'
          : '1px solid var(--border-subtle)',
        boxShadow: isPending ? 'var(--shadow-sm)' : 'none',
      }}
    >
      <div
        className="flex items-center gap-2 px-3.5 py-2 text-[12px]"
        style={{
          backgroundColor: 'var(--accent-computer-tint)',
          color: 'var(--accent-computer)',
          borderBottom: '1px solid var(--border-subtle)',
        }}
      >
        <Lock size={13} strokeWidth={2} className="shrink-0" />
        <span className="font-medium">
          Never shown to your Bot. Filled directly to {card.domain || 'page'}
        </span>
      </div>

      {!isPending ? (
        <div
          className="px-3.5 py-3 flex items-center gap-2.5 text-[13px]"
          style={{
            color: isCancelled ? 'var(--text-muted)' : 'var(--status-ok)',
          }}
        >
          {isCancelled ? (
            <XCircle size={16} strokeWidth={2} className="shrink-0" />
          ) : (
            <ShieldCheck size={16} strokeWidth={2} className="shrink-0" />
          )}
          <span>
            {isCancelled
              ? 'Cancelled — no credentials were submitted.'
              : card.kind === 'secret'
                ? 'Stored securely, never shown to your Bot.'
                : 'Submitted into the page. Secret values were never shown to your Bot.'}
          </span>
        </div>
      ) : (
        <form onSubmit={handleSubmit} className="p-3.5 space-y-3">
          <div className="flex items-center gap-2 text-[13.5px] font-medium">
            <KeyRound size={15} strokeWidth={1.75} style={{ color: 'var(--text-secondary)' }} />
            <span>{card.title}</span>
          </div>

          {card.kind !== 'secret' && (sortedSecrets.length > 0 || vaultQuery.isError) && (
            <div
              className="rounded-lg p-2.5 space-y-1.5"
              style={{
                backgroundColor: 'var(--bg-sidebar)',
                border: '1px solid var(--border-subtle)',
              }}
            >
              <label
                className="block text-[11.5px] font-medium"
                style={{ color: 'var(--text-secondary)' }}
              >
                Fill from Vault
              </label>
              {vaultQuery.isError ? (
                <div className="text-[12px]" style={{ color: 'var(--status-danger)' }}>
                  Could not load saved vault secrets.
                </div>
              ) : (
                <div className="flex flex-wrap items-center gap-2">
                  <select
                    aria-label="Select vault secret"
                    disabled={anyPending}
                    value={selectedSecretId}
                    onChange={(e) => setSelectedSecretId(e.target.value)}
                    className="flex-1 min-w-[180px] px-2.5 py-1.5 rounded-lg text-[12.5px] outline-none"
                    style={{
                      backgroundColor: 'var(--bg-canvas)',
                      border: '1px solid var(--border-strong)',
                    }}
                  >
                    <option value="">Enter credentials manually…</option>
                    {sortedSecrets.map((secret) => {
                      const domainTag = secret.domain ? ` (${secret.domain})` : '';
                      const hint = secret.username_hint ? ` — ${secret.username_hint}` : '';
                      return (
                        <option key={secret.id} value={secret.id}>
                          {secret.name}
                          {domainTag}
                          {hint}
                        </option>
                      );
                    })}
                  </select>
                  {selectedSecretId && (
                    <button
                      type="button"
                      disabled={anyPending}
                      onClick={() => vaultFillMutation.mutate(selectedSecretId)}
                      className="px-3 py-1.5 rounded-lg text-[12.5px] font-medium text-white disabled:opacity-50"
                      style={{ backgroundColor: 'var(--accent-computer)' }}
                    >
                      {vaultFillMutation.isPending ? 'Filling…' : 'Fill from Vault'}
                    </button>
                  )}
                </div>
              )}
            </div>
          )}

          <div className="space-y-2.5">
            {card.fields.map((field) => {
              const isSecret = field.secret;
              const show = Boolean(revealed[field.name]);
              const isRequired = !selectedSecretId && field.required !== false;
              const inputType = isSecret
                ? show
                  ? 'text'
                  : 'password'
                : field.type || 'text';

              return (
                <div key={field.name}>
                  <label
                    className="block text-[12px] font-medium mb-1"
                    style={{ color: 'var(--text-secondary)' }}
                  >
                    {field.label}
                    {field.required === false && (
                      <span className="ml-1 font-normal" style={{ color: 'var(--text-muted)' }}>
                        (optional)
                      </span>
                    )}
                  </label>
                  <div className="relative">
                    <input
                      type={inputType}
                      required={isRequired}
                      disabled={Boolean(selectedSecretId) || anyPending}
                      autoComplete="off"
                      placeholder={field.placeholder}
                      value={values[field.name] ?? ''}
                      onChange={(e) =>
                        setValues((prev) => ({ ...prev, [field.name]: e.target.value }))
                      }
                      className="w-full px-3 py-1.5 pr-9 rounded-lg text-[13px] outline-none disabled:opacity-60"
                      style={{
                        backgroundColor: 'var(--bg-sidebar)',
                        border: '1px solid var(--border-strong)',
                      }}
                    />
                    {isSecret && (
                      <button
                        type="button"
                        disabled={Boolean(selectedSecretId) || anyPending}
                        onClick={() =>
                          setRevealed((prev) => ({ ...prev, [field.name]: !prev[field.name] }))
                        }
                        aria-label={show ? 'Hide value' : 'Show value'}
                        className="absolute right-2 top-1/2 -translate-y-1/2 p-1 rounded hover:bg-[var(--bg-subtle)] disabled:opacity-50"
                        style={{ color: 'var(--text-muted)' }}
                      >
                        {show ? <EyeOff size={14} /> : <Eye size={14} />}
                      </button>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          {card.allow_vault_save && !selectedSecretId && (
            <label className="inline-flex items-center gap-2 text-[12.5px] cursor-pointer select-none">
              <input
                type="checkbox"
                checked={saveToVault}
                disabled={anyPending}
                onChange={(e) => setSaveToVault(e.target.checked)}
              />
              <span style={{ color: 'var(--text-secondary)' }}>
                Securely save to Bot&apos;s vault
              </span>
            </label>
          )}

          <div className="flex flex-wrap items-center gap-2 pt-1">
            {!selectedSecretId && (
              <button
                type="submit"
                disabled={anyPending}
                className="px-3.5 py-1.5 rounded-lg text-[12.5px] font-medium text-white disabled:opacity-50"
                style={{ backgroundColor: 'var(--accent-computer)' }}
              >
                {submitMutation.isPending
                  ? 'Submitting…'
                  : card.kind === 'secret'
                    ? 'Save securely'
                    : 'Fill directly'}
              </button>
            )}
            <button
              type="button"
              disabled={anyPending}
              onClick={() => cancelMutation.mutate()}
              className="px-3 py-1.5 rounded-lg text-[12.5px] hover:bg-[var(--bg-subtle)] disabled:opacity-50"
              style={{ color: 'var(--text-secondary)' }}
            >
              {cancelMutation.isPending ? 'Cancelling…' : 'Cancel'}
            </button>
          </div>
        </form>
      )}
    </div>
  );
};
