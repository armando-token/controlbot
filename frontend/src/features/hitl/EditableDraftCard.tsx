import React, { useEffect, useRef, useState } from 'react';
import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Check, Mail, Send, Trash2 } from 'lucide-react';
import { ApiError, botsApi, hitlApi } from '../../lib/api';
import type { DraftCard } from '../../lib/types';
import { useHitlStore } from '../../stores/hitlStore';
import { useUiStore } from '../../stores/uiStore';

interface EditableDraftCardProps {
  card: DraftCard;
}

type DraftTextField = 'to' | 'bcc' | 'subject' | 'body';

export const EditableDraftCard: React.FC<EditableDraftCardProps> = ({ card }) => {
  const queryClient = useQueryClient();
  const upsertDraft = useHitlStore((s) => s.upsertDraft);
  const pushToast = useUiStore((s) => s.pushToast);

  const [to, setTo] = useState(String(card.fields?.to ?? ''));
  const [bcc, setBcc] = useState(String(card.fields?.bcc ?? ''));
  const [subject, setSubject] = useState(String(card.fields?.subject ?? ''));
  const [body, setBody] = useState(String(card.fields?.body ?? ''));
  const [removeSignature, setRemoveSignature] = useState(
    Boolean(card.fields?.remove_signature),
  );

  const prevCardIdRef = useRef(card.id);
  const lastSyncedFieldsRef = useRef({
    to: String(card.fields?.to ?? ''),
    bcc: String(card.fields?.bcc ?? ''),
    subject: String(card.fields?.subject ?? ''),
    body: String(card.fields?.body ?? ''),
    removeSignature: Boolean(card.fields?.remove_signature),
  });
  const activeFieldRef = useRef<DraftTextField | null>(null);
  const dirtyRef = useRef({
    to: false,
    bcc: false,
    subject: false,
    body: false,
    removeSignature: false,
  });

  useEffect(() => {
    const nextFields = {
      to: String(card.fields?.to ?? ''),
      bcc: String(card.fields?.bcc ?? ''),
      subject: String(card.fields?.subject ?? ''),
      body: String(card.fields?.body ?? ''),
      removeSignature: Boolean(card.fields?.remove_signature),
    };

    if (card.id !== prevCardIdRef.current) {
      prevCardIdRef.current = card.id;
      lastSyncedFieldsRef.current = nextFields;
      dirtyRef.current = {
        to: false,
        bcc: false,
        subject: false,
        body: false,
        removeSignature: false,
      };
      setTo(nextFields.to);
      setBcc(nextFields.bcc);
      setSubject(nextFields.subject);
      setBody(nextFields.body);
      setRemoveSignature(nextFields.removeSignature);
      return;
    }

    const isFinalized = card.status !== 'pending';
    const prevSynced = lastSyncedFieldsRef.current;

    if (nextFields.to !== prevSynced.to || (isFinalized && dirtyRef.current.to)) {
      prevSynced.to = nextFields.to;
      if (isFinalized || (activeFieldRef.current !== 'to' && !dirtyRef.current.to)) {
        setTo(nextFields.to);
        dirtyRef.current.to = false;
      }
    }
    if (nextFields.bcc !== prevSynced.bcc || (isFinalized && dirtyRef.current.bcc)) {
      prevSynced.bcc = nextFields.bcc;
      if (isFinalized || (activeFieldRef.current !== 'bcc' && !dirtyRef.current.bcc)) {
        setBcc(nextFields.bcc);
        dirtyRef.current.bcc = false;
      }
    }
    if (nextFields.subject !== prevSynced.subject || (isFinalized && dirtyRef.current.subject)) {
      prevSynced.subject = nextFields.subject;
      if (
        isFinalized ||
        (activeFieldRef.current !== 'subject' && !dirtyRef.current.subject)
      ) {
        setSubject(nextFields.subject);
        dirtyRef.current.subject = false;
      }
    }
    if (nextFields.body !== prevSynced.body || (isFinalized && dirtyRef.current.body)) {
      prevSynced.body = nextFields.body;
      if (isFinalized || (activeFieldRef.current !== 'body' && !dirtyRef.current.body)) {
        setBody(nextFields.body);
        dirtyRef.current.body = false;
      }
    }
    if (
      nextFields.removeSignature !== prevSynced.removeSignature ||
      (isFinalized && dirtyRef.current.removeSignature)
    ) {
      prevSynced.removeSignature = nextFields.removeSignature;
      if (isFinalized || !dirtyRef.current.removeSignature) {
        setRemoveSignature(nextFields.removeSignature);
        dirtyRef.current.removeSignature = false;
      }
    }
  }, [card.id, card.status, card.fields]);

  const isPending = card.status === 'pending';

  const resolveMutation = useMutation({
    mutationFn: (action: 'send' | 'discard') =>
      hitlApi.resolveDraft(card.id, action, {
        ...card.fields,
        to,
        bcc,
        subject,
        body,
        remove_signature: removeSignature,
      }),
    onSuccess: (updated) => {
      upsertDraft(updated);
      void queryClient.invalidateQueries({ queryKey: ['thread-messages', card.thread_id] });
      pushToast({
        tone: updated.status === 'sent' ? 'success' : 'info',
        title: updated.status === 'sent' ? 'Draft sent' : 'Draft discarded',
      });
    },
    onError: (err: Error) => {
      if (err instanceof ApiError && err.status === 409) {
        pushToast({ tone: 'info', title: 'Draft already finalized' });
        void queryClient.invalidateQueries({ queryKey: ['thread-messages', card.thread_id] });
      } else {
        pushToast({ tone: 'error', title: 'Draft action failed', description: err.message });
      }
    },
  });

  const disableDraftsMutation = useMutation({
    mutationFn: () => botsApi.update(card.bot_id, { drafts_enabled: false }),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['roster'] });
      pushToast({ tone: 'info', title: 'Disabled draft holds for this bot' });
    },
    onError: (err: Error) => {
      pushToast({
        tone: 'error',
        title: 'Could not disable drafts',
        description: err.message,
      });
    },
  });

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
        className="flex items-center justify-between px-3.5 py-2.5"
        style={{
          backgroundColor: 'var(--bg-sidebar)',
          borderBottom: '1px solid var(--border-subtle)',
        }}
      >
        <div className="flex items-center gap-2 text-[13px] font-medium">
          <Mail size={15} strokeWidth={1.75} style={{ color: 'var(--text-secondary)' }} />
          <span className="capitalize">{card.channel_type || 'Email'} draft</span>
        </div>
        <span
          className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-[11.5px] font-medium"
          style={{
            backgroundColor:
              card.status === 'sent'
                ? 'var(--status-ok-bg)'
                : card.status === 'discarded'
                  ? 'var(--bg-subtle)'
                  : 'var(--status-warn-bg)',
            color:
              card.status === 'sent'
                ? 'var(--status-ok)'
                : card.status === 'discarded'
                  ? 'var(--text-muted)'
                  : 'var(--status-warn)',
          }}
        >
          {card.status === 'sent' && <Check size={12} strokeWidth={2.2} />}
          {card.status === 'pending'
            ? 'Needs approval'
            : card.status === 'sent'
              ? 'Sent'
              : 'Discarded'}
        </span>
      </div>

      <div className="p-3.5 space-y-2.5 text-[13px]">
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          <label className="block">
            <span className="text-[11.5px] font-medium" style={{ color: 'var(--text-muted)' }}>
              To
            </span>
            <input
              type="text"
              disabled={!isPending}
              value={to}
              onFocus={() => {
                activeFieldRef.current = 'to';
              }}
              onBlur={() => {
                if (activeFieldRef.current === 'to') activeFieldRef.current = null;
              }}
              onChange={(e) => {
                dirtyRef.current.to = true;
                setTo(e.target.value);
              }}
              className="w-full mt-0.5 px-2.5 py-1.5 rounded-lg text-[13px] outline-none disabled:opacity-70"
              style={{
                backgroundColor: 'var(--bg-sidebar)',
                border: '1px solid var(--border-subtle)',
              }}
            />
          </label>
          <label className="block">
            <span className="text-[11.5px] font-medium" style={{ color: 'var(--text-muted)' }}>
              Bcc
            </span>
            <input
              type="text"
              disabled={!isPending}
              value={bcc}
              onFocus={() => {
                activeFieldRef.current = 'bcc';
              }}
              onBlur={() => {
                if (activeFieldRef.current === 'bcc') activeFieldRef.current = null;
              }}
              onChange={(e) => {
                dirtyRef.current.bcc = true;
                setBcc(e.target.value);
              }}
              placeholder="Optional"
              className="w-full mt-0.5 px-2.5 py-1.5 rounded-lg text-[13px] outline-none disabled:opacity-70"
              style={{
                backgroundColor: 'var(--bg-sidebar)',
                border: '1px solid var(--border-subtle)',
              }}
            />
          </label>
        </div>

        <label className="block">
          <span className="text-[11.5px] font-medium" style={{ color: 'var(--text-muted)' }}>
            Subject
          </span>
          <input
            type="text"
            disabled={!isPending}
            value={subject}
            onFocus={() => {
              activeFieldRef.current = 'subject';
            }}
            onBlur={() => {
              if (activeFieldRef.current === 'subject') activeFieldRef.current = null;
            }}
            onChange={(e) => {
              dirtyRef.current.subject = true;
              setSubject(e.target.value);
            }}
            className="w-full mt-0.5 px-2.5 py-1.5 rounded-lg text-[13px] outline-none disabled:opacity-70"
            style={{
              backgroundColor: 'var(--bg-sidebar)',
              border: '1px solid var(--border-subtle)',
            }}
          />
        </label>

        <label className="block">
          <span className="text-[11.5px] font-medium" style={{ color: 'var(--text-muted)' }}>
            Body
          </span>
          <textarea
            rows={4}
            disabled={!isPending}
            value={body}
            onFocus={() => {
              activeFieldRef.current = 'body';
            }}
            onBlur={() => {
              if (activeFieldRef.current === 'body') activeFieldRef.current = null;
            }}
            onChange={(e) => {
              dirtyRef.current.body = true;
              setBody(e.target.value);
            }}
            className="w-full mt-0.5 px-2.5 py-2 rounded-lg text-[13px] outline-none resize-y disabled:opacity-70"
            style={{
              backgroundColor: 'var(--bg-sidebar)',
              border: '1px solid var(--border-subtle)',
            }}
          />
        </label>

        {isPending && (
          <div className="flex flex-wrap items-center justify-between gap-2 pt-1">
            <label className="inline-flex items-center gap-2 text-[12px] cursor-pointer select-none">
              <input
                type="checkbox"
                checked={removeSignature}
                onChange={(e) => {
                  dirtyRef.current.removeSignature = true;
                  setRemoveSignature(e.target.checked);
                }}
              />
              <span style={{ color: 'var(--text-secondary)' }}>Remove signature</span>
            </label>

            <button
              type="button"
              onClick={() => disableDraftsMutation.mutate()}
              className="text-[12px] hover:underline"
              style={{ color: 'var(--text-muted)' }}
            >
              Disable drafts for Bot
            </button>
          </div>
        )}

        {isPending && (
          <div className="flex items-center gap-2 pt-1">
            <button
              type="button"
              disabled={resolveMutation.isPending}
              onClick={() => resolveMutation.mutate('send')}
              className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-[12.5px] font-medium disabled:opacity-50"
              style={{
                backgroundColor: 'var(--accent-primary)',
                color: 'var(--bg-canvas)',
              }}
            >
              <Send size={13} strokeWidth={1.9} />
              Send
            </button>
            <button
              type="button"
              disabled={resolveMutation.isPending}
              onClick={() => resolveMutation.mutate('discard')}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12.5px] hover:bg-[var(--bg-subtle)] disabled:opacity-50"
              style={{ color: 'var(--text-secondary)' }}
            >
              <Trash2 size={13} strokeWidth={1.75} />
              Discard
            </button>
          </div>
        )}
      </div>
    </div>
  );
};
