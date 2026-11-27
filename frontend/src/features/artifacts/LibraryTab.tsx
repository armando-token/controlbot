import React, { useEffect, useMemo, useState } from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import {
  BookOpen,
  ExternalLink,
  File,
  FilePlus2,
  FileText,
  Image as ImageIcon,
  Link as LinkIcon,
  Pin,
  PinOff,
  Plug,
  Search,
  Trash2,
} from 'lucide-react';
import { libraryApi, pagesApi } from '../../lib/api';
import { downloadTextFile, formatRelativeTime } from '../../lib/markdown';
import type { Artifact, Bot, Channel, RosterResponse } from '../../lib/types';
import { useUiStore } from '../../stores/uiStore';

interface LibraryTabProps {
  bot?: Bot | null;
  channel?: Channel | null;
  allBots?: Bot[];
}

const FILTERS = [
  { id: 'all', label: 'All' },
  { id: 'page', label: 'Pages' },
  { id: 'media', label: 'Media' },
  { id: 'link', label: 'Links' },
  { id: 'file', label: 'Files' },
  { id: 'skill', label: 'Skills' },
  { id: 'app', label: 'Apps' },
  { id: 'pinned', label: 'Pinned' },
] as const;

export const LibraryTab: React.FC<LibraryTabProps> = ({ bot, channel, allBots }) => {
  const queryClient = useQueryClient();
  const activeTarget = useUiStore((s) => s.activeTarget);
  const setActivePageId = useUiStore((s) => s.setActivePageId);
  const setLightboxArtifact = useUiStore((s) => s.setLightboxArtifact);
  const pushToast = useUiStore((s) => s.pushToast);

  const [filter, setFilter] = useState<(typeof FILTERS)[number]['id']>('all');
  const [search, setSearch] = useState('');
  const [expandedGroups, setExpandedGroups] = useState<Record<string, boolean>>({});
  const [selectedMemberBotId, setSelectedMemberBotId] = useState<string>('');

  const roster = queryClient.getQueryData<RosterResponse>(['roster']);
  const effectiveChannel = useMemo(() => {
    if (channel) return channel;
    if (!bot && activeTarget?.kind === 'channel' && roster) {
      return (
        roster.channels.find(
          (c) => c.id === activeTarget.id || c.thread_id === activeTarget.threadId,
        ) ?? null
      );
    }
    return null;
  }, [channel, bot, activeTarget, roster]);

  const resolvedBots = allBots ?? roster?.bots ?? [];
  const channelBots = useMemo(() => {
    if (!effectiveChannel) return [];
    return effectiveChannel.bot_ids
      .map((id) => resolvedBots.find((b) => b.id === id))
      .filter((b): b is Bot => Boolean(b));
  }, [effectiveChannel, resolvedBots]);

  useEffect(() => {
    if (!effectiveChannel) {
      setSelectedMemberBotId('');
      return;
    }
    if (
      !selectedMemberBotId ||
      !effectiveChannel.bot_ids.includes(selectedMemberBotId)
    ) {
      setSelectedMemberBotId(effectiveChannel.bot_ids[0] ?? '');
    }
  }, [effectiveChannel, selectedMemberBotId]);

  const activeBot = useMemo(() => {
    if (bot) return bot;
    if (selectedMemberBotId) {
      return resolvedBots.find((b) => b.id === selectedMemberBotId) ?? null;
    }
    return channelBots[0] ?? null;
  }, [bot, selectedMemberBotId, resolvedBots, channelBots]);

  const effectiveBotId = activeBot?.id ?? effectiveChannel?.bot_ids?.[0] ?? '';

  const libraryQuery = useQuery({
    queryKey: ['library', effectiveBotId, filter, search],
    queryFn: () =>
      libraryApi.list(effectiveBotId, {
        type: filter === 'pinned' ? 'all' : filter,
        pinned: filter === 'pinned',
        q: search.trim() || undefined,
      }),
    enabled: Boolean(effectiveBotId),
  });

  const pinMutation = useMutation({
    mutationFn: ({ id, pinned }: { id: string; pinned: boolean }) =>
      libraryApi.togglePin(id, pinned),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ['library'] });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not update pin', description: err.message });
    },
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => libraryApi.remove(id),
    onSuccess: (_res, deletedId) => {
      void queryClient.invalidateQueries({ queryKey: ['library'] });
      void queryClient.invalidateQueries({ queryKey: ['thread-messages'] });
      queryClient.removeQueries({ queryKey: ['page', deletedId] });
      if (useUiStore.getState().activePageId === deletedId) {
        setActivePageId(null);
      }
      pushToast({ tone: 'info', title: 'Removed from library' });
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not delete item', description: err.message });
    },
  });

  const createPageMutation = useMutation({
    mutationFn: () =>
      pagesApi.create({
        bot_id: effectiveBotId,
        channel_id: effectiveChannel?.id ?? null,
        thread_id: effectiveChannel?.thread_id ?? activeBot?.thread_id ?? null,
        title: activeBot
          ? `${activeBot.name} Document`
          : `${effectiveChannel?.name || 'Channel'} Document`,
        content_md: '# New page\n\nWrite notes or ask your bot to expand this document.\n',
      }),
    onSuccess: (page) => {
      void queryClient.invalidateQueries({ queryKey: ['library'] });
      setActivePageId(page.id);
    },
    onError: (err: Error) => {
      pushToast({ tone: 'error', title: 'Could not create page', description: err.message });
    },
  });

  if (!bot && !effectiveChannel) {
    return (
      <div className="p-5 text-[13px]" style={{ color: 'var(--text-muted)' }}>
        Select a bot or channel to browse its library of Pages, skills, apps, files, media, and links.
      </div>
    );
  }

  const grouped = libraryQuery.data?.grouped ?? {
    pinned: [],
    today: [],
    this_week: [],
    older: [],
  };

  const openArtifact = (art: Artifact) => {
    if (art.type === 'page') {
      setActivePageId(art.id);
    } else if (art.type === 'media') {
      setLightboxArtifact(art);
    } else if (art.type === 'link' && art.url) {
      window.open(art.url, '_blank', 'noopener,noreferrer');
    } else if (art.content_md) {
      downloadTextFile(`${art.title || 'artifact'}.md`, art.content_md);
    }
  };

  const iconFor = (type: Artifact['type']) => {
    switch (type) {
      case 'page':
        return <FileText size={15} strokeWidth={1.75} style={{ color: 'var(--accent-computer)' }} />;
      case 'media':
        return <ImageIcon size={15} strokeWidth={1.75} style={{ color: 'var(--text-secondary)' }} />;
      case 'link':
        return <LinkIcon size={15} strokeWidth={1.75} style={{ color: 'var(--text-secondary)' }} />;
      case 'skill':
        return <BookOpen size={15} strokeWidth={1.75} style={{ color: 'var(--accent-computer)' }} />;
      case 'app':
        return <Plug size={15} strokeWidth={1.75} style={{ color: 'var(--text-secondary)' }} />;
      default:
        return <File size={15} strokeWidth={1.75} style={{ color: 'var(--text-secondary)' }} />;
    }
  };

  const sections: { key: string; label: string; items: Artifact[] }[] = [
    { key: 'pinned', label: 'Pinned', items: grouped.pinned },
    { key: 'today', label: 'Today', items: grouped.today },
    { key: 'this_week', label: 'This week', items: grouped.this_week },
    { key: 'older', label: 'Older', items: grouped.older },
  ];

  const totalCount =
    grouped.pinned.length +
    grouped.today.length +
    grouped.this_week.length +
    grouped.older.length;

  return (
    <div className="h-full flex flex-col">
      {/* Search + New Page */}
      <div className="p-3.5 space-y-2.5 shrink-0" style={{ borderBottom: '1px solid var(--border-subtle)' }}>
        {!bot && effectiveChannel && channelBots.length > 0 && (
          <div className="flex items-center justify-between gap-2 text-[11.5px]">
            <span style={{ color: 'var(--text-muted)' }}>Member library</span>
            <select
              aria-label="Channel member library"
              value={effectiveBotId}
              onChange={(e) => setSelectedMemberBotId(e.target.value)}
              className="px-2 py-1 rounded-lg text-[12px] outline-none"
              style={{
                backgroundColor: 'var(--bg-sidebar)',
                border: '1px solid var(--border-subtle)',
                color: 'var(--text-primary)',
              }}
            >
              {channelBots.map((cb) => (
                <option key={cb.id} value={cb.id}>
                  {cb.name}
                </option>
              ))}
            </select>
          </div>
        )}

        <div className="flex items-center gap-2">
          <div
            className="flex-1 flex items-center gap-2 px-2.5 py-1.5 rounded-lg"
            style={{
              backgroundColor: 'var(--bg-sidebar)',
              border: '1px solid var(--border-subtle)',
            }}
          >
            <Search size={14} style={{ color: 'var(--text-muted)' }} />
            <input
              type="text"
              aria-label="Search library"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search library…"
              className="w-full text-[12.5px] bg-transparent outline-none"
            />
          </div>
          <button
            type="button"
            onClick={() => createPageMutation.mutate()}
            disabled={createPageMutation.isPending || !effectiveBotId}
            title={
              effectiveBotId
                ? 'New page'
                : 'Assign a bot to this channel before creating a page'
            }
            aria-label="Create new page"
            className="inline-flex items-center gap-1 px-2.5 py-1.5 rounded-lg text-[12px] font-medium shrink-0 disabled:opacity-50"
            style={{
              backgroundColor: 'var(--accent-primary)',
              color: 'var(--bg-canvas)',
            }}
          >
            <FilePlus2 size={13.5} />
            <span>New</span>
          </button>
        </div>

        {/* Filter pills */}
        <div className="flex flex-wrap gap-1">
          {FILTERS.map((f) => {
            const active = filter === f.id;
            return (
              <button
                key={f.id}
                type="button"
                onClick={() => setFilter(f.id)}
                className="px-2.5 py-1 rounded-full text-[11.5px] font-medium transition-colors"
                style={{
                  backgroundColor: active ? 'var(--bg-active)' : 'var(--bg-subtle)',
                  color: active ? 'var(--text-primary)' : 'var(--text-secondary)',
                }}
              >
                {f.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Grouped list */}
      <div className="flex-1 overflow-y-auto p-3.5 space-y-4">
        {!effectiveBotId ? (
          <div className="text-center py-10 space-y-2">
            <div className="text-[13px]" style={{ color: 'var(--text-secondary)' }}>
              No member bots assigned to #{effectiveChannel?.name || 'channel'} yet
            </div>
            <div className="text-[12px]" style={{ color: 'var(--text-muted)' }}>
              Assign a bot to this channel before browsing its library or creating a new Page.
            </div>
          </div>
        ) : libraryQuery.isLoading ? (
          <div className="text-[12.5px] py-6 text-center" style={{ color: 'var(--text-muted)' }}>
            Loading library…
          </div>
        ) : libraryQuery.isError ? (
          <div
            className="p-3 rounded-xl text-[12px] flex items-center justify-between gap-2"
            style={{
              backgroundColor: 'var(--status-danger-bg)',
              color: 'var(--status-danger)',
              border: '1px solid rgba(220, 38, 38, 0.2)',
            }}
          >
            <span>
              Could not load library:{' '}
              {libraryQuery.error instanceof Error ? libraryQuery.error.message : 'Request failed'}
            </span>
            <button
              type="button"
              onClick={() => void libraryQuery.refetch()}
              className="px-2 py-1 rounded-lg text-[11.5px] font-medium"
              style={{
                backgroundColor: 'var(--bg-canvas)',
                color: 'var(--text-primary)',
                border: '1px solid var(--border-strong)',
              }}
            >
              Retry
            </button>
          </div>
        ) : totalCount === 0 ? (
          <div className="text-center py-10 space-y-2">
            <div className="text-[13px]" style={{ color: 'var(--text-secondary)' }}>
              No items in library yet
            </div>
            <div className="text-[12px]" style={{ color: 'var(--text-muted)' }}>
              Save any message as a Page or create a new Page above.
            </div>
          </div>
        ) : (
          sections.map((sec) => {
            if (sec.items.length === 0) return null;
            const expanded = Boolean(expandedGroups[sec.key]);
            const visible = expanded ? sec.items : sec.items.slice(0, 5);
            const hasMore = sec.items.length > 5 && !expanded;

            return (
              <div key={sec.key} className="space-y-1.5">
                <div
                  className="text-[11px] font-medium uppercase tracking-wider px-1"
                  style={{ color: 'var(--text-muted)' }}
                >
                  {sec.label} ({sec.items.length})
                </div>

                {visible.map((art) => (
                  <div
                    key={art.id}
                    className="group flex items-center justify-between gap-2 px-2.5 py-2 rounded-xl transition-colors hover:bg-[var(--bg-subtle)]"
                    style={{ border: '1px solid var(--border-subtle)' }}
                  >
                    <button
                      type="button"
                      onClick={() => openArtifact(art)}
                      className="flex items-center gap-2.5 min-w-0 flex-1 text-left"
                    >
                      <span className="shrink-0">{iconFor(art.type)}</span>
                      <div className="min-w-0 flex-1">
                        <div
                          className="text-[13px] font-medium truncate"
                          style={{ color: 'var(--text-primary)' }}
                        >
                          {art.title}
                        </div>
                        <div className="text-[11px] capitalize" style={{ color: 'var(--text-muted)' }}>
                          {art.type} · {formatRelativeTime(art.updated_at)}
                        </div>
                      </div>
                    </button>

                    <div className="flex items-center gap-0.5 opacity-0 group-hover:opacity-100 group-focus-within:opacity-100 transition-opacity shrink-0">
                      {art.url && (
                        <a
                          href={art.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          title="Open link"
                          aria-label={`Open ${art.title}`}
                          className="p-1 rounded hover:bg-[var(--bg-active)]"
                          style={{ color: 'var(--text-muted)' }}
                        >
                          <ExternalLink size={13} />
                        </a>
                      )}
                      <button
                        type="button"
                        onClick={() => pinMutation.mutate({ id: art.id, pinned: !art.pinned })}
                        title={art.pinned ? 'Unpin' : 'Pin'}
                        aria-label={art.pinned ? `Unpin ${art.title}` : `Pin ${art.title}`}
                        className="p-1 rounded hover:bg-[var(--bg-active)]"
                        style={{
                          color: art.pinned ? 'var(--accent-computer)' : 'var(--text-muted)',
                        }}
                      >
                        {art.pinned ? <PinOff size={13} /> : <Pin size={13} />}
                      </button>
                      <button
                        type="button"
                        onClick={() => deleteMutation.mutate(art.id)}
                        title="Delete"
                        aria-label={`Delete ${art.title}`}
                        className="p-1 rounded hover:bg-[var(--status-danger-bg)]"
                        style={{ color: 'var(--status-danger)' }}
                      >
                        <Trash2 size={13} />
                      </button>
                    </div>
                  </div>
                ))}

                {hasMore && (
                  <button
                    type="button"
                    onClick={() =>
                      setExpandedGroups((prev) => ({ ...prev, [sec.key]: true }))
                    }
                    className="w-full py-1 text-[12px] font-medium rounded-lg hover:bg-[var(--bg-subtle)]"
                    style={{ color: 'var(--text-secondary)' }}
                  >
                    Show {sec.items.length - 5} more
                  </button>
                )}
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
