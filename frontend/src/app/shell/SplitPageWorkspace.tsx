import React from 'react';
import { Panel, PanelGroup, PanelResizeHandle } from 'react-resizable-panels';
import { useQuery } from '@tanstack/react-query';
import { pagesApi } from '../../lib/api';
import { InteractivePageViewer } from '../../features/artifacts/InteractivePageViewer';

interface SplitPageWorkspaceProps {
  pageId: string;
  renderChatPane: (pageTitle: string) => React.ReactNode;
}

export const SplitPageWorkspace: React.FC<SplitPageWorkspaceProps> = ({
  pageId,
  renderChatPane,
}) => {
  const pageQuery = useQuery({
    queryKey: ['page', pageId],
    queryFn: () => pagesApi.get(pageId),
  });

  const pageTitle = pageQuery.isError
    ? 'Page unavailable'
    : pageQuery.data?.title || 'Page';

  return (
    <PanelGroup direction="horizontal" className="h-full w-full">
      <Panel defaultSize={58} minSize={35} className="min-w-0">
        <InteractivePageViewer pageId={pageId} />
      </Panel>
      <PanelResizeHandle
        className="resize-handle"
        aria-label="Resize page and chat panels"
      />
      <Panel defaultSize={42} minSize={28} className="min-w-0">
        {renderChatPane(pageTitle)}
      </Panel>
    </PanelGroup>
  );
};
