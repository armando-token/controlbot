import React, { memo, useState } from 'react';
import ReactMarkdown from 'react-markdown';
import remarkGfm from 'remark-gfm';
import { Check, Copy } from 'lucide-react';
import { computerApi } from '../lib/api';
import { copyToClipboard, splitMarkdownBlocks } from '../lib/markdown';
import { useComputerStore } from '../stores/computerStore';
import { useUiStore } from '../stores/uiStore';

function openUrlInLiveBrowser(href: string): void {
  useComputerStore.getState().setPreferredSource('screencast');
  useUiStore.getState().openInspectorTab('computer');
  void computerApi
    .action('default', { type: 'navigate', url: href })
    .then((res) => {
      useComputerStore.getState().setStatus(res.status);
    })
    .catch((err: unknown) => {
      useUiStore.getState().pushToast({
        tone: 'warn',
        title: 'Could not open link in Live Browser',
        description: err instanceof Error ? err.message : 'Navigation failed',
      });
    });
}

interface CodeBlockProps {
  className?: string;
  children?: React.ReactNode;
}

const CodeBlock: React.FC<CodeBlockProps> = ({ className, children }) => {
  const [copied, setCopied] = useState(false);
  const raw = String(children ?? '').replace(/\n$/, '');
  const langMatch = /language-([\w-]+)/.exec(className || '');
  const lang = langMatch ? langMatch[1] : 'code';

  const handleCopy = async () => {
    const ok = await copyToClipboard(raw);
    if (ok) {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    }
  };

  const copyLabel = copied ? 'Copied' : 'Copy';

  return (
    <div
      className="my-2.5 overflow-hidden rounded-xl"
      style={{
        backgroundColor: 'var(--bg-terminal)',
        border: '1px solid rgba(15, 23, 42, 0.14)',
      }}
    >
      <div
        className="flex items-center justify-between px-3 py-1.5 text-[11.5px]"
        style={{
          backgroundColor: 'rgba(255, 255, 255, 0.04)',
          borderBottom: '1px solid rgba(255, 255, 255, 0.08)',
          color: '#A1A7B5',
        }}
      >
        <span className="font-mono uppercase tracking-wider text-[10.5px]">{lang}</span>
        <button
          type="button"
          aria-label={`${copyLabel}`}
          onClick={() => void handleCopy()}
          className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md transition-colors hover:bg-white/10"
          style={{ color: copied ? '#4ADE80' : '#D1D5DB' }}
        >
          {copied ? <Check size={12} strokeWidth={2} /> : <Copy size={12} strokeWidth={1.75} />}
          <span>{copied ? 'Copied' : 'Copy'}</span>
        </button>
      </div>
      <pre className="m-0 p-3 overflow-x-auto text-[12.5px] leading-[1.55] font-mono text-[#E5E7EB]">
        <code>{raw}</code>
      </pre>
    </div>
  );
};

const MarkdownBlock = memo(function MarkdownBlock({ content }: { content: string }) {
  return (
    <ReactMarkdown
      remarkPlugins={[remarkGfm]}
      components={{
        pre({ children }) {
          return <>{children}</>;
        },
        code({ className, children, ...props }) {
          const isBlock = Boolean(className) || String(children ?? '').includes('\n');
          if (isBlock) {
            return <CodeBlock className={className}>{children}</CodeBlock>;
          }
          return (
            <code className={className} {...props}>
              {children}
            </code>
          );
        },
        table({ children }) {
          return (
            <div className="gb-table-wrap">
              <table>{children}</table>
            </div>
          );
        },
        a({ href, children, onClick, title, ...props }) {
          const isHttpUrl = typeof href === 'string' && /^https?:\/\//i.test(href);
          return (
            <a
              href={href}
              target="_blank"
              rel="noopener noreferrer"
              title={
                isHttpUrl
                  ? 'Open in Live Browser (Ctrl/Cmd+Click for new tab)'
                  : title
              }
              onClick={(e) => {
                onClick?.(e);
                if (
                  !isHttpUrl ||
                  e.defaultPrevented ||
                  e.metaKey ||
                  e.ctrlKey ||
                  e.shiftKey ||
                  e.altKey ||
                  e.button !== 0
                ) {
                  return;
                }
                e.preventDefault();
                openUrlInLiveBrowser(href);
              }}
              {...props}
            >
              {children}
            </a>
          );
        },
      }}
    >
      {content}
    </ReactMarkdown>
  );
});

interface MarkdownRendererProps {
  content: string;
  streaming?: boolean;
  className?: string;
}

export const MarkdownRenderer: React.FC<MarkdownRendererProps> = ({
  content,
  streaming = false,
  className = '',
}) => {
  if (!content) return null;

  if (!streaming) {
    return (
      <div className={`gb-markdown ${className}`}>
        <MarkdownBlock content={content} />
      </div>
    );
  }

  const blocks = splitMarkdownBlocks(content);
  return (
    <div className={`gb-markdown ${className}`}>
      {blocks.map((block, idx) => (
        <MarkdownBlock key={`${idx}-${idx === blocks.length - 1 ? 'live' : block.length}`} content={block} />
      ))}
    </div>
  );
};
