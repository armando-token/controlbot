import React, { useEffect, useRef, useState } from 'react';
import type { AvatarShape, BotLifecycleState } from '../../lib/types';

export const AVATAR_SHAPES: { id: AvatarShape; label: string }[] = [
  { id: 'sparkle', label: 'Sparkle' },
  { id: 'square', label: 'Square' },
  { id: 'clover', label: 'Clover' },
  { id: 'flower', label: 'Flower' },
  { id: 'heart', label: 'Heart' },
  { id: 'house', label: 'House' },
  { id: 'star', label: 'Star' },
];

export const AVATAR_COLORS: string[] = [
  '#7C3AED', // Violet
  '#2563EB', // Cobalt
  '#0891B2', // Cyan
  '#059669', // Emerald
  '#D97706', // Amber
  '#DC2626', // Crimson
  '#DB2777', // Rose
  '#4F46E5', // Indigo
  '#111318', // Obsidian
];

interface BotAvatarProps {
  shape?: AvatarShape;
  color?: string;
  eyesLarge?: boolean;
  state?: BotLifecycleState;
  size?: number;
  tooltipText?: string;
  computerActive?: boolean;
  className?: string;
}

function renderShape(shape: AvatarShape, color: string): React.ReactNode {
  switch (shape) {
    case 'square':
      return <rect x="4" y="4" width="24" height="24" rx="7" fill={color} />;
    case 'sparkle':
      return (
        <path
          d="M16 2 C17.8 10 22 14.2 30 16 C22 17.8 17.8 22 16 30 C14.2 22 10 17.8 2 16 C10 14.2 14.2 10 16 2 Z"
          fill={color}
        />
      );
    case 'clover':
      return (
        <g fill={color}>
          <circle cx="11.5" cy="11.5" r="7" />
          <circle cx="20.5" cy="11.5" r="7" />
          <circle cx="11.5" cy="20.5" r="7" />
          <circle cx="20.5" cy="20.5" r="7" />
        </g>
      );
    case 'flower':
      return (
        <g fill={color}>
          <circle cx="16" cy="8.2" r="5.4" />
          <circle cx="23.4" cy="13.6" r="5.4" />
          <circle cx="20.6" cy="22.3" r="5.4" />
          <circle cx="11.4" cy="22.3" r="5.4" />
          <circle cx="8.6" cy="13.6" r="5.4" />
          <circle cx="16" cy="16" r="6.5" />
        </g>
      );
    case 'heart':
      return (
        <path
          d="M16 28.2 C15.4 28.2 4 21.2 4 12.6 C4 8.2 7.4 5 11.4 5 C13.8 5 15.3 6.3 16 7.8 C16.7 6.3 18.2 5 20.6 5 C24.6 5 28 8.2 28 12.6 C28 21.2 16.6 28.2 16 28.2 Z"
          fill={color}
        />
      );
    case 'house':
      return (
        <path
          d="M16 3.5 L28 13.5 C28.6 14 28.3 15 27.5 15 H26 V26 C26 27.4 24.9 28.5 23.5 28.5 H8.5 C7.1 28.5 6 27.4 6 26 V15 H4.5 C3.7 15 3.4 14 4 13.5 Z"
          fill={color}
        />
      );
    case 'star':
      return (
        <path
          d="M16 2.5 L19.9 10.7 L28.8 11.9 L22.3 18.1 L23.9 27 L16 22.7 L8.1 27 L9.7 18.1 L3.2 11.9 L12.1 10.7 Z"
          fill={color}
        />
      );
    default:
      return <rect x="4" y="4" width="24" height="24" rx="7" fill={color} />;
  }
}

export const BotAvatar: React.FC<BotAvatarProps> = ({
  shape = 'sparkle',
  color = '#7C3AED',
  eyesLarge = false,
  state = 'idle',
  size = 32,
  tooltipText,
  computerActive = false,
  className = '',
}) => {
  const [showTip, setShowTip] = useState(false);
  const timerRef = useRef<number | null>(null);

  const eyeRadius = eyesLarge ? 2.45 : 1.75;
  const eyeY = shape === 'house' ? 18.2 : shape === 'heart' ? 14.5 : 15.8;

  useEffect(() => {
    return () => {
      if (timerRef.current !== null) {
        window.clearTimeout(timerRef.current);
        timerRef.current = null;
      }
    };
  }, []);

  const onEnter = () => {
    if (!tooltipText) return;
    if (timerRef.current !== null) {
      window.clearTimeout(timerRef.current);
      timerRef.current = null;
    }
    timerRef.current = window.setTimeout(() => setShowTip(true), 250);
  };

  const onLeave = () => {
    if (timerRef.current !== null) {
      window.clearTimeout(timerRef.current);
      timerRef.current = null;
    }
    setShowTip(false);
  };

  return (
    <span
      className={`relative inline-flex items-center justify-center shrink-0 select-none ${className}`}
      style={{ width: size, height: size }}
      onMouseEnter={onEnter}
      onMouseLeave={onLeave}
    >
      <svg
        width={size}
        height={size}
        viewBox="0 0 32 32"
        className={`bot-avatar-${state}`}
        aria-hidden="true"
      >
        {renderShape(shape, color)}
        <g className="bot-eyes">
          {state === 'error' ? (
            <>
              <path
                d={`M11 ${eyeY - 1.5} L14 ${eyeY + 1.5} M14 ${eyeY - 1.5} L11 ${eyeY + 1.5}`}
                stroke="#FFFFFF"
                strokeWidth="1.6"
                strokeLinecap="round"
              />
              <path
                d={`M18 ${eyeY - 1.5} L21 ${eyeY + 1.5} M21 ${eyeY - 1.5} L18 ${eyeY + 1.5}`}
                stroke="#FFFFFF"
                strokeWidth="1.6"
                strokeLinecap="round"
              />
            </>
          ) : (
            <>
              <circle cx="12.4" cy={eyeY} r={eyeRadius} fill="#FFFFFF" />
              <circle cx="19.6" cy={eyeY} r={eyeRadius} fill="#FFFFFF" />
              {eyesLarge && (
                <>
                  <circle cx="12.9" cy={eyeY - 0.5} r="0.85" fill="#111318" />
                  <circle cx="20.1" cy={eyeY - 0.5} r="0.85" fill="#111318" />
                </>
              )}
            </>
          )}
        </g>
      </svg>

      {state === 'waiting_human' && (
        <span
          className="absolute -top-0.5 -right-0.5 w-2.5 h-2.5 rounded-full ring-2 ring-[var(--bg-sidebar)]"
          style={{ backgroundColor: 'var(--accent-takeover)' }}
          title="Needs your attention"
        />
      )}

      {computerActive && state !== 'waiting_human' && (
        <span
          className="absolute -bottom-0.5 -right-0.5 w-2.5 h-2.5 rounded-full ring-2 ring-[var(--bg-sidebar)]"
          style={{ backgroundColor: 'var(--accent-computer)' }}
          title="Using computer"
        />
      )}

      {showTip && tooltipText && (
        <span
          className="pointer-events-none absolute left-1/2 -translate-x-1/2 bottom-full mb-1.5 z-50 whitespace-nowrap px-2.5 py-1 rounded-lg text-[11.5px] font-medium"
          style={{
            backgroundColor: '#111318',
            color: '#FFFFFF',
            boxShadow: 'var(--shadow-md)',
          }}
        >
          {tooltipText}
        </span>
      )}
    </span>
  );
};
