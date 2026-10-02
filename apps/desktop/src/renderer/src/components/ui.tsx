import { Check, Minus, X } from 'lucide-react';
import type { ButtonHTMLAttributes, ReactNode } from 'react';
import type { Severity } from '@vigil/core';
import { severityLabel } from '../format';
import { onRovingKeyDown, rovingTabIndex } from './roving';

type Kind = 'primary' | 'secondary' | 'ghost' | 'outline' | 'danger' | 'good';

export function Button({
  kind = 'secondary',
  size,
  full,
  icon,
  children,
  className = '',
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  kind?: Kind;
  size?: 'sm' | 'lg';
  full?: boolean;
  icon?: ReactNode;
}) {
  const cls = ['btn', kind !== 'secondary' && kind, size, full && 'full', className]
    .filter(Boolean)
    .join(' ');
  return (
    <button type="button" className={cls} {...rest}>
      {icon}
      {children}
    </button>
  );
}

export function IconButton({
  label,
  children,
  size,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & { label: string; size?: 'sm' }) {
  return (
    <button
      type="button"
      className={`btn ghost icon-btn ${size ?? ''}`}
      aria-label={label}
      title={label}
      {...rest}
    >
      {children}
    </button>
  );
}

export type Level = 'good' | 'fair' | 'poor';
const levelName: Record<Level, string> = { good: 'Good', fair: 'Fair', poor: 'Poor' };

/** Good / Fair / Poor: shape and word as well as colour. */
export function LevelPill({
  level,
  label,
  small,
}: {
  level: Level;
  label?: string;
  small?: boolean;
}) {
  const Glyph = { good: Check, fair: Minus, poor: X }[level];
  return (
    <span className={`pill ${level} ${small ? 'sm' : ''}`}>
      <Glyph size={11} strokeWidth={3} aria-hidden />
      {label ?? levelName[level]}
    </span>
  );
}

export function SeverityMark({ severity }: { severity: Severity }) {
  return (
    <span className="sev" style={{ ['--sev-color' as string]: `var(--sev-${severity})` }}>
      {severityLabel[severity]}
    </span>
  );
}

export function Chip({
  tone,
  children,
  title,
}: {
  tone?: 'accent' | 'good' | 'fair' | 'poor' | 'ai' | undefined;
  children: ReactNode;
  title?: string;
}) {
  return (
    <span className={`chip ${tone ?? ''}`} title={title}>
      {children}
    </span>
  );
}

export function Card({
  children,
  tight,
  className = '',
}: {
  children: ReactNode;
  tight?: boolean;
  className?: string;
}) {
  return <section className={`card ${tight ? 'tight' : ''} ${className}`}>{children}</section>;
}

export function SectionHead({
  title,
  sub,
  right,
}: {
  title: string;
  sub?: string;
  right?: ReactNode;
}) {
  return (
    <div className="row spread" style={{ alignItems: 'flex-start' }}>
      <div className="col" style={{ gap: 3 }}>
        <h2 className="t-h2">{title}</h2>
        {sub && <span className="t-small">{sub}</span>}
      </div>
      {right && <div className="row">{right}</div>}
    </div>
  );
}

export function Segmented<T extends string>({
  value,
  options,
  onChange,
  label,
  disabled,
}: {
  value: T;
  options: { value: T; label: string }[];
  onChange: (v: T) => void;
  label: string;
  disabled?: boolean;
}) {
  return (
    <span
      className="seg"
      role="tablist"
      aria-label={label}
      aria-disabled={disabled || undefined}
      onKeyDown={onRovingKeyDown}
    >
      {options.map((o, i) => (
        <button
          key={o.value}
          type="button"
          role="tab"
          aria-selected={o.value === value}
          tabIndex={rovingTabIndex(
            o.value === value,
            i,
            options.some((x) => x.value === value),
          )}
          disabled={disabled}
          onClick={() => onChange(o.value)}
        >
          {o.label}
        </button>
      ))}
    </span>
  );
}

export type MarkState = 'pending' | 'running' | 'done' | 'failed' | 'warn';

/** One glyph for a lifecycle: dashed ring, turning arc, check, cross or bang. */
export function StatusMark({ state, label }: { state: MarkState; label: string }) {
  const ring = (stroke: string, fill = false) => (
    <circle
      cx="12"
      cy="12"
      r="9"
      stroke={stroke}
      strokeWidth="2"
      fill={fill ? stroke : 'none'}
      fillOpacity={0.14}
    />
  );
  return (
    <span className="mark" role="img" aria-label={label} title={label}>
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
        {state === 'pending' && (
          <circle
            cx="12"
            cy="12"
            r="9"
            stroke="var(--tx3)"
            strokeWidth="2"
            strokeDasharray="2.6 3.4"
          />
        )}
        {state === 'running' && (
          <>
            {ring('var(--ln2)')}
            <circle
              className="spin"
              cx="12"
              cy="12"
              r="9"
              stroke="var(--ac)"
              strokeWidth="2.2"
              strokeLinecap="round"
              strokeDasharray="36 60"
            />
          </>
        )}
        {state === 'done' && (
          <>
            {ring('var(--good)', true)}
            <path
              className="draw"
              d="M7.8 12.4l2.9 2.9 5.6-5.8"
              stroke="var(--good)"
              strokeWidth="2.2"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          </>
        )}
        {state === 'failed' && (
          <>
            {ring('var(--poor)', true)}
            <path
              className="draw"
              d="M9.2 9.2l5.6 5.6M14.8 9.2l-5.6 5.6"
              stroke="var(--poor)"
              strokeWidth="2.2"
              strokeLinecap="round"
            />
          </>
        )}
        {state === 'warn' && (
          <>
            {ring('var(--fair)', true)}
            <path
              d="M12 7.6v5.4M12 16.3v.1"
              stroke="var(--fair)"
              strokeWidth="2.4"
              strokeLinecap="round"
            />
          </>
        )}
      </svg>
    </span>
  );
}
