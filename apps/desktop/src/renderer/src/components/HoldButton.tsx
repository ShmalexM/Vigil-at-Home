import { useEffect, useRef, useState, type ReactNode } from 'react';

/**
 * Press and hold to confirm something risky, such as releasing a block.
 * A fill sweeps across while held; letting go early cancels. Enter or Space
 * held down works the same way from the keyboard.
 */
export function HoldButton({
  label,
  doneLabel,
  icon,
  ms = 1200,
  onConfirm,
  size,
  full,
  disabled,
}: {
  label: string;
  doneLabel?: string;
  icon?: ReactNode;
  ms?: number;
  onConfirm: () => void;
  size?: 'sm' | 'lg';
  full?: boolean;
  disabled?: boolean;
}) {
  const [state, setState] = useState<'idle' | 'holding' | 'done'>('idle');
  const timer = useRef<ReturnType<typeof setTimeout>>(undefined);

  useEffect(() => () => clearTimeout(timer.current), []);

  const start = () => {
    if (disabled || state !== 'idle') return;
    setState('holding');
    timer.current = setTimeout(() => {
      setState('done');
      onConfirm();
    }, ms);
  };
  const cancel = () => {
    if (state !== 'holding') return;
    clearTimeout(timer.current);
    setState('idle');
  };

  const fill =
    state === 'idle'
      ? { width: '0%', transition: 'width .18s ease-out' }
      : { width: '100%', transition: state === 'holding' ? `width ${ms}ms linear` : 'none' };

  return (
    <button
      type="button"
      className={`btn hold ${state} ${size ?? ''} ${full ? 'full' : ''}`}
      aria-label={`${label}. Press and hold to confirm.`}
      disabled={disabled}
      onPointerDown={start}
      onPointerUp={cancel}
      onPointerLeave={cancel}
      onKeyDown={(e) => {
        if ((e.key === 'Enter' || e.key === ' ') && !e.repeat) {
          e.preventDefault();
          start();
        }
      }}
      onKeyUp={cancel}
    >
      <span className="hold-fill" style={fill} aria-hidden />
      <span className="hold-label">
        {icon}
        {state === 'done' ? (doneLabel ?? label) : state === 'holding' ? 'Keep holding…' : label}
      </span>
    </button>
  );
}
