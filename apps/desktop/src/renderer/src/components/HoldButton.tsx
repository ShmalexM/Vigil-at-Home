import { useEffect, useRef, useState, type ReactNode } from 'react';
import { Hold, type HoldState } from './hold';

/**
 * Press and hold to confirm something risky, such as releasing a block.
 * A fill sweeps across while held; letting go early cancels. Enter or Space
 * held down works the same way from the keyboard. Only the pointer or key
 * that started the hold can finish it: tabbing away, the pointer leaving or
 * the system cancelling it all cancel the hold.
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
  const [state, setState] = useState<HoldState>('idle');
  const confirm = useRef(onConfirm);
  confirm.current = onConfirm;
  const hold = useRef<Hold>(undefined);
  hold.current ??= new Hold(ms, setState, () => confirm.current());
  hold.current.ms = ms;

  useEffect(() => () => hold.current?.abort(), []);
  useEffect(() => {
    if (disabled) hold.current?.abort();
  }, [disabled]);

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
      onPointerDown={(e) => {
        if (!disabled && e.button === 0) hold.current?.press({ pointer: e.pointerId });
      }}
      onPointerUp={(e) => hold.current?.release({ pointer: e.pointerId })}
      onPointerLeave={(e) => hold.current?.pointerLeft(e.pointerId)}
      onPointerCancel={() => hold.current?.abort()}
      onBlur={() => hold.current?.abort()}
      onKeyDown={(e) => {
        if ((e.key === 'Enter' || e.key === ' ') && !e.repeat) {
          e.preventDefault();
          if (!disabled) hold.current?.press({ key: e.key });
        }
      }}
      onKeyUp={(e) => hold.current?.release({ key: e.key })}
    >
      <span className="hold-fill" style={fill} aria-hidden />
      <span className="hold-label">
        {icon}
        {state === 'done' ? (doneLabel ?? label) : state === 'holding' ? 'Keep holding…' : label}
      </span>
    </button>
  );
}
