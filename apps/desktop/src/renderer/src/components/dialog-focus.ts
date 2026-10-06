import { useEffect, useRef, type RefObject } from 'react';

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';

/**
 * Keyboard handling for a dialog or drawer: focus moves into it when it
 * opens, Tab and Shift+Tab stay inside it, Escape closes it, and focus goes
 * back to where it was (or to `fallback`, when that element is gone) once it
 * closes.
 */
export function useDialogFocus(
  box: RefObject<HTMLElement | null>,
  onClose: () => void,
  fallback?: () => HTMLElement | null,
): void {
  const close = useRef(onClose);
  close.current = onClose;
  const back = useRef(fallback);
  back.current = fallback;
  // Read on the first render, before an autofocused field inside takes focus.
  const opener = useRef(document.activeElement as HTMLElement | null);

  useEffect(() => {
    const before = opener.current;
    const el = box.current;
    if (el && !el.contains(document.activeElement)) {
      (el.querySelector<HTMLElement>('[autofocus]') ?? first(el) ?? el).focus();
    }
    const onKey = (e: KeyboardEvent) => {
      const el = box.current;
      if (!el) return;
      if (e.key === 'Escape') {
        e.preventDefault();
        e.stopPropagation();
        close.current();
        return;
      }
      if (e.key !== 'Tab') return;
      const items = [...el.querySelectorAll<HTMLElement>(FOCUSABLE)].filter(
        (n) => n.offsetParent !== null || n === document.activeElement,
      );
      if (items.length === 0) {
        e.preventDefault();
        el.focus();
        return;
      }
      const at = items.indexOf(document.activeElement as HTMLElement);
      const next = e.shiftKey
        ? at <= 0
          ? items[items.length - 1]
          : items[at - 1]
        : at === -1 || at === items.length - 1
          ? items[0]
          : items[at + 1];
      e.preventDefault();
      next!.focus();
    };
    document.addEventListener('keydown', onKey, true);
    return () => {
      document.removeEventListener('keydown', onKey, true);
      // Wait for React to finish swapping elements, so the fallback exists.
      setTimeout(() => {
        const target = before?.isConnected ? before : back.current?.();
        target?.focus();
      }, 0);
    };
  }, [box]);
}

function first(el: HTMLElement): HTMLElement | null {
  return el.querySelector<HTMLElement>(FOCUSABLE);
}
