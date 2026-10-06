import { useSyncExternalStore } from 'react';
import type { ChatContext } from '../../shared/pack';
import { vigil } from './api';

/**
 * One conversation with the Lead dog, shared by the Pack page and the Ask
 * drawer on every other page. It lives outside React so a half-written
 * message survives moving between pages, and a failed send puts the words
 * back instead of losing them.
 */
interface LeadChatState {
  draft: string;
  sending: boolean;
  /** Why the last send didn't reach the Lead dog, shown by the box. */
  error: string | null;
  /** Whether the Ask drawer is open. */
  open: boolean;
}

let state: LeadChatState = { draft: '', sending: false, error: null, open: false };
const subs = new Set<() => void>();

function set(patch: Partial<LeadChatState>): void {
  state = { ...state, ...patch };
  for (const s of subs) s();
}

function subscribe(fn: () => void): () => void {
  subs.add(fn);
  return () => subs.delete(fn);
}

export function useLeadChat(): LeadChatState {
  return useSyncExternalStore(subscribe, () => state);
}

export const leadChat = {
  setDraft: (draft: string) => set({ draft, error: null }),
  open: () => set({ open: true }),
  close: () => set({ open: false }),
  toggle: () => set({ open: !state.open }),
  /**
   * Sends one message. Refuses when no AI is set up (the caller shows why),
   * and when the Lead dog didn't take it, puts the words back in an empty box
   * and says what went wrong.
   */
  async send(words: string, opts: { noAi: boolean; context?: ChatContext }): Promise<boolean> {
    const text = words.trim();
    if (!text || state.sending || opts.noAi) return false;
    set({ draft: '', sending: true, error: null });
    let error: string | null = null;
    try {
      const r = await vigil.sayToLead(text, opts.context);
      if (!r.ok) error = r.error ?? 'The Lead dog couldn’t answer';
    } catch (err) {
      error = err instanceof Error ? err.message : String(err);
    }
    set({
      sending: false,
      error: error ? `Not sent: ${error}` : null,
      ...(error && !state.draft ? { draft: text } : {}),
    });
    return !error;
  },
};

/** The current state, outside React. */
export function leadChatState(): Readonly<LeadChatState> {
  return state;
}

/** For tests: back to an empty, closed conversation. */
export function resetLeadChat(): void {
  state = { draft: '', sending: false, error: null, open: false };
}
