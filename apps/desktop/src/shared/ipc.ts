import {
  Id,
  RuleMode,
  UserDecision,
  type ActionProposal,
  type ActionRecord,
  type Alert,
  type Rule,
  type SensorEvent,
} from '@vigil/core';
import { z } from 'zod';
import type { CALL_NAMES, PUSH_NAMES } from './channels.js';

/**
 * The renderer's whole view of the main process. Every call is one IPC
 * channel `vigil:<method>`; main validates the arguments with these schemas
 * before doing anything, because the renderer is untrusted.
 */
export const DecisionInput = z.object({
  verdict: UserDecision.shape.verdict,
  release: z.boolean(),
  remember: z.boolean().optional(),
  scope: UserDecision.shape.scope,
  note: z.string().max(2000).optional(),
});

export const Route = z.string().regex(/^[a-z]+(\/[A-Za-z0-9_-]+)?$/);

export const ThemePref = z.enum(['system', 'dark', 'light']);
export type ThemePref = z.infer<typeof ThemePref>;

export const calls = {
  getStatus: z.tuple([]),
  listAlerts: z.tuple([z.enum(['open', 'resolved']).optional()]),
  getAlertDetail: z.tuple([Id]),
  decide: z.tuple([Id, DecisionInput]),
  reopen: z.tuple([Id]),
  undoAction: z.tuple([Id]),
  approveProposal: z.tuple([Id]),
  rejectProposal: z.tuple([Id]),
  listRules: z.tuple([]),
  setRuleMode: z.tuple([z.string(), RuleMode]),
  listActions: z.tuple([]),
  getSettings: z.tuple([]),
  setTheme: z.tuple([ThemePref]),
  sendTestAlert: z.tuple([]),
  openMain: z.tuple([Route.optional()]),
  closePopup: z.tuple([]),
  /** The popup's content height in CSS pixels, so the window hugs it. */
  fitPopup: z.tuple([z.number().int().min(80).max(1000)]),
  quit: z.tuple([]),
} as const;
export type CallName = keyof typeof calls;

export interface SensorView {
  id: string;
  name: string;
  state: 'ok' | 'degraded' | 'down' | 'not_installed';
  detail?: string;
}

export interface StatusView {
  level: 'good' | 'fair' | 'poor';
  needsYou: number;
  reasons: string[];
  sensors: SensorView[];
  /** True while blocks are simulated because the privileged helper is missing. */
  dryRun: boolean;
}

export interface AlertDetail {
  alert: Alert;
  events: SensorEvent[];
  actions: ActionRecord[];
  proposals: ActionProposal[];
  rule?: Rule;
}

export interface RuleView {
  rule: Rule;
  /** Matches in the last 14 days (the detection engine's replay window), all modes. */
  matches: number;
}

export interface SettingsView {
  theme: ThemePref;
  dataDir: string;
  version: string;
}

/** Return types, one per call. */
export interface CallResults {
  getStatus: StatusView;
  listAlerts: Alert[];
  getAlertDetail: AlertDetail | null;
  decide: Alert;
  reopen: Alert;
  undoAction: ActionRecord;
  approveProposal: ActionRecord;
  rejectProposal: void;
  listRules: RuleView[];
  setRuleMode: Rule;
  listActions: ActionRecord[];
  getSettings: SettingsView;
  setTheme: void;
  sendTestAlert: Alert;
  openMain: void;
  closePopup: void;
  fitPopup: void;
  quit: void;
}

/** Pushed from main to every window. */
export interface Pushes {
  /** Alerts, actions or status changed; refetch what you show. */
  changed: [];
  /** The popup window should show this alert. */
  popup: [Id];
  /** Navigate the main window. */
  navigate: [string];
  theme: [ThemePref];
}

export type VigilApi = {
  [K in CallName]: (...args: z.input<(typeof calls)[K]>) => Promise<CallResults[K]>;
} & {
  on<K extends keyof Pushes>(channel: K, fn: (...args: Pushes[K]) => void): () => void;
};

// Compile-time check that channels.ts lists exactly these calls and pushes.
type Same<A, B> = [A] extends [B] ? ([B] extends [A] ? true : never) : never;
export const channelsMatch: [
  Same<(typeof CALL_NAMES)[number], CallName>,
  Same<(typeof PUSH_NAMES)[number], keyof Pushes>,
] = [true, true];
