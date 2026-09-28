import {
  Id,
  RuleMode,
  UserDecision,
  type ActionProposal,
  type EventKind,
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

/**
 * What detection made of one event: how many rules looked at it and which
 * matched. Missing when nothing has analysed the event (no rules loaded yet).
 */
export const EventOutcome = z.object({
  checked: z.number().int().nonnegative(),
  matches: z.array(z.object({ ruleId: z.string(), ruleName: z.string(), mode: RuleMode })),
});
export type EventOutcome = z.infer<typeof EventOutcome>;

/** Which events broad kind the feed filters by. */
export const EventGroup = z.enum(['programs', 'network', 'files', 'startup', 'system']);
export type EventGroup = z.infer<typeof EventGroup>;

export const EVENT_GROUPS: Record<EventGroup, EventKind[]> = {
  programs: ['process.exec', 'process.exit', 'santa.decision'],
  network: ['network.connection', 'network.listen'],
  files: ['file'],
  startup: ['persistence', 'browser.extension'],
  system: ['system.alert'],
};

export const EventQuery = z.object({
  group: EventGroup.optional(),
  /** Only events that matched a rule. */
  matchedOnly: z.boolean().optional(),
  /** Case-insensitive text anywhere in the event. */
  text: z.string().max(200).optional(),
  /** Page backwards from this timestamp. */
  before: z.number().int().optional(),
  limit: z.number().int().min(1).max(500).optional(),
});
export type EventQuery = z.infer<typeof EventQuery>;

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
  listEvents: z.tuple([EventQuery]),
  eventStats: z.tuple([]),
  getSettings: z.tuple([]),
  setTheme: z.tuple([ThemePref]),
  sendTestAlert: z.tuple([]),
  openMain: z.tuple([Route.optional()]),
  closePopup: z.tuple([]),
  /** The popup's content height in CSS pixels, so the window hugs it. */
  fitPopup: z.tuple([z.number().int().min(80).max(1000)]),
  quit: z.tuple([]),
  installHelper: z.tuple([]),
  uninstallHelper: z.tuple([]),
} as const;
export type CallName = keyof typeof calls;

export interface SensorView {
  id: string;
  name: string;
  state: 'ok' | 'degraded' | 'down' | 'not_installed';
  detail?: string;
  note?: string;
}

export interface StatusView {
  level: 'good' | 'fair' | 'poor';
  needsYou: number;
  reasons: string[];
  sensors: SensorView[];
  /** True while blocks are simulated because the privileged helper is missing. */
  dryRun: boolean;
  /** True when this build carries the helper, so the app can install it. */
  helperInstallable: boolean;
}

export interface HelperInstallResult {
  ok: boolean;
  /** Set when it failed; "cancelled" when the user closed the password dialog. */
  error?: string;
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

export interface EventView {
  event: SensorEvent;
  outcome: EventOutcome | null;
}

export interface EventStats {
  /** Events in the last hour. */
  lastHour: number;
  /** Of those, how many matched a rule in any mode. */
  matchedLastHour: number;
  /** Distinct programs started in the last hour. */
  programsLastHour: number;
  /** Last hour's events by group. */
  byGroup: Record<EventGroup, number>;
  /** Timestamp of the newest event, if any. */
  newest: number | null;
  /** How many days of events Vigil keeps. */
  retentionDays: number;
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
  listEvents: EventView[];
  eventStats: EventStats;
  getSettings: SettingsView;
  setTheme: void;
  sendTestAlert: Alert;
  openMain: void;
  closePopup: void;
  fitPopup: void;
  quit: void;
  installHelper: HelperInstallResult;
  uninstallHelper: HelperInstallResult;
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
  /** New events were stored. Sent at most once a second, with how many arrived. */
  events: [number];
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
