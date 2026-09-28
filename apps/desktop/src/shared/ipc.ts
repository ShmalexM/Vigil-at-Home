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
import { AiPrefsPatch, AiProvider, type AiActionResult, type AiView } from './ai.js';
import type { AppearanceSettings } from './themes.js';
import type { UsageLimitsView, UsageReport } from './usage.js';
import { ApiKeyInput, ApiKeyProvider, SettingsPane, SetupMode, type SetupView } from './setup.js';

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

const HexColor = z.string().regex(/^#[0-9a-fA-F]{6}$/);
const FontFamily = z.string().regex(/^[\w\s,'"().-]{0,120}$/);
const VariantTheme = z.object({
  preset: z.string().regex(/^[a-z-]{1,40}$/),
  accent: HexColor.optional(),
  background: HexColor.optional(),
  foreground: HexColor.optional(),
});
/** Settings › Appearance; see shared/themes.ts. */
export const Appearance = z.object({
  light: VariantTheme,
  dark: VariantTheme,
  contrast: z.number().int().min(0).max(100),
  uiFontSize: z.number().int().min(11).max(16),
  uiFont: FontFamily,
  codeFont: FontFamily,
}) satisfies z.ZodType<AppearanceSettings>;

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

/** How far back one text search looks; the feed then offers the day before. */
export const TEXT_SEARCH_WINDOW_MS = 24 * 60 * 60 * 1000;

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

const RuleId = z.string().min(1).max(100);
/** A rule as JSON text from the editor. Main parses and validates it. */
const RuleJson = z.string().min(2).max(50_000);

/** One simple exclusion from the Rules screen: never fire when this field matches. */
export const ExclusionInput = z.object({
  field: z
    .string()
    .max(100)
    .regex(/^[a-z][A-Za-z0-9]*(\.[a-z][A-Za-z0-9]*)*$/),
  op: z.enum(['eq', 'startsWith', 'endsWith', 'contains', 'glob', 'in']),
  /** For `in`, a comma-separated list. */
  value: z.string().min(1).max(2000),
});
export type ExclusionInput = z.infer<typeof ExclusionInput>;

/** What an exclusion made from an alert covers. */
export const ExcludeScope = z.enum(['this_binary', 'this_signer', 'this_path', 'this_host']);
export type ExcludeScope = z.infer<typeof ExcludeScope>;

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
  getRuleEditor: z.tuple([RuleId]),
  previewRule: z.tuple([RuleJson]),
  saveRule: z.tuple([RuleJson]),
  revertRule: z.tuple([RuleId]),
  deleteRule: z.tuple([RuleId]),
  addExclusion: z.tuple([RuleId, ExclusionInput]),
  removeExclusion: z.tuple([RuleId, z.number().int().min(0).max(100)]),
  removeException: z.tuple([z.string().min(1).max(100)]),
  excludeFromAlert: z.tuple([Id, ExcludeScope]),
  listActions: z.tuple([]),
  listEvents: z.tuple([EventQuery]),
  eventStats: z.tuple([]),
  getSettings: z.tuple([]),
  setTheme: z.tuple([ThemePref]),
  setAppearance: z.tuple([Appearance]),
  sendTestAlert: z.tuple([]),
  openMain: z.tuple([Route.optional()]),
  closePopup: z.tuple([]),
  /** The popup's content height in CSS pixels, so the window hugs it. */
  fitPopup: z.tuple([z.number().int().min(80).max(1000)]),
  quit: z.tuple([]),
  // First-run setup (main/onboarding).
  getSetup: z.tuple([]),
  checkSetup: z.tuple([]),
  setSetupMode: z.tuple([SetupMode]),
  skipSetupStep: z.tuple([z.string().max(64), z.boolean()]),
  finishSetup: z.tuple([]),
  restartSetup: z.tuple([]),
  saveApiKey: z.tuple([ApiKeyInput]),
  clearApiKey: z.tuple([ApiKeyProvider]),
  openSettingsPane: z.tuple([SettingsPane]),
  installHelper: z.tuple([]),
  uninstallHelper: z.tuple([]),
  // The Usage page (main/usage.ts).
  getUsage: z.tuple([z.union([z.literal(1), z.literal(7), z.literal(30), z.literal(90)])]),
  /** True to read the vendors' limits again now. */
  getUsageLimits: z.tuple([z.boolean().optional()]),
  // AI (main/ai.ts).
  getAi: z.tuple([]),
  setAiPrefs: z.tuple([AiPrefsPatch]),
  signInAi: z.tuple([AiProvider]),
  shareCodexSignIn: z.tuple([]),
  stopSharingCodexSignIn: z.tuple([]),
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

/** Everything the rule editor shows for one rule. */
export interface RuleEditorView {
  rule: Rule;
  /** The rule as editable JSON, bookkeeping fields left out. */
  ruleJson: string;
  /** The mode the engine applies (the rule's own, or your or the engine's override). */
  mode: RuleMode;
  /** Shipped with Vigil. Built-ins can be edited and reverted, not deleted. */
  builtin: boolean;
  /** A built-in you changed. */
  edited: boolean;
  /** Vigil shipped a newer version of a built-in you changed. */
  builtinUpdateAvailable: boolean;
  /** The rule's exclusions, in plain words, in order (the index removes one). */
  exclusions: string[];
  /** "Don't alert me about this again" answers from alerts for this rule. */
  exceptions: { id: string; summary: string; note?: string; createdAt: number }[];
  /** Field names the rule language knows, for the exclusion form. */
  fields: string[];
}

/**
 * How a draft would have behaved over recent history. The same shape as
 * @vigil/detection's ReplayReport, restated so the renderer does not compile
 * the engine.
 */
export interface ReplayPreview {
  windowStart: number;
  windowEnd: number;
  eventsScanned: number;
  hits: number;
  popups: number;
  hitsPerDay: number;
  popupsPerDay: number;
  distinctPrograms: number;
  topPrograms: { program: string; hits: number }[];
  hitsOnUserAllowed: number;
  hitsOnAppleSigned: number;
  samples: {
    ts: number;
    program?: string;
    subject: string;
    reasons: string[];
    wouldDo: string[];
  }[];
  verdict: 'never_fired' | 'quiet' | 'ok' | 'noisy';
  notes: string[];
}

/** The result of checking or saving a rule draft. */
export interface RuleCheck {
  ok: boolean;
  errors: string[];
  warnings: string[];
  /** How the draft would have behaved on this Mac over the last 14 days. */
  replay?: ReplayPreview;
}

/**
 * What a model made of an event no rule matched. A hint for the person
 * reading the feed; it never blocks, allows or raises anything.
 */
export const EventLabel = z.object({
  label: z.enum(['benign', 'unusual', 'suspicious']),
  /** 0 to 1: how much a person should look at it. 0 for the local model's hints. */
  score: z.number().min(0).max(1),
  reason: z.string().max(300),
  by: z.enum(['model', 'jev']),
  at: z.number().int(),
});
export type EventLabel = z.infer<typeof EventLabel>;

export interface EventView {
  event: SensorEvent;
  outcome: EventOutcome | null;
  label?: EventLabel;
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
  appearance: AppearanceSettings;
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
  getRuleEditor: RuleEditorView | null;
  previewRule: RuleCheck;
  saveRule: RuleCheck;
  revertRule: void;
  deleteRule: void;
  addExclusion: RuleCheck;
  removeExclusion: RuleCheck;
  removeException: void;
  excludeFromAlert: RuleCheck;
  listActions: ActionRecord[];
  listEvents: EventView[];
  eventStats: EventStats;
  getSettings: SettingsView;
  setTheme: void;
  setAppearance: void;
  sendTestAlert: Alert;
  openMain: void;
  closePopup: void;
  fitPopup: void;
  quit: void;
  getSetup: SetupView;
  checkSetup: SetupView;
  setSetupMode: SetupView;
  skipSetupStep: SetupView;
  finishSetup: void;
  restartSetup: void;
  saveApiKey: SetupView;
  clearApiKey: SetupView;
  openSettingsPane: void;
  installHelper: HelperInstallResult;
  uninstallHelper: HelperInstallResult;
  getUsage: UsageReport;
  getUsageLimits: UsageLimitsView;
  getAi: AiView;
  setAiPrefs: AiView['prefs'];
  signInAi: AiActionResult;
  shareCodexSignIn: AiActionResult;
  stopSharingCodexSignIn: void;
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
