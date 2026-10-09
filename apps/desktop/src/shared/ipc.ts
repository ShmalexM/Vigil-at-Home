import {
  AgentId,
  AgentIdentityInput,
  AgentMatcher,
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
import type {
  AgentCandidate,
  AgentDetail,
  AgentMatchPreview,
  AgentPrefs as AgentPrefsShape,
  AgentSessionView,
  AgentToolsStatus,
  AgentView,
  PreflightStatus,
  SaveAgentResult,
  TreeNode,
  VigilHelperView,
} from './agents.js';
import {
  ChatContext,
  ConnectorInput,
  DogInput,
  DogPatch,
  PackVoice,
  PermissionMode,
  ToolChoice,
  ToolDecision,
  ToolKey,
  type DogNote,
  type MemoryEntry,
  type PackView,
  NotesFilter,
  MemoryInput,
} from './pack.js';
import type { AppearanceSettings } from './themes.js';

const DogRef = z.string().regex(/^[a-z0-9-]{1,64}$/);
const ConnectorRef = z.string().regex(/^[a-z0-9-]{1,40}$/);
import type { UpdateView } from './updates.js';
import type { UsageLimitsView, UsageReport } from './usage.js';
import {
  ApiKeyInput,
  ApiKeyProvider,
  FeedKey,
  FeedKeyName,
  type FeedKeysView,
  SettingsPane,
  SetupAction,
  SetupMode,
  type SetupView,
} from './setup.js';

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
 * How much of what Vigil notices the user sees. `less`: only what needs a
 * decision badges the menu bar; noticed alerts fold into one line. `more`:
 * noticed alerts are listed in full and count in the badge. Neither changes
 * what Vigil blocks or the Good/Fair/Poor level.
 */
export const AlertView = z.enum(['less', 'more']);
export type AlertView = z.infer<typeof AlertView>;

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
  uiFontSize: z.number().int().min(11).max(26),
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
export const EventGroup = z.enum(['programs', 'network', 'files', 'startup', 'system', 'agents']);
export type EventGroup = z.infer<typeof EventGroup>;

export const EVENT_GROUPS: Record<EventGroup, EventKind[]> = {
  programs: ['process.exec', 'process.exit', 'santa.decision'],
  network: ['network.connection', 'network.listen'],
  files: ['file'],
  startup: ['persistence', 'browser.extension'],
  system: ['system.alert'],
  agents: ['agent.tool_request'],
};

/** One run of an agent (see AgentSessionView): 16 hex chars. */
export const AgentSessionId = z.string().regex(/^[0-9a-f]{16}$/);

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
  /** With `before`: the id of the last event shown, for events sharing its ts. */
  beforeId: z.string().min(1).max(128).optional(),
  limit: z.number().int().min(1).max(500).optional(),
  /** Only events from this agent's sessions. */
  agent: AgentId.optional(),
  /** Only events from one agent session. */
  agentSession: AgentSessionId.optional(),
});
export type EventQuery = z.infer<typeof EventQuery>;

/** Agents › Tool policy switches (main/agents/service.ts). */
export const AgentPrefs = z.object({
  preflightEnabled: z.boolean(),
  onUnavailable: z.enum(['ask', 'defer']),
  suggestions: z.boolean(),
  toolsEnabled: z.boolean(),
}) satisfies z.ZodType<AgentPrefsShape>;
export type AgentPrefs = AgentPrefsShape;

/** A change to some agent prefs. */
export const AgentPrefsPatch = AgentPrefs.partial();
export type AgentPrefsPatch = z.input<typeof AgentPrefsPatch>;

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
  clearNoticed: z.tuple([z.array(Id).min(1).max(500)]),
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
  listRuleSuggestions: z.tuple([]),
  acceptRuleSuggestion: z.tuple([RuleId, RuleMode.optional()]),
  dismissRuleSuggestion: z.tuple([RuleId, z.string().max(500).optional()]),
  reviewRulesNow: z.tuple([]),
  listActions: z.tuple([]),
  listEvents: z.tuple([EventQuery]),
  eventStats: z.tuple([]),
  getSettings: z.tuple([]),
  setTheme: z.tuple([ThemePref]),
  setAlertView: z.tuple([AlertView]),
  setShowAdvanced: z.tuple([z.boolean()]),
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
  runSetupAction: z.tuple([SetupAction]),
  finishSetup: z.tuple([]),
  restartSetup: z.tuple([]),
  saveApiKey: z.tuple([ApiKeyInput]),
  clearApiKey: z.tuple([ApiKeyProvider]),
  /** Keys for threat feeds that need one, such as abuse.ch's Auth-Key. Only whether one is saved comes back. */
  getFeedKeys: z.tuple([]),
  saveFeedKey: z.tuple([FeedKeyName, FeedKey]),
  clearFeedKey: z.tuple([FeedKeyName]),
  openSettingsPane: z.tuple([SettingsPane]),
  installHelper: z.tuple([]),
  uninstallHelper: z.tuple([]),
  // The Usage page (main/usage.ts).
  getUsage: z.tuple([z.union([z.literal(1), z.literal(7), z.literal(30), z.literal(90)])]),
  /** True to read the vendors' limits again now. */
  getUsageLimits: z.tuple([z.boolean().optional()]),
  // AI (main/ai.ts).
  getAi: z.tuple([]),
  /** The saved AI switches only, without probing the vendors' CLIs. */
  getAiPrefs: z.tuple([]),
  turnAiBackOn: z.tuple([]),
  setAiPrefs: z.tuple([AiPrefsPatch]),
  /** The user asked for an explanation of this alert (may use their Claude plan). */
  explainAlert: z.tuple([Id]),
  signInAi: z.tuple([AiProvider]),
  shareCodexSignIn: z.tuple([]),
  stopSharingCodexSignIn: z.tuple([]),
  // Update notices (main/updates.ts).
  getUpdates: z.tuple([]),
  checkUpdates: z.tuple([]),
  setUpdateAuto: z.tuple([z.boolean()]),
  dismissUpdate: z.tuple([]),
  downloadUpdate: z.tuple([]),
  // Agents (main/agents).
  listAgents: z.tuple([]),
  listAgentNames: z.tuple([]),
  getAgent: z.tuple([AgentId]),
  saveAgent: z.tuple([AgentIdentityInput]),
  setAgentWatch: z.tuple([AgentId, z.boolean()]),
  setAgentStatus: z.tuple([AgentId, z.enum(['active', 'ignored'])]),
  removeAgent: z.tuple([AgentId]),
  /** A built-in agent back to Vigil's own matchers, watch and status. */
  resetAgent: z.tuple([AgentId]),
  previewAgentMatch: z.tuple([z.array(AgentMatcher).min(1).max(4)]),
  listAgentCandidates: z.tuple([]),
  listAgentSessions: z.tuple([
    AgentId,
    z.object({ before: z.number().int().optional() }).optional(),
  ]),
  getAgentSession: z.tuple([AgentSessionId]),
  getAgentPrefs: z.tuple([]),
  setAgentPrefs: z.tuple([AgentPrefsPatch]),
  getPreflightStatus: z.tuple([]),
  /** Vigil's read-only tools for your own agents (MCP). */
  getAgentToolsStatus: z.tuple([]),
  listVigilHelpers: z.tuple([]),
  getPack: z.tuple([]),
  setPackMode: z.tuple([PermissionMode]),
  setPackVoice: z.tuple([PackVoice]),
  sayToLead: z.tuple([z.string().min(1).max(4000), ChatContext.optional()]),
  clearLeadChat: z.tuple([]),
  decideLeadAction: z.tuple([Id, Id, z.boolean()]),
  decidePackTool: z.tuple([Id, ToolDecision]),
  adoptDog: z.tuple([DogInput]),
  updateDog: z.tuple([DogRef, DogPatch]),
  retireDog: z.tuple([DogRef]),
  runDog: z.tuple([DogRef]),
  setPackToolChoice: z.tuple([ToolKey, ToolChoice]),
  addConnector: z.tuple([ConnectorInput]),
  setConnectorEnabled: z.tuple([ConnectorRef, z.boolean()]),
  removeConnector: z.tuple([ConnectorRef]),
  refreshConnector: z.tuple([ConnectorRef]),
  /** A dog's notebook, or every note about one alert, rule, event or tool. */
  listPackNotes: z.tuple([NotesFilter]),
  clearPackNotes: z.tuple([DogRef.optional()]),
  /** What the pack remembers, from the person's own words. */
  listPackMemory: z.tuple([]),
  addPackMemory: z.tuple([MemoryInput]),
  /** One entry, or every entry when no id is given. */
  forgetPackMemory: z.tuple([Id.optional()]),
  packMemoryMarkdown: z.tuple([]),
  /** Keep or decline a memory change the Lead dog asked for, or undo one it made. */
  decideLeadMemory: z.tuple([Id, Id, z.boolean()]),
} as const;
export type CallName = keyof typeof calls;

export interface SensorView {
  id: string;
  name: string;
  state: 'ok' | 'degraded' | 'down' | 'not_installed';
  detail?: string;
  note?: string;
}

/** Proof that Vigil is running, for the "it's working" line. Today is since local midnight. */
export interface WatchSummary {
  /** Events Vigil checked against its rules today. */
  checkedToday: number;
  /** When the newest event arrived, or null before the first. */
  lastEventAt: number | null;
  /** Things a rule blocked or paused today. */
  blockedToday: number;
}

export interface StatusView {
  level: 'good' | 'fair' | 'poor';
  /** Open alerts that need a decision (shared/attention.ts needsDecision). */
  needsYou: number;
  /** Open alerts Vigil only noticed; they don't badge or lower the level. */
  noticed: number;
  reasons: string[];
  watch: WatchSummary;
  /** The user's Show me less / Show me more choice. */
  alertView: AlertView;
  /** The number on the menu-bar icon and the Alerts nav item. */
  badge: number;
  sensors: SensorView[];
  /** True while blocks are simulated because the privileged helper is missing. */
  dryRun: boolean;
  /** True when this build carries the helper, so the app can install it. */
  helperInstallable: boolean;
  /** True when the installed helper is older than (or not) the one this build ships. */
  helperOutdated: boolean;
  /** Background jobs whose latest run was given up on and none has finished since. */
  stuckJobs: string[];
  /** Why the AI can't work because of its switches, for one quiet line on Home. */
  aiOff?: string;
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

/**
 * What became of a rule change on the helper, which blocks with the app
 * closed. `declined`: it loosened blocking, the user cancelled the password,
 * and nothing changed. `unavailable`: the helper isn't connected; Vigil made
 * the change and the helper gets it when it reconnects.
 */
export type HelperOutcome = 'applied' | 'declined' | 'unavailable';

export interface RuleModeResult {
  rule: Rule;
  helper: HelperOutcome;
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

/**
 * What approving a change would stop catching (@vigil/detection's
 * ImpactReport): real events it goes quiet on, and look-alikes an attacker
 * could use that would slip through too.
 */
export interface ImpactPreview {
  lostEvents: number;
  stopsAlertingOn: { what: string; events: number; untrusted: boolean }[];
  lookAlikes: { what: string; how: string }[];
  findings: string[];
  verdict: 'no_loss' | 'narrow' | 'broad';
}

/**
 * A change the AI suggested for the rules, checked and replayed on this Mac's
 * last 14 days. Nothing changes until the user accepts it.
 */
export interface RuleSuggestionView {
  id: string;
  /** new_rule adds a rule; tuning adds an exclusion; retire turns a rule down. */
  kind: 'new_rule' | 'tuning' | 'retire';
  createdAt: number;
  provider: string;
  rationale: string;
  evidence: string[];
  ruleId: string;
  ruleName: string;
  description: string;
  severity: string;
  /** New rule: what it matches, in words. */
  condition?: string;
  /** Tuning: the exclusion it adds, in words. */
  exclusion?: string;
  /** Retire: the quieter mode. */
  retireTo?: 'alert' | 'shadow' | 'disabled';
  /** New rule: the whole rule, for reading or copying into the editor. */
  ruleJson?: string;
  replay?: ReplayPreview;
  tuning?: { hitsBefore: number; hitsAfter: number; removed: number };
  impact?: ImpactPreview;
  warnings: string[];
}

export interface RuleSuggestionsView {
  pending: RuleSuggestionView[];
  /** The last few decided suggestions. */
  recent: {
    id: string;
    kind: RuleSuggestionView['kind'];
    ruleName: string;
    status: 'approved' | 'rejected' | 'rejected_by_checks' | 'withdrawn';
    at: number;
  }[];
  review: {
    /** A cloud AI is set up to run reviews. */
    available: boolean;
    lastRunAt?: number;
    lastOkAt?: number;
    lastError?: string;
    lastSummary?: string;
    nextDueAt?: number;
  };
}

/** The result of checking or saving a rule draft. */
export interface RuleCheck {
  ok: boolean;
  errors: string[];
  warnings: string[];
  /** How the draft would have behaved on this Mac over the last 14 days. */
  replay?: ReplayPreview;
  /** For an edit to an existing rule: what it would stop catching. */
  impact?: ImpactPreview;
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
  /** Short commit hash of the build, '' when unknown. */
  commit: string;
  /** The sidebar's Advanced group was left open. */
  showAdvanced: boolean;
}

/** Return types, one per call. */
export interface CallResults {
  getStatus: StatusView;
  listAlerts: Alert[];
  getAlertDetail: AlertDetail | null;
  decide: Alert;
  reopen: Alert;
  /** How many of the given alerts were cleared. */
  clearNoticed: number;
  undoAction: ActionRecord;
  approveProposal: ActionRecord;
  rejectProposal: void;
  listRules: RuleView[];
  setRuleMode: RuleModeResult;
  getRuleEditor: RuleEditorView | null;
  previewRule: RuleCheck;
  saveRule: RuleCheck;
  revertRule: void;
  deleteRule: void;
  addExclusion: RuleCheck;
  removeExclusion: RuleCheck;
  removeException: void;
  excludeFromAlert: RuleCheck;
  listRuleSuggestions: RuleSuggestionsView;
  acceptRuleSuggestion: { helper: HelperOutcome };
  dismissRuleSuggestion: void;
  reviewRulesNow: RuleSuggestionsView;
  listActions: ActionRecord[];
  listEvents: EventView[];
  eventStats: EventStats;
  getSettings: SettingsView;
  setTheme: void;
  setAlertView: void;
  setShowAdvanced: void;
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
  runSetupAction: SetupView;
  finishSetup: void;
  restartSetup: void;
  saveApiKey: SetupView;
  clearApiKey: SetupView;
  getFeedKeys: FeedKeysView;
  saveFeedKey: FeedKeysView;
  clearFeedKey: FeedKeysView;
  openSettingsPane: void;
  installHelper: HelperInstallResult;
  uninstallHelper: HelperInstallResult;
  getUsage: UsageReport;
  getUsageLimits: UsageLimitsView;
  getAi: AiView;
  getAiPrefs: AiView['prefs'];
  turnAiBackOn: AiView['prefs'];
  setAiPrefs: AiView['prefs'];
  explainAlert: AiActionResult;
  signInAi: AiActionResult;
  shareCodexSignIn: AiActionResult;
  stopSharingCodexSignIn: void;
  getUpdates: UpdateView;
  checkUpdates: UpdateView;
  setUpdateAuto: void;
  dismissUpdate: void;
  downloadUpdate: void;
  listAgents: AgentView[];
  /** The registry only, without listAgents' stats. */
  listAgentNames: Pick<AgentView, 'id' | 'name' | 'status'>[];
  getAgent: AgentDetail | null;
  saveAgent: SaveAgentResult;
  setAgentWatch: void;
  setAgentStatus: void;
  removeAgent: void;
  resetAgent: void;
  previewAgentMatch: AgentMatchPreview;
  listAgentCandidates: AgentCandidate[];
  listAgentSessions: AgentSessionView[];
  getAgentSession: AgentSessionDetail | null;
  getAgentPrefs: AgentPrefs;
  setAgentPrefs: AgentPrefs;
  getPreflightStatus: PreflightStatus;
  getAgentToolsStatus: AgentToolsStatus;
  listVigilHelpers: VigilHelperView[];
  getPack: PackView;
  setPackMode: void;
  setPackVoice: void;
  sayToLead: AiActionResult;
  clearLeadChat: void;
  decideLeadAction: void;
  decidePackTool: void;
  adoptDog: AiActionResult;
  updateDog: void;
  retireDog: void;
  runDog: AiActionResult;
  setPackToolChoice: void;
  addConnector: AiActionResult;
  setConnectorEnabled: void;
  removeConnector: void;
  refreshConnector: AiActionResult;
  listPackNotes: DogNote[];
  clearPackNotes: void;
  listPackMemory: MemoryEntry[];
  addPackMemory: { ok: boolean; error?: string };
  forgetPackMemory: void;
  packMemoryMarkdown: string;
  decideLeadMemory: void;
}

/** One agent session: its process tree (at most 200 nodes) and events (at most 500). */
export interface AgentSessionDetail {
  session: AgentSessionView;
  tree: TreeNode[];
  events: EventView[];
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
  /**
   * Agent activity was recorded: a pre-flight request, a session, a hook
   * check-in or a tools call. Sent at most every 2 seconds, for the views
   * that show those; `changed` covers everything else.
   */
  agents: [];
  /** The pack changed: a dog's mood, the chat, an approval. Only the Pack page listens. */
  pack: [];
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
