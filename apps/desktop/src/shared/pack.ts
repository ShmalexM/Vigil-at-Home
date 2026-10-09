// The pack: Vigil's own AI agents. The Lead dog is the one the user talks to;
// it can add dogs to the pack, change them, send them off on a job or retire
// them, within the permission mode the user picked. Each pack dog has a job
// (its standing instructions), a schedule and the tools the user lets it use.
//
// What no dog can do, in any mode: block or allow anything on the Mac,
// release a block, answer a watched agent's pre-flight check, or approve or
// edit a rule. Vigil's own tools are read-only; connectors are the user's own
// MCP servers, and every call to one goes through the tool gate (pack.ts in
// main).

import { z } from 'zod';

export const Breed = z.enum([
  'shepherd',
  'doberman',
  'husky',
  'golden',
  'beagle',
  'corgi',
  'dachshund',
  'chihuahua',
]);
export type Breed = z.infer<typeof Breed>;

/** What a dog looks like it's doing. Driven by real work, never decoration alone. */
export type DogMood =
  'idle' | 'thinking' | 'sniffing' | 'fetching' | 'waiting' | 'done' | 'error' | 'sleeping';

/**
 * How much the pack may do without asking, like a coding agent's permission
 * modes. "ask": every pack change and every tool that can change something
 * waits for the user. "auto": the user's AI judges each such tool call and
 * low-risk ones go ahead (never on a Claude plan for background work).
 * "full": dogs go ahead, except where a rule or the user's own tool setting
 * says ask.
 */
export const PermissionMode = z.enum(['ask', 'auto', 'full']);
export type PermissionMode = z.infer<typeof PermissionMode>;

/** How the pack talks: with a little dog in it, or plain. Wording only; nothing else changes. */
export const PackVoice = z.enum(['pack', 'plain']);
export type PackVoice = z.infer<typeof PackVoice>;

/**
 * The user's choice for one tool. "auto" follows the permission mode; "ask"
 * always asks; "allow" never asks (rules still apply); "off" hides it from
 * every dog.
 */
export const ToolChoice = z.enum(['auto', 'ask', 'allow', 'off']);
export type ToolChoice = z.infer<typeof ToolChoice>;

export const Schedule = z.enum(['manual', 'hourly', 'daily', 'nightly']);
export type Schedule = z.infer<typeof Schedule>;

/** A tool's key: `vigil.<name>` for Vigil's own, `<connectorId>.<name>` for a connector's. */
export const ToolKey = z.string().regex(/^[a-z0-9-]{1,40}\.[A-Za-z0-9_.-]{1,64}$/);

/**
 * Where the person was in Vigil when they asked, so "what's this?" has an
 * answer. Ids only; the Lead dog reads the details with its own tools.
 */
export const ChatContext = z.object({
  page: z.string().regex(/^[a-z-]{1,24}$/),
  /** The alert, rule, agent or event open on that page. */
  selected: z
    .string()
    .regex(/^[A-Za-z0-9_.:-]{1,80}$/)
    .optional(),
});
export type ChatContext = z.infer<typeof ChatContext>;

export const DogName = z.string().trim().min(1).max(32);
export const DogJob = z.string().trim().min(1).max(2000);

export const DogInput = z.object({
  name: DogName,
  breed: Breed,
  job: DogJob,
  schedule: Schedule,
  tools: z.array(ToolKey).max(64),
});
export type DogInput = z.infer<typeof DogInput>;

export const DogPatch = DogInput.partial().extend({ enabled: z.boolean().optional() });
export type DogPatch = z.infer<typeof DogPatch>;

export interface DogReport {
  at: number;
  ok: boolean;
  summary: string;
  findings: {
    title: string;
    detail?: string | undefined;
    severity: 'info' | 'low' | 'medium' | 'high';
  }[];
  /** The AI that ran it. */
  provider?: string;
  /** The run used a tool, or read a report that did: the summary could hold anyone's text. */
  tainted?: boolean;
}

/** Vigil's built-in AI helpers, shown as pack dogs. Their jobs and tools are fixed. */
export type HelperId = 'explainer' | 'labeller' | 'rule-reviewer';

export interface Dog {
  id: string;
  /** lead: the one you talk to. helper: one of Vigil's built-in AI jobs. pack: made by you or the Lead dog. */
  role: 'lead' | 'helper' | 'pack';
  helper?: HelperId;
  name: string;
  breed: Breed;
  /** The Lead dog's job is fixed: talk with the user and manage the pack. */
  job: string;
  schedule: Schedule;
  tools: string[];
  enabled: boolean;
  createdBy: 'you' | 'lead';
  createdAt: number;
  /**
   * The job could hold someone else's text: it was written by a change from
   * an older Lead dog answer that read outside text. Cleared when the person
   * edits the job, or a later change from the acting path (which reads none)
   * writes it. A pack dog saved before this was recorded counts as tainted.
   * The acting path sees a tainted job only as `job:<dogId>`.
   */
  jobTainted?: boolean;
  /**
   * The name could hold someone else's text: it came from a change from an
   * older Lead dog answer that read outside text. Cleared when the person
   * names the dog themselves. Saved before this was recorded, it counts as
   * tainted unless it is the built-in name. Prompts then name the dog by its
   * id only; a name the person types is mapped to that id by exact match.
   */
  nameTainted?: boolean;
  lastReport?: DogReport;
}

/** What the Lead dog asked to do. Applied by Vigil, as the mode allows. */
export const LeadActionKind = z.enum(['create', 'update', 'run', 'retire']);
export type LeadActionKind = z.infer<typeof LeadActionKind>;

export interface LeadAction {
  id: string;
  kind: LeadActionKind;
  /** The dog it's about (update, run, retire, or the one created). */
  dogId?: string;
  /** For create and update. */
  dog?: Partial<DogInput>;
  status: 'pending' | 'done' | 'declined' | 'failed';
  /** Why it waits, or why it failed. */
  note?: string;
  /** Its name and job could hold outside text: set only on changes saved by older versions. */
  nameTainted?: boolean;
  jobTainted?: boolean;
}

export interface ChatMessage {
  id: string;
  at: number;
  from: 'you' | 'lead';
  text: string;
  actions?: LeadAction[];
  /** What the Lead dog noted in, or crossed out of, the pack's memory. */
  memory?: MemoryChange[];
  /** Tools the Lead dog used while answering. */
  used?: string[];
  /**
   * It could hold someone else's text: a reading-path answer (which may read
   * tool results, reports, jobs and remembered facts), or an older answer
   * that read any. The person's own messages and acting-path answers are
   * clean. Saved before this was recorded, a Lead dog message counts as
   * tainted. The acting path sees a tainted answer only as `answer-<n>`.
   */
  tainted?: boolean;
  failed?: boolean;
}

/** A tool call waiting on the user. */
export interface ToolApproval {
  id: string;
  at: number;
  dogId: string;
  tool: string;
  toolTitle: string;
  /** The arguments, redacted and cut short, as the user sees them. */
  args: string;
  why: 'mode' | 'always-ask' | 'rule' | 'judged-risky' | 'no-judge';
  /** The rule's or the judge's reason, when there is one. */
  reason?: string;
}

export const ToolDecision = z.enum(['allow-once', 'deny']);
export type ToolDecision = z.infer<typeof ToolDecision>;

export interface ToolView {
  key: string;
  /** "vigil" or the connector's id. */
  source: string;
  sourceName: string;
  name: string;
  title: string;
  description: string;
  /** Only Vigil's own tools. A connector's tools never count as read-only. */
  readOnly: boolean;
  /** The connector's server says the tool only reads: shown, never trusted. */
  serverHint: boolean;
  choice: ToolChoice;
}

/** https anywhere; plain http only to a server on this computer. */
export function isSafeConnectorUrl(url: string): boolean {
  try {
    const u = new URL(url);
    if (u.protocol === 'https:') return true;
    return u.protocol === 'http:' && ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
  } catch {
    return false;
  }
}

export const ConnectorInput = z.discriminatedUnion('kind', [
  z.object({
    kind: z.literal('stdio'),
    name: z.string().trim().min(1).max(40),
    command: z.string().trim().min(1).max(1024),
    args: z.array(z.string().max(1024)).max(32),
    /** Environment values (tokens) kept in the Keychain, never shown again. */
    env: z.record(z.string().regex(/^[A-Z_][A-Z0-9_]{0,63}$/), z.string().max(4096)).optional(),
  }),
  z.object({
    kind: z.literal('http'),
    name: z.string().trim().min(1).max(40),
    url: z
      .string()
      .url()
      .max(2048)
      .refine(isSafeConnectorUrl, 'Use https, or http only for a server on this computer'),
    /** A bearer token, kept in the Keychain. */
    token: z.string().max(4096).optional(),
  }),
]);
export type ConnectorInput = z.infer<typeof ConnectorInput>;

export interface ConnectorView {
  id: string;
  name: string;
  kind: 'stdio' | 'http';
  /** Command line or URL, for display. */
  target: string;
  /** Names of saved secrets (env names, or "token"); values never leave main. */
  secrets: string[];
  state: 'connected' | 'connecting' | 'error' | 'off';
  error?: string;
  tools: number;
  enabled: boolean;
}

export interface PackView {
  mode: PermissionMode;
  voice: PackVoice;
  dogs: (Dog & { mood: DogMood; activity?: string })[];
  chat: ChatMessage[];
  approvals: ToolApproval[];
  /** Whether a Claude plan may answer the Lead dog (Settings › AI opt-in). */
  leadMayUsePlan: boolean;
  /** Which AI judges risk in "auto" mode, or why none can. */
  judge: { ready: boolean; detail: string };
  /** No AI is set up, so nobody can talk yet. */
  noAi: boolean;
  tools: ToolView[];
  connectors: ConnectorView[];
  /** What each dog did since midnight, from the notebooks. */
  today: DiaryTally[];
  /** How many lasting facts the pack remembers. */
  remembered: number;
}

// ---------------------------------------------------------------- memory

/**
 * What a memory is about. The pack's memory is one short list, grouped by
 * these, like a MEMORY.md with a page per topic.
 */
export const MemoryTopic = z.enum(['you', 'mac', 'apps', 'network', 'agents', 'pack']);
export type MemoryTopic = z.infer<typeof MemoryTopic>;

export const MEMORY_TOPIC_LABEL: Record<MemoryTopic, string> = {
  you: 'About you',
  mac: 'This Mac',
  apps: 'Apps and tools',
  network: 'Network',
  agents: 'Coding agents',
  pack: 'How the pack works',
};

/** One line, short enough to read at a glance. */
export const MemoryFact = z
  .string()
  .transform((s) => s.replace(/\s+/g, ' ').trim())
  .pipe(z.string().min(3).max(200));

/**
 * One lasting fact the pack remembers, in one line, with where it came from
 * and when. Background for answers only: no memory makes anything safe,
 * allowed or a rule.
 */
export interface MemoryEntry {
  id: string;
  fact: string;
  topic: MemoryTopic;
  /** you: typed on the Memory sheet or kept from a "Remember this?" card. lead: the Lead dog noted it from your words. */
  from: 'you' | 'lead';
  /** The chat message it came from. */
  source?: string;
  added: number;
  /**
   * It could hold someone else's text: it came from an answer that read a
   * tool's output or a dog's report, even if the person then said yes to it.
   * Entries saved before this was recorded count as tainted.
   */
  tainted?: boolean;
}

/**
 * A change the Lead dog's acting path asked for in the pack's memory. The
 * acting path reads no outside text, so the change applies straight away,
 * except that it waits on a "Remember this?" or "Forget this?" card when the
 * turn also went down the reading path, leans on or cites a reference, the
 * fact replaces one the person's message doesn't name word for word, or it
 * forgets a fact that could hold outside text.
 */
export interface MemoryChange {
  id: string;
  op: 'remember' | 'forget';
  fact: string;
  topic: MemoryTopic;
  /** The entry it forgets, or the one it was saved as. */
  entryId?: string;
  /** The entry a remembered fact replaces. */
  replaces?: string;
  status: 'pending' | 'done' | 'declined' | 'failed';
  note?: string;
  /** The fact could hold outside text and stays tainted if kept. Cards saved before this was recorded count. */
  tainted?: boolean;
}

export const MemoryInput = z.object({ fact: MemoryFact, topic: MemoryTopic });
export type MemoryInput = z.infer<typeof MemoryInput>;

export interface DiaryTally {
  dog: string;
  kind: DogNoteKind;
  n: number;
  failed: number;
}

const DID: Record<DogNoteKind, (n: number) => string> = {
  explain: (n) => `explained ${count(n, 'alert')}`,
  label: (n) => `sniffed through new events ${times(n)}`,
  review: (n) => `reviewed the rules${n > 1 ? ` ${times(n)}` : ''}`,
  chat: (n) => `answered ${count(n, 'question')}`,
  job: (n) => `went on ${count(n, 'job')}`,
  judge: (n) => `checked ${count(n, 'tool call')}`,
};
const PLAIN: Record<DogNoteKind, (n: number) => string> = {
  explain: (n) => `explained ${count(n, 'alert')}`,
  label: (n) => `labelled new events ${times(n)}`,
  review: (n) => `reviewed the rules${n > 1 ? ` ${times(n)}` : ''}`,
  chat: (n) => `answered ${count(n, 'question')}`,
  job: (n) => `ran ${count(n, 'job')}`,
  judge: (n) => `checked ${count(n, 'tool call')}`,
};
const ORDER: DogNoteKind[] = ['chat', 'job', 'explain', 'label', 'review', 'judge'];

/**
 * The pack diary: one plain line per dog that did something today, Lead dog
 * first, in the order the pack is listed. Fixed wording from counts, never
 * written by an AI.
 */
export function diaryLines(
  dogs: readonly Pick<Dog, 'id' | 'name'>[],
  today: readonly DiaryTally[],
  voice: PackVoice = 'pack',
): { dog: string; text: string; failed: number }[] {
  const words = voice === 'plain' ? PLAIN : DID;
  return dogs.flatMap((d) => {
    const mine = today.filter((t) => t.dog === d.id && t.n > 0);
    if (mine.length === 0) return [];
    const failed = mine.reduce((n, t) => n + t.failed, 0);
    // Only finished runs count as done; the rest are the "didn't finish" count.
    const did = ORDER.flatMap((k) => {
      const t = mine.find((x) => x.kind === k);
      return t && t.n > t.failed ? [words[k](t.n - t.failed)] : [];
    });
    const text =
      did.length === 0
        ? `${d.name} tried ${times(failed)} but couldn’t finish`
        : `${d.name} ${did.length > 1 ? `${did.slice(0, -1).join(', ')} and ${did.at(-1)}` : did[0]}`;
    return [{ dog: d.id, text, failed: did.length === 0 ? 0 : failed }];
  });
}

function count(n: number, thing: string): string {
  return `${n} ${thing}${n === 1 ? '' : 's'}`;
}
function times(n: number): string {
  return n === 1 ? 'once' : n === 2 ? 'twice' : `${n} times`;
}

/** What kind of work a note records. */
export type DogNoteKind = 'explain' | 'label' | 'review' | 'chat' | 'job' | 'judge';

/**
 * One entry in a dog's notebook: an AI run in plain words. `reasons` are the
 * reasons the model gave in its own answer; `thinking` is a reasoning summary
 * only where a provider returns one through its official API. Never used by
 * any decision.
 */
export interface DogNote {
  id: string;
  at: number;
  /** A dog id: lead, explainer, labeller, rule-reviewer, or a pack dog's id. */
  dog: string;
  kind: DogNoteKind;
  ok: boolean;
  /** What it was asked, in plain words. */
  ask: string;
  /** What the note is about, to find it from that item. */
  subject?: { kind: 'alert' | 'event' | 'rule' | 'tool'; id: string };
  /** What it looked at: tools it used, records it was shown. */
  lookedAt: string[];
  answer: string;
  reasons: string[];
  /**
   * Set when part of the answer came from reading outside text (a report, a
   * connector's output). That part, and `readReasons`, may hold anyone's words,
   * so they are shown as what the dog read, not as its own reasoning.
   */
  fromOutside?: boolean;
  readReasons?: string[];
  thinking?: string;
  provider?: string;
  model?: string;
}

export type DogNoteInput = Omit<DogNote, 'id' | 'at' | 'lookedAt' | 'reasons' | 'readReasons'> & {
  lookedAt?: string[];

  reasons?: string[];
  readReasons?: string[];
};

export const NoteSubject = z.object({
  kind: z.enum(['alert', 'event', 'rule', 'tool']),
  id: z.string().min(1).max(160),
});

/** Which notes to read: one dog's, or every dog's about one thing. */
export const NotesFilter = z.object({
  dog: z
    .string()
    .regex(/^[a-z0-9-]{1,64}$/)
    .optional(),
  subject: NoteSubject.optional(),
  limit: z.number().int().min(1).max(200).optional(),
});
export type NotesFilter = z.infer<typeof NotesFilter>;

/** Piles this size or bigger get Scout's card on Home. */
export const SCOUT_PILE_MIN = 3;

/**
 * What the Lead dog says about the biggest pile in Needs you. Fixed wording
 * from the pile's own fields (the grouping is the alerts' own), never AI.
 */
export function pileWords(
  pile: { who: string; title: string; count: number },
  voice: PackVoice = 'pack',
): string {
  return voice === 'plain'
    ? `${pile.count} alerts from ${pile.who}: “${pile.title}”. They’re grouped so you can look at them and decide them together.`
    : `${pile.who} set off “${pile.title}” ${pile.count} times. I’ve stacked them into one pile, so you can look once and decide them all together.`;
}
