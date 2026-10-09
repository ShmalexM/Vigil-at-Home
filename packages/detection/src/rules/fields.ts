import type { DetectionEvent } from '../types.js';
import { runsQuietLine } from './quiet-lines.js';

export type FieldValue = string | number | boolean | string[] | undefined;
export type FieldGetter = (e: DetectionEvent) => FieldValue;

function basename(p: unknown): string | undefined {
  if (typeof p !== 'string' || p === '') return undefined;
  const i = p.lastIndexOf('/');
  return i === -1 ? p : p.slice(i + 1);
}

function read(e: DetectionEvent, key: string): unknown {
  return (e as unknown as Record<string, unknown>)[key];
}

/**
 * Computed fields rules can use as if they were on the event. They are part
 * of the rule language, so keep this list short and documented.
 */
const COMPUTED: Record<string, FieldGetter> = {
  'process.name': (e) => ('process' in e ? basename(e.process?.path) : undefined),
  /** The parent's name from its path, else the nearest ancestor Vigil knows (see process.ancestors). */
  'process.parentName': (e) =>
    'process' in e ? (basename(e.process?.parentPath) ?? e.process?.ancestors?.[0]) : undefined,
  'process.commandLine': (e) => ('process' in e ? e.process?.args?.join(' ') : undefined),
  /**
   * A shell running exactly one of Claude Code's real local-service reads
   * (see rules/quiet-lines.ts). The download-run rule stays quiet on these.
   */
  'process.quietDownloadLine': (e) =>
    'process' in e ? runsQuietLine(e.process?.path, e.process?.args, e.process?.user) : undefined,
  /**
   * The download a process comes from: the nearest downloaded ancestor, or the
   * process itself when it carries the quarantine flag. Chain rules key on it.
   */
  'process.downloadRoot': (e) => {
    const p = 'process' in e ? e.process : undefined;
    return p?.downloadedAncestor?.path ?? (p?.quarantine ? p.path : undefined);
  },
  /** The signature of that download (see process.downloadRoot). */
  'process.downloadRootSigning': (e) => {
    const p = 'process' in e ? e.process : undefined;
    if (p?.downloadedAncestor) return p.downloadedAncestor.signing;
    return p?.quarantine ? p.signing : undefined;
  },
  /** Last component of the event's `path` (file, persistence item, Santa-protected file). */
  pathName: (e) => basename(read(e, 'path')),
  /** Last component of a persistence item's program. */
  programName: (e) => basename(read(e, 'program')),
  /** A persistence item's full command line, falling back to its program. */
  programCommandLine: (e) => {
    const args = read(e, 'programArgs');
    if (Array.isArray(args) && args.length > 0) return args.join(' ');
    const program = read(e, 'program');
    return typeof program === 'string' ? program : undefined;
  },
  /**
   * Agent tool requests: the file is outside the folder the agent works in.
   * The hook has already resolved `..`, so a prefix test is enough.
   */
  toolOutsideCwd: (e) => {
    const file = read(e, 'filePath');
    const cwd = read(e, 'cwd');
    if (typeof file !== 'string' || typeof cwd !== 'string' || file === '' || cwd === '')
      return undefined;
    const root = cwd.endsWith('/') ? cwd : `${cwd}/`;
    return file !== cwd && !file.startsWith(root);
  },
};

export const COMPUTED_FIELDS = Object.keys(COMPUTED);

const PROCESS_FIELDS = [
  'pid',
  'startTime',
  'ppid',
  'path',
  'args',
  'cwd',
  'uid',
  'user',
  'sha256',
  'cdhash',
  'signingId',
  'teamId',
  'signing',
  'parentPath',
  'quarantine',
  'quarantine.originUrl',
  'quarantine.agent',
  'downloadedAncestor',
  'downloadedAncestor.path',
  'downloadedAncestor.originUrl',
  'downloadedAncestor.signing',
  // Filled by Vigil: the helper's sensor hub and the app's process tracker.
  'ancestors',
  // Filled by the app's process tracker only, never in the helper.
  'agent',
  'agent.id',
  'agent.session',
  'agent.depth',
  // The agent root's signature, while the parent has it too (see AgentTag).
  'agent.teamId',
  'agent.signingId',
].map((f) => `process.${f}`);

/** Every path a rule may reference, for the linter and the AI's rule guide. */
export const KNOWN_FIELDS = new Set<string>([
  'kind',
  'source',
  ...PROCESS_FIELDS,
  // process.exit
  'exitCode',
  // file
  'op',
  'path',
  'newPath',
  'sha256',
  // network.connection, network.listen
  'direction',
  'protocol',
  'localAddress',
  'localPort',
  'remoteAddress',
  'remotePort',
  'remoteHost',
  // persistence
  'change',
  'mechanism',
  'label',
  'program',
  'programArgs',
  // santa.decision
  'target',
  'decision',
  'reason',
  // browser.extension
  'browser',
  'extensionId',
  'name',
  'permissions',
  // system.alert (details.* fields are subtype-specific)
  'subtype',
  'details.malware', // xprotect_detected
  'details.service', // tcc_modified
  'details.identity',
  'details.eventType',
  'details.authRight',
  'details.authReason',
  // agent.tool_request
  'tool',
  'command',
  'commandBytes',
  'commandClipped',
  'filePath',
  'url',
  'mcpServer',
  'cwd',
  'contentBytes',
  'contentSha256',
  'agent',
  'agent.host',
  'agent.id',
  'agent.session',
  'agent.hookSession',
  ...COMPUTED_FIELDS,
]);

const cache = new Map<string, FieldGetter>();

/** Compile a dotted path to a getter once, so evaluation does no string work. */
export function compileField(path: string): FieldGetter {
  let g = cache.get(path);
  if (!g) {
    g = buildGetter(path);
    if (cache.size < 10_000) cache.set(path, g);
  }
  return g;
}

function buildGetter(path: string): FieldGetter {
  const computed = COMPUTED[path];
  if (computed) return computed;
  const parts = path.split('.');
  return (e) => {
    let cur: unknown = e;
    for (const p of parts) {
      if (cur === null || typeof cur !== 'object') return undefined;
      cur = (cur as Record<string, unknown>)[p];
    }
    if (cur === null || cur === undefined) return undefined;
    if (typeof cur === 'string' || typeof cur === 'number' || typeof cur === 'boolean') return cur;
    if (Array.isArray(cur)) return cur.map(String);
    // Objects (e.g. process.quarantine) only answer "exists".
    return true;
  };
}

/** Stable string for a tuple of field values, used by baseline, dedupe and thresholds. */
export function keyOf(getters: FieldGetter[], e: DetectionEvent): string | undefined {
  const parts: string[] = [];
  for (const g of getters) {
    const v = g(e);
    if (v === undefined) return undefined;
    parts.push(Array.isArray(v) ? v.join(' ') : String(v));
  }
  return parts.join('␟');
}
