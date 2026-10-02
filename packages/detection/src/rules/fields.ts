import type { DetectionEvent } from '../types.js';

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
  'process.parentName': (e) => ('process' in e ? basename(e.process?.parentPath) : undefined),
  'process.commandLine': (e) => ('process' in e ? e.process?.args?.join(' ') : undefined),
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
  'ancestors',
  'downloadedAncestor',
  'downloadedAncestor.path',
  'downloadedAncestor.originUrl',
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
