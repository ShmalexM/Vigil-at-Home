import type { SensorEvent } from "../types.js";

export type FieldValue = string | number | boolean | string[] | undefined;

function basename(p: string | undefined): string | undefined {
  if (!p) return undefined;
  const i = p.lastIndexOf("/");
  return i === -1 ? p : p.slice(i + 1);
}

/**
 * Computed fields that rules can use as if they were on the event.
 * Keep this list small and documented: it is part of the rule language.
 */
const COMPUTED: Record<string, (e: SensorEvent) => FieldValue> = {
  "process.name": (e) => basename(e.process?.path),
  "process.parentName": (e) => basename(e.process?.parentPath),
  "process.commandLine": (e) => e.process?.args?.join(" "),
  "file.name": (e) => basename(e.file?.path),
  "persistence.programName": (e) => basename(e.persistence?.programPath),
  "persistence.commandLine": (e) =>
    e.persistence?.programArgs?.join(" ") ?? e.persistence?.programPath,
};

export const COMPUTED_FIELDS = Object.keys(COMPUTED);

/** Every path a rule may reference, for the linter. */
export const KNOWN_FIELDS = new Set<string>([
  "kind",
  "source",
  "process.pid",
  "process.ppid",
  "process.path",
  "process.args",
  "process.sha256",
  "process.cdhash",
  "process.user",
  "process.parentPath",
  "process.signing.status",
  "process.signing.teamId",
  "process.signing.signingId",
  "process.signing.notarized",
  "process.quarantine",
  "process.quarantine.originUrl",
  "process.quarantine.agent",
  "file.path",
  "file.targetPath",
  "network.remoteAddress",
  "network.remotePort",
  "network.localAddress",
  "network.localPort",
  "network.protocol",
  "network.domain",
  "persistence.type",
  "persistence.itemPath",
  "persistence.label",
  "persistence.programPath",
  "persistence.programArgs",
  "extension.browser",
  "extension.id",
  "extension.name",
  "extension.permissions",
  "santa.reason",
  "santa.ruleType",
  ...COMPUTED_FIELDS,
]);

export type FieldGetter = (e: SensorEvent) => FieldValue;

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
  const parts = path.split(".");
  return (e) => {
    let cur: unknown = e;
    for (const p of parts) {
      if (cur === null || typeof cur !== "object") return undefined;
      cur = (cur as Record<string, unknown>)[p];
    }
    if (cur === null || cur === undefined) return undefined;
    if (typeof cur === "string" || typeof cur === "number" || typeof cur === "boolean") return cur;
    if (Array.isArray(cur)) return cur.map(String);
    // Objects (e.g. process.quarantine) only answer "exists".
    return true;
  };
}

/** Stable string for a tuple of field values, used by baseline, dedupe and thresholds. */
export function keyOf(getters: FieldGetter[], e: SensorEvent): string | undefined {
  const parts: string[] = [];
  for (const g of getters) {
    const v = g(e);
    if (v === undefined) return undefined;
    parts.push(Array.isArray(v) ? v.join(" ") : String(v));
  }
  return parts.join("␟");
}
