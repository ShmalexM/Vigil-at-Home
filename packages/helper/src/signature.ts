// Reads a program's code signature with codesign, for programs that started
// before Vigil and so never had their launch (and signature) logged by Santa.
// Rules treat unsigned and ad hoc programs as untrusted; without this, such a
// program's file reads and connections carry no signature at all.
//
// Lookups run one at a time and at most 60 a minute, so a burst of unknown
// programs right after the helper starts can't load the Mac.

import type { SignatureInfo } from '@vigil/sensors';
import type { System } from './system.js';

const PER_MINUTE = 60;

/** Parses `codesign -dv` output (it writes to stderr). */
export function parseCodesign(output: string): SignatureInfo | undefined {
  if (/code object is not signed at all/.test(output)) return { signing: 'unsigned' };
  // A planted line (a name holding a line break) repeats a real one: trust nothing.
  for (const key of [
    /^Identifier=/gm,
    /^TeamIdentifier=/gm,
    /^Platform identifier=/gm,
    /^Signature=/gm,
  ])
    if ((output.match(key)?.length ?? 0) > 1) return undefined;
  const identifier = /^Identifier=(.+)$/m.exec(output)?.[1]?.trim();
  if (!identifier) return undefined;
  const team = /^TeamIdentifier=([A-Z0-9]{10})$/m.exec(output)?.[1];
  if (/^Platform identifier=\d+/m.test(output))
    return { signing: 'apple', signingId: `platform:${identifier}` };
  if (/^Signature=adhoc$/m.test(output)) return { signing: 'adhoc' };
  const authority = /^Authority=(.+)$/m.exec(output)?.[1] ?? '';
  const signingId = team ? `${team}:${identifier}` : undefined;
  const base = { ...(team ? { teamId: team } : {}), ...(signingId ? { signingId } : {}) };
  if (authority.startsWith('Developer ID Application')) return { signing: 'developer_id', ...base };
  if (authority === 'Apple Mac OS Application Signing') return { signing: 'app_store', ...base };
  return { signing: 'unknown', ...base };
}

/** Line breaks other than LF: `^…$/m` treats them as line ends, so they could plant lines. */
const ODD_BREAKS = /[\r\u2028\u2029]/;
/** Characters a signing identifier may have before it goes into a requirement. */
const SAFE_IDENTIFIER = /^[A-Za-z0-9._-]{1,255}$/;
const DEVELOPER_ID =
  'certificate 1[field.1.2.840.113635.100.6.2.6] exists and certificate leaf[field.1.2.840.113635.100.6.1.13] exists';
const APP_STORE = 'certificate leaf[field.1.2.840.113635.100.6.1.9] exists';

/**
 * The requirement a signature class must pass with `codesign --verify`
 * before it counts: what `codesign -dv` prints is display text, so it never
 * grants a class by itself. Undefined when there is nothing to check
 * (unsigned, ad hoc, no team) and null when it can't be written safely.
 */
function requirementFor(info: SignatureInfo, identifier: string): string | undefined | null {
  if (info.signing === 'unsigned' || info.signing === 'adhoc') return undefined;
  if (info.signing !== 'apple' && !info.teamId)
    return info.signing === 'unknown' ? undefined : null;
  if (!SAFE_IDENTIFIER.test(identifier)) return null;
  const id = `identifier "${identifier}"`;
  if (info.signing === 'apple') return `anchor apple and ${id}`;
  const team = `certificate leaf[subject.OU] = "${info.teamId}"`;
  if (info.signing === 'developer_id')
    return `anchor apple generic and ${id} and ${DEVELOPER_ID} and ${team}`;
  if (info.signing === 'app_store')
    return `anchor apple generic and ${id} and ${APP_STORE} and ${team}`;
  return `anchor apple generic and ${id} and ${team}`;
}

export function signatureLookup(
  sys: System,
  now: () => number = Date.now,
): (path: string) => Promise<SignatureInfo | undefined> {
  const recent: number[] = [];
  let chain: Promise<unknown> = Promise.resolve();
  return (path) => {
    const run = chain.then(async () => {
      const t = now();
      while (recent.length > 0 && t - recent[0]! >= 60_000) recent.shift();
      // codesign echoes the path in its output, so a path with a line break
      // could plant lines (Platform identifier=, Authority=) ahead of the real ones.
      if (recent.length >= PER_MINUTE || !path.startsWith('/') || /[\n\r\u2028\u2029]/.test(path))
        return undefined;
      recent.push(t);
      const r = await sys.run('codesign', ['-dv', path], { timeoutMs: 10_000 });
      const output = `${r.stderr}\n${r.stdout}`;
      if (ODD_BREAKS.test(output)) return undefined;
      if (r.code !== 0) {
        // codesign exits 1 for an unsigned program; anything else is a failure.
        const unsigned = r.stderr.trim() === `${path}: code object is not signed at all`;
        return unsigned ? { signing: 'unsigned' as const } : undefined;
      }
      const info = parseCodesign(output);
      if (!info || info.signing === 'unsigned') return undefined;
      const identifier = /^Identifier=(.+)$/m.exec(output)?.[1]?.trim() ?? '';
      const req = requirementFor(info, identifier);
      if (req === null) return undefined;
      if (req !== undefined) {
        const v = await sys.run('codesign', ['--verify', `-R=${req}`, path], { timeoutMs: 10_000 });
        if (v.code !== 0) return undefined;
      }
      return info;
    });
    chain = run.catch(() => undefined);
    return run;
  };
}
