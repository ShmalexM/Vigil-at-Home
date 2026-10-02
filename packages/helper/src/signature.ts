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
      if (recent.length >= PER_MINUTE || !path.startsWith('/')) return undefined;
      recent.push(t);
      const r = await sys.run('codesign', ['-dv', path], { timeoutMs: 10_000 });
      return parseCodesign(`${r.stderr}\n${r.stdout}`);
    });
    chain = run.catch(() => undefined);
    return run;
  };
}
