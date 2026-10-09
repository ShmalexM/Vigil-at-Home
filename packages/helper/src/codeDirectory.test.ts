import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';
import { CPU_TYPE_ARM64, CPU_TYPE_X86_64, readCodeIdentity } from './codeDirectory.js';
import { machO } from './testing/machO.js';

const reader = (data: Buffer) => (pos: number, len: number) => data.subarray(pos, pos + len);

describe('reading a CodeDirectory from Mach-O bytes', () => {
  it('reads the CDHash and identifier of a single-architecture program', () => {
    const m = machO('app.vigilathome.desktop', 'one');
    expect(readCodeIdentity(reader(m.data))).toEqual({
      cdhash: m.cdhash,
      identifier: 'app.vigilathome.desktop',
    });
    // Another build has another CDHash.
    expect(readCodeIdentity(reader(machO('app.vigilathome.desktop', 'two').data))?.cdhash).not.toBe(
      m.cdhash,
    );
  });

  it('takes the SHA-256 CodeDirectory over a SHA-1 one, as codesign does', () => {
    const m = machO('app.vigilathome.desktop', 'both', { sha1Too: true });
    expect(readCodeIdentity(reader(m.data))?.cdhash).toBe(m.cdhash);
  });

  it('reads the slice for the given CPU from a universal program', () => {
    const m = machO('app.vigilathome.desktop', 'fat', { universal: true });
    expect(readCodeIdentity(reader(m.data), CPU_TYPE_ARM64)?.cdhash).toBe(m.cdhash);
    const x86 = readCodeIdentity(reader(m.data), CPU_TYPE_X86_64);
    expect(x86?.identifier).toBe('app.vigilathome.desktop');
    expect(x86?.cdhash).not.toBe(m.cdhash);
  });

  it('finds nothing in bytes that are not signed Mach-O code', () => {
    const m = machO('app.vigilathome.desktop', 'cut');
    for (const data of [
      Buffer.alloc(0),
      Buffer.from('#!/bin/sh\necho hi\n'),
      Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
      m.data.subarray(0, m.data.length - 10),
    ])
      expect(readCodeIdentity(reader(data))).toBeUndefined();
    // The CDHash is the CodeDirectory's own hash, so any change to it shows.
    const changed = Buffer.from(m.data);
    changed.writeUInt8(changed.at(-1)! ^ 1, changed.length - 1);
    expect(readCodeIdentity(reader(changed))?.cdhash).not.toBe(m.cdhash);
    expect(createHash('sha256').update(m.data).digest('hex')).toBe(m.sha256);
  });
});
