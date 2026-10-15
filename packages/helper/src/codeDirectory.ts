// The CDHash and signing identifier of a Mach-O program, read from its own
// bytes: the code signature's CodeDirectory, as the kernel and codesign
// choose it. The helper reads these from a file it holds open, so the
// identity it pins is the identity of exactly the bytes it hashed, with no
// second lookup by path in between (appPin.ts).
//
// Layout (all from <mach-o/loader.h>, <mach-o/fat.h> and the Security
// framework's cs_blobs.h):
//   fat header (big-endian)   0xcafebabe / 0xcafebabf, then one entry per
//                             architecture: cputype, cpusubtype, offset, size
//   Mach-O header (little)    0xfeedfacf (64-bit) or 0xfeedface (32-bit),
//                             then load commands; LC_CODE_SIGNATURE (0x1d)
//                             gives the signature's offset and size
//   SuperBlob (big-endian)    0xfade0cc0, length, count, then (type, offset)
//   CodeDirectory             0xfade0c02, length, ..., identOffset at 20,
//                             hashType at 37; slot 0 and the alternates
//                             0x1000-0x1004 may each hold one
// The CDHash is the CodeDirectory blob hashed with its own hash type,
// truncated to 20 bytes; when there are several, the one with the strongest
// hash type counts (SHA-384, then SHA-256, then truncated SHA-256, then SHA-1),
// which is the one codesign prints and the kernel reports for a process.

import { createHash } from 'node:crypto';

export const CPU_TYPE_X86_64 = 0x01000007;
export const CPU_TYPE_ARM64 = 0x0100000c;

/** The CPU type this machine runs natively. */
export function hostCpuType(): number {
  return process.arch === 'arm64' ? CPU_TYPE_ARM64 : CPU_TYPE_X86_64;
}

export interface CodeIdentityRead {
  cdhash: string;
  identifier: string;
}

/** Reads `len` bytes at `pos`; may return fewer at the end of the file. */
export type ReadAt = (pos: number, len: number) => Buffer;

const LC_CODE_SIGNATURE = 0x1d;
const CSMAGIC_EMBEDDED_SIGNATURE = 0xfade0cc0;
const CSMAGIC_CODEDIRECTORY = 0xfade0c02;
/** Priority of each CodeDirectory hash type, strongest first, with its digest. */
const HASH_TYPES: [number, string][] = [
  [4, 'sha384'],
  [2, 'sha256'],
  [3, 'sha256'],
  [1, 'sha1'],
];
const MAX_BLOB = 64 * 1024 * 1024;

function exact(read: ReadAt, pos: number, len: number): Buffer | undefined {
  if (pos < 0 || len < 0 || !Number.isSafeInteger(pos + len)) return undefined;
  const b = read(pos, len);
  return b.length === len ? b : undefined;
}

/**
 * The CDHash and identifier of the Mach-O at the start of `read` (a single
 * architecture, or from a universal file the slice for `cpu`, else its
 * first). Undefined when the bytes are not signed Mach-O code.
 */
export function readCodeIdentity(read: ReadAt, cpu = hostCpuType()): CodeIdentityRead | undefined {
  const head = exact(read, 0, 8);
  if (!head) return undefined;
  const fat = head.readUInt32BE(0);
  if (fat === 0xcafebabe || fat === 0xcafebabf) {
    const n = head.readUInt32BE(4);
    if (n === 0 || n > 32) return undefined;
    const size = fat === 0xcafebabe ? 20 : 32;
    const table = exact(read, 8, n * size);
    if (!table) return undefined;
    const slices: { cpu: number; offset: number }[] = [];
    for (let i = 0; i < n; i++) {
      const at = i * size;
      const offset =
        fat === 0xcafebabe ? table.readUInt32BE(at + 8) : Number(table.readBigUInt64BE(at + 8));
      slices.push({ cpu: table.readInt32BE(at), offset });
    }
    const slice = slices.find((s) => s.cpu === cpu) ?? slices[0]!;
    return thin(read, slice.offset);
  }
  return thin(read, 0);
}

function thin(read: ReadAt, base: number): CodeIdentityRead | undefined {
  const header = exact(read, base, 32);
  if (!header) return undefined;
  const magic = header.readUInt32LE(0);
  if (magic !== 0xfeedfacf && magic !== 0xfeedface) return undefined;
  const ncmds = header.readUInt32LE(16);
  const sizeofcmds = header.readUInt32LE(20);
  if (ncmds > 4096 || sizeofcmds > 16 * 1024 * 1024) return undefined;
  const cmds = exact(read, base + (magic === 0xfeedfacf ? 32 : 28), sizeofcmds);
  if (!cmds) return undefined;
  let at = 0;
  for (let i = 0; i < ncmds && at + 8 <= cmds.length; i++) {
    const cmd = cmds.readUInt32LE(at);
    const cmdsize = cmds.readUInt32LE(at + 4);
    if (cmdsize < 8) return undefined;
    if (cmd === LC_CODE_SIGNATURE && at + 16 <= cmds.length) {
      const dataoff = cmds.readUInt32LE(at + 8);
      const datasize = cmds.readUInt32LE(at + 12);
      return signature(read, base + dataoff, datasize);
    }
    at += cmdsize;
  }
  return undefined;
}

function signature(read: ReadAt, at: number, size: number): CodeIdentityRead | undefined {
  if (size < 12 || size > MAX_BLOB) return undefined;
  const sb = exact(read, at, size);
  if (!sb || sb.readUInt32BE(0) !== CSMAGIC_EMBEDDED_SIGNATURE) return undefined;
  const count = sb.readUInt32BE(8);
  if (12 + count * 8 > sb.length) return undefined;
  let best: { rank: number; digest: string; blob: Buffer } | undefined;
  for (let i = 0; i < count; i++) {
    const type = sb.readUInt32BE(12 + i * 8);
    const offset = sb.readUInt32BE(16 + i * 8);
    if (type !== 0 && (type < 0x1000 || type > 0x1004)) continue;
    if (offset + 40 > sb.length || sb.readUInt32BE(offset) !== CSMAGIC_CODEDIRECTORY) continue;
    const length = sb.readUInt32BE(offset + 4);
    if (length < 40 || offset + length > sb.length) return undefined;
    const blob = sb.subarray(offset, offset + length);
    const rank = HASH_TYPES.findIndex(([t]) => t === blob[37]);
    if (rank < 0) continue;
    if (!best || rank < best.rank) best = { rank, digest: HASH_TYPES[rank]![1], blob };
  }
  if (!best) return undefined;
  const identOffset = best.blob.readUInt32BE(20);
  const end = best.blob.indexOf(0, identOffset);
  if (identOffset < 40 || end < 0) return undefined;
  const identifier = best.blob.subarray(identOffset, end).toString('utf8');
  const cdhash = createHash(best.digest).update(best.blob).digest('hex').slice(0, 40);
  return identifier ? { cdhash, identifier } : undefined;
}
