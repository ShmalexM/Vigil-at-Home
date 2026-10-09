import { createHash } from 'node:crypto';
import { CPU_TYPE_ARM64, CPU_TYPE_X86_64 } from '../codeDirectory.js';

/** A CodeDirectory blob naming `identifier`, with hash type `hashType` (2 = SHA-256, 1 = SHA-1). */
function codeDirectory(identifier: string, seed: string, hashType: number): Buffer {
  const ident = Buffer.from(`${identifier}\0`, 'utf8');
  const filler = Buffer.from(seed, 'utf8');
  const head = Buffer.alloc(44);
  const length = head.length + ident.length + filler.length;
  head.writeUInt32BE(0xfade0c02, 0);
  head.writeUInt32BE(length, 4);
  head.writeUInt32BE(0x20400, 8); // version
  head.writeUInt32BE(0, 12); // flags
  head.writeUInt32BE(head.length + ident.length, 16); // hashOffset
  head.writeUInt32BE(head.length, 20); // identOffset
  head[36] = hashType === 1 ? 20 : 32; // hashSize
  head[37] = hashType;
  return Buffer.concat([head, ident, filler]);
}

const digestOf = (blob: Buffer, hashType: number) =>
  createHash(hashType === 1 ? 'sha1' : 'sha256')
    .update(blob)
    .digest('hex')
    .slice(0, 40);

/** A 64-bit Mach-O for `cpu` with an embedded signature holding the given CodeDirectories. */
function thin(cpu: number, cds: { slot: number; blob: Buffer }[]): Buffer {
  const index = Buffer.alloc(12 + cds.length * 8);
  index.writeUInt32BE(0xfade0cc0, 0);
  index.writeUInt32BE(cds.length, 8);
  let offset = index.length;
  cds.forEach(({ slot, blob }, i) => {
    index.writeUInt32BE(slot, 12 + i * 8);
    index.writeUInt32BE(offset, 16 + i * 8);
    offset += blob.length;
  });
  index.writeUInt32BE(offset, 4);
  const sig = Buffer.concat([index, ...cds.map((c) => c.blob)]);
  const header = Buffer.alloc(32 + 16);
  header.writeUInt32LE(0xfeedfacf, 0);
  header.writeInt32LE(cpu, 4);
  header.writeUInt32LE(2, 12); // MH_EXECUTE
  header.writeUInt32LE(1, 16); // ncmds
  header.writeUInt32LE(16, 20); // sizeofcmds
  header.writeUInt32LE(0x1d, 32); // LC_CODE_SIGNATURE
  header.writeUInt32LE(16, 36);
  header.writeUInt32LE(64, 40); // dataoff
  header.writeUInt32LE(sig.length, 44);
  return Buffer.concat([header, Buffer.alloc(16), sig]);
}

export interface FakeMachO {
  data: Buffer;
  /** What codesign and the kernel report for this program on an arm64 Mac. */
  cdhash: string;
  /** Its sha256. */
  sha256: string;
}

/**
 * A signed Mach-O program as the helper reads it: `identifier` in its
 * CodeDirectory, `seed` to make each one's CDHash its own. With `universal`,
 * an x86_64 and an arm64 slice (the arm64 one differs). With `sha1Too`, a
 * SHA-1 CodeDirectory in slot 0 and the SHA-256 one as an alternate, as
 * older signatures have.
 */
export function machO(
  identifier: string,
  seed: string,
  opts: { universal?: boolean; sha1Too?: boolean } = {},
): FakeMachO {
  const sha256Cd = codeDirectory(identifier, seed, 2);
  const cds = opts.sha1Too
    ? [
        { slot: 0, blob: codeDirectory(identifier, seed, 1) },
        { slot: 0x1000, blob: sha256Cd },
      ]
    : [{ slot: 0, blob: sha256Cd }];
  let data: Buffer;
  let cdhash = digestOf(sha256Cd, 2);
  if (opts.universal) {
    const armCd = codeDirectory(identifier, `${seed}-arm64`, 2);
    const x86 = thin(CPU_TYPE_X86_64, cds);
    const arm = thin(CPU_TYPE_ARM64, [{ slot: 0, blob: armCd }]);
    const fat = Buffer.alloc(8 + 2 * 20);
    fat.writeUInt32BE(0xcafebabe, 0);
    fat.writeUInt32BE(2, 4);
    const x86At = 4096;
    const armAt = x86At + Math.ceil(x86.length / 4096) * 4096;
    fat.writeInt32BE(CPU_TYPE_X86_64, 8);
    fat.writeUInt32BE(x86At, 16);
    fat.writeUInt32BE(x86.length, 20);
    fat.writeInt32BE(CPU_TYPE_ARM64, 28);
    fat.writeUInt32BE(armAt, 36);
    fat.writeUInt32BE(arm.length, 40);
    data = Buffer.alloc(armAt + arm.length);
    fat.copy(data, 0);
    x86.copy(data, x86At);
    arm.copy(data, armAt);
    cdhash = digestOf(armCd, 2);
  } else {
    data = thin(CPU_TYPE_ARM64, cds);
  }
  return { data, cdhash, sha256: createHash('sha256').update(data).digest('hex') };
}
