// Which process is on the other end of a connection to the helper's socket,
// from the kernel's own socket tables, never from anything the client says.
//
// Node has no API for the peer credentials of a Unix socket (SO_PEERCRED on
// Linux, LOCAL_PEERPID on macOS), and the helper ships no native code, so it
// asks the tools that read the same kernel data as root:
//
//   Linux  `ss -x` lists every Unix socket with its inode and its peer's
//          inode (sock_diag, UNIX_DIAG_PEER). The helper finds its own end by
//          the inode of the connection's file descriptor (/proc/self/fd), and
//          the client as the one process holding the peer inode
//          (/proc/<pid>/fd).
//   macOS  `lsof -U` prints each Unix socket's kernel address and, for a
//          connected one, its peer's ("->0x…", from proc_pidfdinfo). The
//          client is the one process holding a socket whose peer is the
//          helper's end, or whose address is the helper's end's peer.
//
// Like the peer credentials, this names a process the kernel ties to the
// connection; unlike them it names who holds the client end now rather than
// who called connect(). Exactly one holder is required: a client end shared
// by several processes names none of them.

import type { System } from './system.js';

/** The pid on the other end of the helper's connection on file descriptor `fd`, if exactly one. */
export async function peerPid(
  sys: System,
  fd: number,
  socketPath: string,
  self: number = process.pid,
): Promise<number | undefined> {
  return sys.platform === 'linux' ? linuxPeer(sys, fd, socketPath, self) : macPeer(sys, fd, self);
}

const SOCKET = /^socket:\[(\d+)\]$/;

async function linuxPeer(
  sys: System,
  fd: number,
  socketPath: string,
  self: number,
): Promise<number | undefined> {
  if (!sys.procFds || !sys.procPids) return undefined;
  const own = SOCKET.exec(sys.procFds(self).find(([n]) => n === fd)?.[1] ?? '')?.[1];
  if (!own) return undefined;
  const ss = await sys.run('ss', ['-x', '-n'], { timeoutMs: 10_000 });
  if (ss.code !== 0) return undefined;
  const peer = ssPeerInode(ss.stdout, socketPath, own);
  if (!peer) return undefined;
  const holders = new Set<number>();
  for (const pid of sys.procPids()) {
    if (pid === self) continue;
    if (sys.procFds(pid).some(([, link]) => link === `socket:[${peer}]`)) holders.add(pid);
  }
  return holders.size === 1 ? [...holders][0] : undefined;
}

/**
 * The peer inode of the helper's socket with inode `own`, from `ss -x -n`.
 * A line reads `u_str ESTAB 0 0 <local path> <inode> <peer address> <peer inode>`;
 * the local path is the helper's own, so it is matched exactly, and the peer
 * inode is always the last field, whatever the peer's address holds.
 */
export function ssPeerInode(out: string, socketPath: string, own: string): string | undefined {
  for (const line of out.split('\n')) {
    const m = /^u_str\s+\S+\s+\d+\s+\d+\s+(.*)$/.exec(line.trim());
    if (!m || !m[1]!.startsWith(`${socketPath} `)) continue;
    const rest = m[1]!.slice(socketPath.length).trim().split(/\s+/);
    if (rest[0] !== own || rest.length < 3) continue;
    const peer = rest.at(-1)!;
    return /^\d+$/.test(peer) && peer !== '0' ? peer : undefined;
  }
  return undefined;
}

interface LsofSocket {
  pid: number;
  addr?: bigint;
  peer?: bigint;
}

/** `lsof -F pfdn` output for Unix sockets: each one's kernel address and peer address. */
export function parseLsofSockets(out: string): LsofSocket[] {
  const list: LsofSocket[] = [];
  let pid = 0;
  let cur: LsofSocket | undefined;
  const hex = (s: string) => (/^0x[0-9a-f]+$/i.test(s) ? BigInt(s) : undefined);
  for (const line of out.split('\n')) {
    const tag = line[0];
    const v = line.slice(1);
    if (tag === 'p') {
      pid = Number(v);
      cur = undefined;
    } else if (tag === 'f') {
      cur = { pid };
      list.push(cur);
    } else if (cur && tag === 'd') {
      const a = hex(v);
      if (a !== undefined) cur.addr = a;
    } else if (cur && tag === 'n' && v.startsWith('->')) {
      const a = hex(v.slice(2).split(/\s/)[0]!);
      if (a !== undefined) cur.peer = a;
    }
  }
  return list;
}

async function macPeer(sys: System, fd: number, self: number): Promise<number | undefined> {
  const mine = await sys.run(
    'lsof',
    ['-n', '-P', '-a', '-U', '-p', String(self), '-d', String(fd), '-F', 'pfdn'],
    { timeoutMs: 10_000 },
  );
  if (mine.code !== 0) return undefined;
  const end = parseLsofSockets(mine.stdout).find((s) => s.pid === self);
  if (end?.addr === undefined) return undefined;
  const all = await sys.run('lsof', ['-n', '-P', '-U', '-F', 'pfdn'], { timeoutMs: 15_000 });
  // lsof exits 1 when some process could not be read; what it printed still counts.
  if (!all.stdout) return undefined;
  const holders = new Set<number>();
  for (const s of parseLsofSockets(all.stdout)) {
    if (s.pid === self || !s.pid) continue;
    if (s.peer === end.addr || (end.peer !== undefined && s.addr === end.peer)) holders.add(s.pid);
  }
  return holders.size === 1 ? [...holders][0] : undefined;
}
