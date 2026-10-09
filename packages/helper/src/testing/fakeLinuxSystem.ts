import type { OpenedFile, OpenOptions } from '../openedFile.js';
import type { BinaryName, RunResult, System } from '../system.js';
import { FakeFs } from './fakeFs.js';
import type { FakeProcess } from './fakeSystem.js';

interface FakeRule {
  chain: string;
  handle: number;
  comment: string;
}

/** Scripted stand-in for Linux: /proc, nftables and systemctl. */
export class FakeLinuxSystem implements System {
  readonly platform = 'linux' as const;
  readonly runs: { bin: BinaryName; args: string[]; input?: string | Buffer | undefined }[] = [];
  readonly signals: { pid: number; signal: string }[] = [];
  readonly processes = new Map<number, FakeProcess>();
  readonly rules: FakeRule[] = [];
  /** Units that are running, as "<scope> <unit>" with scope "system" or "user:<name>". */
  readonly active = new Set<string>();
  tableExists = false;
  fagenrulesFails = false;
  private nextHandle = 2;
  console: number | undefined = 1000;

  async run(
    bin: BinaryName,
    args: string[],
    opts: { input?: string | Buffer } = {},
  ): Promise<RunResult> {
    // ACL reads (commands/transfer.ts) are answered without being logged: no ACLs here.
    if (bin === 'ls')
      return { code: 0, stdout: `d--------- 1 root wheel 0 ${args.at(-1)}\n`, stderr: '' };
    this.runs.push({ bin, args, input: opts.input });
    if (bin === 'nft' && args.length === 1) return this.nftScript(args[0]!);
    const ok = (stdout = ''): RunResult => ({ code: 0, stdout, stderr: '' });
    const fail = (stderr = 'error'): RunResult => ({ code: 1, stdout: '', stderr });
    switch (bin) {
      case 'ps': {
        const p = this.processes.get(Number(args.at(-1)));
        return p ? ok(p.started + '\n') : fail();
      }
      case 'nft':
        return this.nft(args);
      case 'fagenrules':
        return this.fagenrulesFails ? fail('rule error') : ok();
      case 'systemctl': {
        const user = args[0] === '--user' ? `user:${args[2]!.replace(/@$/, '')}` : 'system';
        const rest = args[0] === '--user' ? args.slice(3) : args;
        const unit = rest.at(-1)!;
        switch (rest[0]) {
          case 'is-active':
            return this.active.has(`${user} ${unit}`) ? ok() : fail('inactive');
          case 'stop':
            this.active.delete(`${user} ${unit}`);
            return ok();
          case 'start':
            this.active.add(`${user} ${unit}`);
            return ok();
          case 'daemon-reload':
          case 'restart':
          case 'try-restart':
            return ok();
          case 'enable':
          case 'disable':
            if (rest[1] === '--now') {
              if (rest[0] === 'enable') this.active.add(`${user} ${unit}`);
              else this.active.delete(`${user} ${unit}`);
            }
            return ok();
        }
        return fail();
      }
      default:
        return fail(`unexpected ${bin}`);
    }
  }

  private nft(args: string[]): RunResult {
    const ok = (stdout = ''): RunResult => ({ code: 0, stdout, stderr: '' });
    if (args[0] === 'list')
      return this.tableExists ? ok() : { code: 1, stdout: '', stderr: 'No such file or directory' };
    if (args[0] === 'delete') {
      this.tableExists = false;
      this.rules.length = 0;
      return ok();
    }
    if (args[0] === '-j') {
      if (!this.tableExists) return { code: 1, stdout: '', stderr: 'no table' };
      const items = this.rules.map((r) => ({
        rule: {
          family: 'inet',
          table: 'vigil',
          chain: r.chain,
          handle: r.handle,
          comment: r.comment,
        },
      }));
      return ok(JSON.stringify({ nftables: [{ metainfo: {} }, ...items] }));
    }
    return { code: 1, stdout: '', stderr: `unexpected nft ${args.join(' ')}` };
  }

  /** One argument: a script of commands joined by "; ". */
  private nftScript(script: string): RunResult {
    const ok = (stdout = ''): RunResult => ({ code: 0, stdout, stderr: '' });
    if (script.startsWith('table inet vigil')) {
      this.tableExists = true;
      return ok();
    }
    for (const line of script.split('; ')) {
      let m = /^add rule inet vigil (\w+) .* comment "([^"]+)"$/.exec(line);
      if (m) this.rules.push({ chain: m[1]!, handle: this.nextHandle++, comment: m[2]! });
      m = /^delete rule inet vigil (\w+) handle (\d+)$/.exec(line);
      if (m) {
        const i = this.rules.findIndex((r) => r.handle === Number(m![2]));
        if (i >= 0) this.rules.splice(i, 1);
      }
    }
    return ok();
  }

  procExe(pid: number): string | undefined {
    return this.processes.get(pid)?.path;
  }

  /** /proc/self/mountinfo. */
  mounts = '';
  /** Paths, file contents and links (fakeFs.ts). */
  readonly fs = new FakeFs();
  /** Files by path, with their `fileId` (device:inode). */
  readonly files = this.fs.paths;
  /** Contents and metadata by file id; a file not listed has ctime "1" and size 1. */
  readonly inodes = this.fs.inodes;
  /** Open files by pid, as `[fd, link]`. */
  readonly fds = new Map<number, [number, string][]>();
  /** Start times by pid, in clock ticks. */
  readonly starts = new Map<number, number>();

  mountInfo(): string {
    return this.mounts;
  }

  procPids(): number[] {
    return [...this.processes.keys()];
  }

  procFds(pid: number): [number, string][] {
    return this.fds.get(pid) ?? [];
  }

  procStart(pid: number): number | undefined {
    return this.starts.get(pid);
  }

  /** What a /proc/<pid>/exe or /proc/<pid>/fd/<n> link points at; other paths as they are. */
  private procTarget(path: string): string | undefined {
    const m = /^\/proc\/(\d+)\/(exe|fd\/(\d+))$/.exec(path);
    if (!m) return path;
    const pid = Number(m[1]);
    return m[3]
      ? this.procFds(pid).find(([n]) => n === Number(m[3]))?.[1]
      : this.processes.get(pid)?.path;
  }

  fileId(path: string): string | undefined {
    const target = this.procTarget(path);
    return target === undefined ? undefined : this.files.get(target);
  }

  openFile(path: string, opts?: OpenOptions): OpenedFile | undefined {
    const target = this.procTarget(path);
    // /proc links are always followed, as the kernel does.
    return target === undefined ? undefined : this.fs.open(target, target === path ? opts : {});
  }

  signal(pid: number, signal: 'SIGSTOP' | 'SIGCONT' | 'SIGKILL'): void {
    this.signals.push({ pid, signal });
    if (signal === 'SIGKILL') this.processes.delete(pid);
  }

  consoleUid(): number | undefined {
    return this.console;
  }

  now(): number {
    return Date.now();
  }
}
