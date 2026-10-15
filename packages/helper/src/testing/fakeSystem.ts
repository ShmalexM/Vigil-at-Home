import { readFileSync } from 'node:fs';
import type { OpenedFile, OpenOptions } from '../openedFile.js';
import type { BinaryName, RunResult, System } from '../system.js';
import { FakeFs } from './fakeFs.js';

export interface FakeProcess {
  path: string;
  started: string;
}

/** Scripted stand-in for macOS: fake processes, pf, launchctl and plutil. */
export class FakeSystem implements System {
  readonly runs: { bin: BinaryName; args: string[]; input?: string | Buffer | undefined }[] = [];
  readonly signals: { pid: number; signal: string }[] = [];
  readonly processes = new Map<number, FakeProcess>();
  readonly pfTable = new Set<string>();
  readonly loaded = new Set<string>();
  labels = new Map<string, string>();
  /** ProgramArguments[0] of a plist, by path. */
  programs = new Map<string, string>();
  console: number | undefined = 501;
  /**
   * The helper's pid in this fake. Fixed, so the fake pids tests use never
   * collide with the test runner's real pid.
   */
  pid = 999_999;

  selfPid(): number {
    return this.pid;
  }

  async run(
    bin: BinaryName,
    args: string[],
    opts: { input?: string | Buffer } = {},
  ): Promise<RunResult> {
    // ACL reads (commands/transfer.ts) are answered without being logged: no ACLs here.
    if (bin === 'ls')
      return { code: 0, stdout: `d--------- 1 root wheel 0 ${args.at(-1)}\n`, stderr: '' };
    this.runs.push({ bin, args, input: opts.input });
    const ok = (stdout = '', stderr = ''): RunResult => ({ code: 0, stdout, stderr });
    const fail = (stderr = 'error'): RunResult => ({ code: 1, stdout: '', stderr });
    switch (bin) {
      case 'ps': {
        const p = this.processes.get(Number(args.at(-1)));
        return p ? ok(p.started + '\n') : fail();
      }
      case 'lsof': {
        const pid = Number(args[args.indexOf('-p') + 1]);
        const p = this.processes.get(pid);
        return p ? ok(`p${pid}\nftxt\nn${p.path}\nftxt\nn/usr/lib/dyld\n`) : fail();
      }
      case 'pfctl': {
        if (args[0] === '-E') return ok('', 'pf enabled\nToken : 1234567890\n');
        const t = args.indexOf('-T');
        if (t >= 0) {
          const verb = args[t + 1];
          const addr = args[t + 2]!;
          if (verb === 'add') this.pfTable.add(addr);
          if (verb === 'delete') this.pfTable.delete(addr);
          if (verb === 'show') return ok([...this.pfTable].map((a) => `   ${a}`).join('\n'));
        }
        return ok();
      }
      case 'plutil': {
        let path = args.at(-1)!;
        // From stdin ("-"): the file whose bytes these are.
        if (path === '-') {
          const input = Buffer.from(opts.input ?? '');
          const match = [...new Set([...this.labels.keys(), ...this.programs.keys()])].find((p) => {
            try {
              return readFileSync(p).equals(input);
            } catch {
              return false; // Not a file here.
            }
          });
          if (!match) return fail();
          path = match;
        }
        const key = args[args.indexOf('-extract') + 1];
        // Programs for the launch item keys; `labels` answers any other key.
        const value =
          key === 'ProgramArguments.0'
            ? this.programs.get(path)
            : key === 'Program'
              ? undefined
              : this.labels.get(path);
        return value ? ok(value + '\n') : fail();
      }
      case 'launchctl': {
        const [verb, target, path] = args;
        if (verb === 'print') return this.loaded.has(target!) ? ok() : fail('not found');
        if (verb === 'bootout') return this.loaded.delete(target!) ? ok() : fail();
        if (verb === 'bootstrap') {
          this.loaded.add(`${target}/${this.labels.get(path!)}`);
          return ok();
        }
        return fail();
      }
      case 'santactl':
        return ok('Sync completed');
      default:
        return fail(`unexpected ${bin}`);
    }
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

  /** Paths, file contents and links (fakeFs.ts). */
  readonly fs = new FakeFs();

  openFile(path: string, opts?: OpenOptions): OpenedFile | undefined {
    return this.fs.open(path, opts);
  }
}
