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
  console: number | undefined = 501;

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
        // From stdin ("-"): the label of the file whose bytes these are.
        if (args.at(-1) === '-') {
          const input = Buffer.from(opts.input ?? '');
          for (const [path, l] of this.labels) {
            try {
              if (readFileSync(path).equals(input)) return ok(l + '\n');
            } catch {
              // Not a file here.
            }
          }
          return fail();
        }
        const label = this.labels.get(args.at(-1)!);
        return label ? ok(label + '\n') : fail();
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
