import type { BinaryName, RunResult, System } from '../system.js';

export interface FakeProcess {
  path: string;
  started: string;
}

/** Scripted stand-in for macOS: fake processes, pf, launchctl and plutil. */
export class FakeSystem implements System {
  readonly runs: { bin: BinaryName; args: string[]; input?: string | undefined }[] = [];
  readonly signals: { pid: number; signal: string }[] = [];
  readonly processes = new Map<number, FakeProcess>();
  readonly pfTable = new Set<string>();
  readonly loaded = new Set<string>();
  labels = new Map<string, string>();
  /** ProgramArguments[0] of a plist, by path. */
  programs = new Map<string, string>();
  /** The whole ProgramArguments of a plist, by path. */
  argv = new Map<string, string[]>();
  console: number | undefined = 501;

  async run(bin: BinaryName, args: string[], opts: { input?: string } = {}): Promise<RunResult> {
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
        const path = args.at(-1)!;
        const key = args[args.indexOf('-extract') + 1];
        if (key === 'ProgramArguments') {
          const argv = this.argv.get(path);
          return argv ? ok(JSON.stringify(argv)) : fail();
        }
        const value =
          key === 'Label'
            ? this.labels.get(path)
            : key === 'ProgramArguments.0'
              ? (this.programs.get(path) ?? this.argv.get(path)?.[0])
              : undefined;
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
}
