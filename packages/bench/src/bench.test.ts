import { SensorEvent } from '@vigil/core';
import { describe, expect, it } from 'vitest';
import { ATTACKS } from './attacks.js';
import { HELDOUT_ATTACKS, HELDOUT_LOOKALIKES } from './heldout.js';
import {
  AGENT_RULE_IDS,
  runAttacks,
  runWorkload,
  START,
  type WorkloadResult,
} from './detection.js';
import { runPreflight, summarizePreflight, type PreflightRun } from './preflight.js';
import { rng } from './rng.js';
import { santaWatchItems, throughSensors } from './sensors.js';
import { workday } from './workday.js';

// Quick checks on the benchmark itself, so it can't rot between bench runs.
// The full benchmark is src/detection.run.ts (pnpm --filter @vigil/bench bench).
describe('benchmark corpus', () => {
  it('only contains valid sensor events', () => {
    for (const s of ATTACKS)
      for (const e of s.events(START)) expect(() => SensorEvent.parse(e), s.id).not.toThrow();
  });

  it('keeps the held-out set valid and apart from the train set', () => {
    const train = new Set(ATTACKS.map((s) => s.id));
    for (const s of HELDOUT_ATTACKS) {
      expect(train.has(s.id), s.id).toBe(false);
      expect(s.variant, s.id).toBe('heldout');
      for (const e of s.events(START)) expect(() => SensorEvent.parse(e), s.id).not.toThrow();
    }
    for (const l of HELDOUT_LOOKALIKES)
      for (const e of l.events(START)) expect(() => SensorEvent.parse(e), l.id).not.toThrow();
    expect(ATTACKS.some((s) => s.variant === 'heldout')).toBe(false);
  });

  it('reads the watch items from the Santa policy Vigil ships', () => {
    expect(santaWatchItems().map((w) => w.name)).toContain('ChromeCookies');
  });

  it('renders events through the real sensor parsers', () => {
    const exec = ATTACKS.find((s) => s.id === 'clickfix-curl-pipe')!.events(START)[0]!;
    const [seen] = throughSensors(exec);
    expect(seen?.kind).toBe('process.exec');
    // The pipe survives Santa's <pipe> escaping.
    expect(seen && 'process' in seen && seen.process?.args?.join(' ')).toContain('| bash');
  });

  it('catches every canonical attack when the telemetry has what the rules need', () => {
    const missed = runAttacks()
      .filter((r) => r.telemetry === 'ideal' && r.variant === 'canonical' && !r.caught)
      .map((r) => r.id);
    expect(missed).toEqual([]);
  });

  it('never blocks anything in a normal everyday week', () => {
    const w = runWorkload('everyday', 'sensors', { days: 8 });
    expect(w.perDay.blocks).toBe(0);
  }, 30_000);
});

describe('AI agents', () => {
  const scenarios = ATTACKS.filter((s) => s.expect.some((id) => AGENT_RULE_IDS.has(id)));

  it('has the canonical agent scenarios, each in its own range of pids', () => {
    expect(scenarios.map((s) => s.id).sort()).toEqual(
      [
        'agent-aws-paste-exfil',
        'agent-paste-upload',
        'agent-launchagent-curl',
        'mcp-server-ssh-key-read',
        'agent-guard-tamper',
        'agent-keychain-password',
      ].sort(),
    );
    // The sensor parsers remember pids across scenarios, so none may share one.
    const owner = new Map<number, string>();
    for (const s of scenarios) {
      expect(s.variant, s.id).toBe('canonical');
      for (const e of s.events(START)) {
        const p = 'process' in e ? e.process : undefined;
        for (const pid of p ? [p.pid, p.ppid ?? p.pid] : []) {
          expect(pid, s.id).toBeGreaterThanOrEqual(60_000);
          expect(owner.get(pid) ?? s.id, `pid ${pid}`).toBe(s.id);
          owner.set(pid, s.id);
        }
      }
    }
  });

  it('catches every canonical agent scenario with the rule it aims at', () => {
    for (const r of runAttacks({}, undefined, scenarios).filter((x) => x.telemetry === 'ideal'))
      expect(r.caughtBy, r.id).toEqual(expect.arrayContaining(r.expect));
  });

  let preflight: PreflightRun | undefined;
  const answers = () => (preflight ??= runPreflight({}, 1));

  it('never refuses a pre-flight look-alike', () => {
    const denied = answers().results.filter((r) => r.kind === 'lookalike' && r.decision === 'deny');
    expect(denied.map((r) => r.id)).toEqual([]);
  });

  it('asks about or refuses every pre-flight attack', () => {
    const { results } = answers();
    expect(results.filter((r) => r.kind === 'attack').length).toBeGreaterThanOrEqual(20);
    expect(results.filter((r) => r.kind === 'lookalike').length).toBeGreaterThanOrEqual(20);
    const missed = results.filter((r) => r.kind === 'attack' && r.decision === 'none');
    expect(missed.map((r) => r.id)).toEqual([]);
  });

  it('refuses exactly the pre-flight steps meant to be refused', () => {
    const run = answers();
    const ids = (f: (r: PreflightRun['results'][number]) => boolean) =>
      run.results
        .filter((r) => r.kind !== 'gap' && f(r))
        .map((r) => r.id)
        .sort();
    expect(ids((r) => r.decision === 'deny')).toEqual(ids((r) => r.expect === 'deny'));
    expect(summarizePreflight(run).deniesExact).toBe(true);
  });

  // Two measured weeks of a developer's Mac, Claude Code sessions included.
  let developer: WorkloadResult | undefined;
  const week = () => (developer ??= runWorkload('developer', 'ideal', { days: 14 }));

  it('keeps agent rules under half an alert a day for a developer', () => {
    const w = week();
    expect(w.rates['agentSession']).toBeGreaterThan(0);
    expect(w.agentRules.alerts + w.agentRules.asks).toBeLessThanOrEqual(0.5);
    expect(w.perDay.denies).toBe(0);
  }, 60_000);

  it('puts look-alike agent commands in that measured week, so the check above can fail', () => {
    // Agent sessions draw from their own stream, seeded by the day, so these
    // are the tool calls runWorkload sees whatever stream the rest uses.
    const DAY = 86_400_000;
    const r = rng(1);
    const calls = { all: 0, lookalike: 0 };
    for (let day = 7; day < 14; day++)
      for (const w of workday('developer', START + day * DAY, r)) {
        if (w.event.kind !== 'agent.tool_request') continue;
        calls.all++;
        if (w.lookalike) calls.lookalike++;
      }
    expect(calls.all / 7).toBeGreaterThanOrEqual(100);
    expect(calls.lookalike / 7).toBeGreaterThanOrEqual(3);
  });

  it('stores at most 40 bytes more per event to follow agents', () => {
    const { storedBytesPerEvent: b } = week();
    expect(b.withAgents).toBeGreaterThan(b.plain);
    expect(b.delta).toBeLessThanOrEqual(40);
  }, 60_000);
});

describe('rule scoring', () => {
  it('credits a candidate rule with the attacks only it catches', async () => {
    const { scoreCandidates } = await import('./detection.js');
    const [score] = scoreCandidates(
      [
        {
          id: 'candidate-curl-then-run',
          version: 1,
          origin: 'user',
          name: 'Downloaded to a file, then run',
          description: 'curl or wget saving a file, then a shell running it on the same line.',
          mode: 'shadow',
          severity: 'medium',
          fidelity: 'medium',
          eventKinds: ['process.exec'],
          condition: {
            field: 'process.commandLine',
            op: 'regex',
            value: ['(curl|wget)\\s[^|&;]{0,200}(&&|;)\\s*(sudo\\s+)?(/\\S+/)?(ba|z|da)?sh\\s+/'],
          },
          response: [],
          exclusions: [],
          reasons: ['A command downloaded code to a file and ran it with a shell.'],
          tags: [],
          createdAt: START,
          updatedAt: START,
        },
      ],
      { days: 8, telemetry: ['sensors'] },
    );
    // The built-in rule now catches the piped full-path shape itself (it reads the
    // stages), so what a candidate still adds is the two-step download-then-run.
    expect(score?.newlyCaught).toContain('curl-then-run (sensors)');
    expect(score?.falsePerDay.developer.alerts).toBe(0);
  }, 30_000);
});
