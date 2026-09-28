import type { UsageProvider, UsagePurpose } from '../shared/usage.js';
import type { UsageService } from './usage.js';

const HOUR = 60 * 60 * 1000;
const DAY = 24 * HOUR;

/** Deterministic, so screenshots match from run to run. */
function random(seed: number) {
  let s = seed;
  return () => {
    s = (s * 1664525 + 1013904223) % 2 ** 32;
    return s / 2 ** 32;
  };
}

const KINDS: {
  provider: UsageProvider;
  purpose: UsagePurpose;
  model: string;
  perDay: number;
  input: number;
  output: number;
  cost: (input: number, output: number) => number | null;
}[] = [
  {
    provider: 'claude',
    purpose: 'explain',
    model: 'claude-sonnet-5-5',
    perDay: 3,
    input: 9_000,
    output: 700,
    cost: (i, o) => (i * 3 + o * 15) / 1e6,
  },
  {
    provider: 'claude',
    purpose: 'analyze',
    model: 'claude-opus-5-5',
    perDay: 0.6,
    input: 42_000,
    output: 2_400,
    cost: (i, o) => (i * 5 + o * 25) / 1e6,
  },
  {
    provider: 'codex',
    purpose: 'explain',
    model: 'gpt-5.5',
    perDay: 1.2,
    input: 11_000,
    output: 900,
    cost: () => null,
  },
  {
    provider: 'jev',
    purpose: 'classify',
    model: 'jev-latest',
    perDay: 24,
    input: 3_500,
    output: 120,
    cost: (i) => (i * 0.042) / 1e6,
  },
  {
    provider: 'ollama',
    purpose: 'classify',
    model: 'qwen2.5:1.5b',
    perDay: 18,
    input: 2_200,
    output: 90,
    cost: () => 0,
  },
];

/** Ninety days of Vigil's AI runs and made-up plan limits (`VIGIL_DEMO=1`). */
export function seedUsageDemo(usage: UsageService, now = Date.now()): void {
  const rnd = random(7);
  for (let day = 89; day >= 0; day--) {
    // Busier on weekdays, and a busy spell two weeks ago.
    const date = new Date(now - day * DAY);
    const weekday = date.getDay() % 6 !== 0 ? 1 : 0.4;
    const spell = day >= 12 && day <= 16 ? 2.4 : 1;
    for (const k of KINDS) {
      const count = Math.round(k.perDay * weekday * spell * (0.5 + rnd()));
      for (let n = 0; n < count; n++) {
        const at = now - day * DAY - Math.floor(rnd() * (day === 0 ? 20 * HOUR : DAY));
        const input = Math.round(k.input * (0.6 + rnd() * 0.8));
        const cached =
          k.provider === 'claude' || k.provider === 'codex' ? Math.round(input * 0.7) : 0;
        const output = Math.round(k.output * (0.6 + rnd() * 0.8));
        usage.record({
          id: `demo-${k.provider}-${day}-${n}-${k.purpose}`,
          at,
          purpose: k.purpose,
          provider: k.provider,
          outcome: rnd() < 0.03 ? 'timeout' : 'ok',
          model: k.model,
          usage: {
            inputTokens: input - cached,
            cachedInputTokens: cached,
            outputTokens: output,
            costUsd: k.cost(input, output),
          },
        });
      }
    }
  }

  usage.setLimitsSource(async () => ({
    plans: [
      {
        provider: 'claude',
        plan: 'max',
        available: true,
        windows: [
          {
            id: 'five_hour',
            label: '5-hour limit',
            kind: 'session',
            usedPercent: 38,
            vigilPercent: 2,
            resetsAt: now + 2 * HOUR + 14 * 60_000,
          },
          {
            id: 'seven_day',
            label: 'Weekly limit',
            kind: 'weekly',
            usedPercent: 71,
            vigilPercent: 4,
            resetsAt: now + 2 * DAY + 5 * HOUR,
          },
        ],
      },
      {
        provider: 'codex',
        plan: 'plus',
        available: true,
        windows: [
          {
            id: 'codex:primary',
            label: 'Short-term limit',
            kind: 'session',
            usedPercent: 12,
            vigilPercent: 1,
            resetsAt: now + 3 * HOUR + 40 * 60_000,
          },
          {
            id: 'codex:secondary',
            label: 'Weekly limit',
            kind: 'weekly',
            usedPercent: 22,
            vigilPercent: 1,
            resetsAt: now + 5 * DAY + 2 * HOUR,
          },
        ],
      },
    ],
    caps: { jev: 5 },
    backgroundSharePercent: 10,
  }));
}
