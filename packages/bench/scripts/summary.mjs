// Turns bench-results/*.json into a Markdown summary for the job page.
//   node packages/bench/scripts/summary.mjs [resultsDir] >> "$GITHUB_STEP_SUMMARY"
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';

const dir = resolve(process.argv[2] ?? 'bench-results');
if (!existsSync(dir)) process.exit(0);
const pct = (x) => (x === null || x === undefined ? '–' : `${Math.round(x * 100)}%`);
const ms = (x) => (x === null || x === undefined ? '–' : `${Math.round(x)} ms`);
const num = (x, d = 2) => (x === null || x === undefined ? '–' : x.toFixed(d));
const lines = [];

for (const f of readdirSync(dir)
  .filter((f) => f.endsWith('.json'))
  .sort()) {
  const d = JSON.parse(readFileSync(join(dir, f), 'utf8'));
  if (f === 'detection.json') {
    const s = d.summary;
    lines.push('### Detection', '');
    lines.push(
      "| Attacks | Rules with full telemetry | Through today's sensors |",
      '|---|---|---|',
    );
    lines.push(
      `| Canonical (${s.canonical.total}) | ${s.canonical.caughtIdeal} | ${s.canonical.caughtSensors} |`,
    );
    lines.push(
      `| Evasive (${s.evasive.total}) | ${s.evasive.caughtIdeal} | ${s.evasive.caughtSensors} |`,
    );
    if (s.agents)
      lines.push(
        `| AI agents, canonical (${s.agents.total}) | ${s.agents.caughtIdeal} | ${s.agents.caughtSensors} |`,
      );
    const h = d.heldoutSummary;
    if (h)
      lines.push(
        `| **Held-out (${h.attacks})** | ${h.caughtIdeal} | ${h.caughtSensors} (${h.caughtSensorsNoticed} with a popup or badge) |`,
        '',
        `Held-out look-alikes: ${h.falseAlertsSensors} of ${h.lookalikes} raise a popup or badge through today's sensors (${h.falseAlertsIdeal} with full telemetry), ${h.silentSensors} leave a silent entry, ${h.falseBlocksSensors} blocked.`,
      );
    lines.push('');
    lines.push(
      '| Workload | Telemetry | Events/day | Alerts/day | Popups/day | Blocks/day | Agent rules/day | p99 µs/event | Stored B/event |',
      '|---|---|---|---|---|---|---|---|---|',
    );
    for (const w of d.workload) {
      // Agent rules: their alerts plus the steps an agent stopped to ask about.
      const agent = w.agentRules ? w.agentRules.alerts + w.agentRules.asks : undefined;
      const b = w.storedBytesPerEvent;
      lines.push(
        `| ${w.profile}${w.variant ? ` (${w.variant})` : ''} | ${w.telemetry} | ${w.eventsPerDay} | ${w.perDay.alerts.toFixed(2)} | ${w.perDay.popups.toFixed(2)} | ${w.perDay.blocks.toFixed(2)} | ${num(agent)} | ${w.latencyUs.p99.toFixed(1)} | ${b ? `${Math.round(b.withAgents)} (+${num(b.delta, 1)})` : '–'} |`,
      );
    }
    lines.push('');
    // Shadow rules raise nothing; this is what they would have flagged.
    const shadow = d.workload.filter((w) => w.shadowPerDay && Object.keys(w.shadowPerDay).length);
    if (shadow.length) {
      lines.push('Shadow matches per day (recorded only):', '');
      for (const w of shadow)
        lines.push(
          `- ${w.profile}${w.variant ? ` (${w.variant})` : ''}, ${w.telemetry}: ${Object.entries(
            w.shadowPerDay,
          )
            .map(([id, n]) => `${id} ${n.toFixed(2)}`)
            .join(', ')}`,
        );
      lines.push('');
    }
  } else if (f === 'preflight.json') {
    const s = d.summary;
    lines.push('### Pre-flight', '');
    lines.push(
      "Claude Code's hook asks before each tool call; rules answer deny, ask or nothing (never allow).",
      '',
      '| Tool calls | Denied | Asked | No opinion |',
      '|---|---|---|---|',
      `| Attacks (${s.attacks.total}) | ${s.attacks.denied} | ${s.attacks.asked} | ${s.attacks.missed} |`,
      `| Look-alikes (${s.lookalikes.total}) | ${s.lookalikes.denied} | ${s.lookalikes.asked} | ${s.lookalikes.quiet} |`,
      '',
      `Denies exactly as expected: ${s.deniesExact ? 'yes' : '**no**'}. Known gaps answered as they should be: ${s.gaps.asExpected} of ${s.gaps.total}. Answer time p50 ${num(s.answerUs.p50, 0)} µs, p99 ${num(s.answerUs.p99, 0)} µs.`,
      '',
    );
    for (const m of s.mismatches)
      lines.push(
        `- ${m.kind} \`${m.id}\`: expected ${m.expect}, got ${m.decision}${m.ruleIds.length ? ` (${m.ruleIds.join(', ')})` : ''}`,
      );
    if (s.mismatches.length) lines.push('');
  } else if (f.startsWith('labels-')) {
    lines.push(
      `### Labels: ${d.model}${d.prompt && d.prompt !== 'shipped' ? ` (${d.prompt})` : ''}${d.split === 'heldout' ? ', held-out' : ''}`,
      '',
    );
    lines.push(
      `Attacks flagged ${pct(d.recall)} (${d.attacks}), normal events flagged ${pct(d.falseFlagRate)} (${d.benign}), ${d.secondsPerBatch.toFixed(1)} s per 20-event batch.`,
      '',
    );
  } else if (f === 'flow.json') {
    lines.push(
      `### End-to-end flow on ${d.platform}, macOS ${d.macos}: ${d.passed}/${d.total} checks`,
      '',
    );
    for (const c of d.checks) lines.push(`- ${c.ok ? '✅' : '❌'} ${c.name}`);
    const t = d.timings.filter((x) => x.eventToPopupMs !== null);
    const med = (k) => {
      const xs = t
        .map((x) => x[k])
        .filter((x) => x !== null)
        .sort((a, b) => a - b);
      return xs.length ? xs[Math.floor(xs.length / 2)] : null;
    };
    lines.push(
      '',
      `Median over ${t.length} runs: event to block ${ms(med('eventToBlockMs'))}, to popup ${ms(med('eventToPopupMs'))}, release ${ms(med('releaseMs'))}.`,
      '',
    );
  }
}
console.log(lines.join('\n'));
