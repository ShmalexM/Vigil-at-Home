// Turns bench-results/*.json into a Markdown summary for the job page.
//   node packages/bench/scripts/summary.mjs [resultsDir] >> "$GITHUB_STEP_SUMMARY"
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join, resolve } from 'node:path';

const dir = resolve(process.argv[2] ?? 'bench-results');
if (!existsSync(dir)) process.exit(0);
const pct = (x) => (x === null || x === undefined ? '–' : `${Math.round(x * 100)}%`);
const ms = (x) => (x === null || x === undefined ? '–' : `${Math.round(x)} ms`);
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
    const h = d.heldoutSummary;
    if (h)
      lines.push(
        `| **Held-out (${h.attacks})** | ${h.caughtIdeal} | ${h.caughtSensors} (${h.caughtSensorsNoticed} with a popup or badge) |`,
        '',
        `Held-out look-alikes: ${h.falseAlertsSensors} of ${h.lookalikes} raise a popup or badge through today's sensors (${h.falseAlertsIdeal} with full telemetry), ${h.silentSensors} leave a silent entry, ${h.falseBlocksSensors} blocked.`,
      );
    lines.push('');
    lines.push(
      '| Workload | Telemetry | Events/day | Alerts/day | Popups/day | Blocks/day | p99 µs/event |',
      '|---|---|---|---|---|---|---|',
    );
    for (const w of d.workload)
      lines.push(
        `| ${w.profile}${w.variant ? ` (${w.variant})` : ''} | ${w.telemetry} | ${w.eventsPerDay} | ${w.perDay.alerts.toFixed(2)} | ${w.perDay.popups.toFixed(2)} | ${w.perDay.blocks.toFixed(2)} | ${w.latencyUs.p99.toFixed(1)} |`,
      );
    lines.push('');
  } else if (f.startsWith('labels-')) {
    lines.push(`### Labels: ${d.model}`, '');
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
