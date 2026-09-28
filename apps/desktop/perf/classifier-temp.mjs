// TEMP (reverted before review): cost of one classifier batch on this runner.
import { execFileSync } from 'node:child_process';
import { cpus } from 'node:os';
import { appendFileSync } from 'node:fs';

const cpuS = () =>
  execFileSync('ps', ['-A', '-o', 'time=,comm='], { encoding: 'utf8' })
    .split('\n')
    .filter((l) => /ollama/i.test(l))
    .map((l) => l.trim().split(/\s+/)[0])
    .reduce((a, t) => {
      const p = t.split(':').map(Number);
      while (p.length < 3) p.unshift(0);
      return a + p[0] * 3600 + p[1] * 60 + p[2];
    }, 0);

const tools = [
  '/usr/bin/clang',
  '/usr/bin/git',
  '/usr/local/bin/node',
  '/Applications/Slack.app/Contents/MacOS/Slack',
  '/tmp/.x/upd',
  '/usr/bin/curl',
];
const lines = Array.from(
  { length: 20 },
  (_, i) =>
    `e${i} process started ${tools[i % 6]} [${i % 6 === 4 ? 'unsigned' : 'apple'}] args=-c src/file${i}.c -o obj${i}.o parent=/bin/zsh`,
);
const prompt = [
  'Each line in the data is one event from this Mac, starting with its id. Label every event benign, unusual or suspicious with a score 0-1 and a reason of at most 12 words. Answer JSON {"labels":[{"id","label","score","reason"}]}.',
  ...lines,
].join('\n');
const threads = Math.max(1, Math.floor(cpus().length / 2));
const rows = [];
for (const model of process.argv.slice(2)) {
  for (const run of ['cold', 'warm']) {
    const c0 = cpuS();
    const t0 = Date.now();
    const res = await fetch('http://127.0.0.1:11434/api/chat', {
      method: 'POST',
      body: JSON.stringify({
        model,
        stream: false,
        format: 'json',
        keep_alive: '1m',
        options: { num_ctx: 4096, num_thread: threads, temperature: 0 },
        messages: [{ role: 'user', content: prompt }],
      }),
    }).then((r) => r.json());
    const wall = (Date.now() - t0) / 1000;
    const cpu = cpuS() - c0;
    rows.push(
      `| ${model} | ${run} | ${wall.toFixed(1)} s | ${cpu.toFixed(1)} s | ${(res.load_duration / 1e9).toFixed(1)} s | ${res.prompt_eval_count} | ${res.eval_count} | ${(res.eval_count / (res.eval_duration / 1e9)).toFixed(1)} |`,
    );
  }
}
const md = [
  `### Classifier batch (20 events, ${threads} threads of ${cpus().length}, ${cpus()[0].model})`,
  '',
  '| Model | Run | Wall | CPU | Load | Prompt tok | Output tok | Output tok/s |',
  '|---|---|---|---|---|---|---|---|',
  ...rows,
].join('\n');
console.log(md);
if (process.env.GITHUB_STEP_SUMMARY) appendFileSync(process.env.GITHUB_STEP_SUMMARY, md + '\n');
