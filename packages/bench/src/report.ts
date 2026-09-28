import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';

/**
 * Writes one result file to BENCH_OUT (default bench-results/ at the repo
 * root) and prints it on one line, since the bench workflow's logs are the
 * easiest place to read results back from.
 */
export function writeResult(name: string, data: unknown): string {
  const dir = resolve(
    process.env['BENCH_OUT'] ?? join(import.meta.dirname, '../../../bench-results'),
  );
  mkdirSync(dir, { recursive: true });
  const file = join(dir, `${name}.json`);
  const json = JSON.stringify(data);
  writeFileSync(file, JSON.stringify(data, null, 2));
  console.log(`VIGIL_BENCH ${name} ${json}`);
  return file;
}
