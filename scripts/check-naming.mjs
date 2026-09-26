#!/usr/bin/env node
// Fails if the former company name appears anywhere in tracked files or file
// paths. The product is Vigil / Vigil at Home; the shield mark may be used,
// but the old name must never ship. The pattern is assembled from pieces so
// this script does not flag itself.
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const parts = ['deep', 'tempo'];
const banned = new RegExp(`${parts[0]}[\\s_-]?${parts[1]}`, 'i');
// Upstream leftovers that carried the name in short form.
const bannedTokens = [/--dt-[a-z]/, /\bdt_[a-z]+_/];

const files = execFileSync('git', ['ls-files', '--cached', '--others', '--exclude-standard'], {
  encoding: 'utf8',
})
  .split('\n')
  .filter(Boolean);

const hits = [];
for (const file of files) {
  if (banned.test(file)) hits.push(`${file}: file name`);
  let text;
  try {
    text = readFileSync(file, 'utf8');
  } catch {
    continue;
  }
  if (text.includes('\0')) continue;
  text.split('\n').forEach((line, i) => {
    if (banned.test(line) || bannedTokens.some((re) => re.test(line))) {
      hits.push(`${file}:${i + 1}`);
    }
  });
}

if (hits.length > 0) {
  console.error('Naming check failed. Use "Vigil" instead of the former company name:');
  for (const hit of hits) console.error(`  ${hit}`);
  process.exit(1);
}
console.log(`Naming check passed (${files.length} files).`);
