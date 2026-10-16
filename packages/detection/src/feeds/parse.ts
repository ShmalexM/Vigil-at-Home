import type { FeedSource } from './sources.js';

/** Pull candidate values out of a feed body. Validation happens separately. */
export function parseFeed(text: string, format: FeedSource['format']): string[] {
  const out: string[] = [];
  for (const rawLine of text.split(/\r?\n/)) {
    const comment = rawLine.search(/[#;]/);
    const line = (comment < 0 ? rawLine : rawLine.slice(0, comment)).trim();
    if (!line) continue;
    const fields = line.split(/[\s,]+/);
    if (format === 'hosts') {
      // "0.0.0.0 host [host...]"; a bare host name is accepted too.
      const hosts = fields.length > 1 ? fields.slice(1) : fields;
      for (const h of hosts) if (h) out.push(h);
    } else if (fields[0]) {
      out.push(fields[0]);
    }
  }
  return out;
}
