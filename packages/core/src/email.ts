/**
 * Email-like spans, found in one linear pass for privacy redaction.
 *
 * Each `@` (or a URL-encoded `%40`) is grown left over name characters and
 * right over domain characters, with no length limits, so a long or dotted
 * name (`report.2026.10.alice@…`) is hidden whole. A span counts when its
 * domain has a dot followed by two letters. Spans that touch merge, so
 * `alice@example.com-bob@example.org` and `a@b@example.com` go whole. This
 * over-redacts on purpose: a missed address leaks, an extra `<email>` costs
 * nothing. Non-ASCII letters count as name and domain characters.
 */
const isSpace = (c: number): boolean =>
  c === 0xa0 ||
  c === 0x1680 ||
  (c >= 0x2000 && c <= 0x200b) ||
  c === 0x2028 ||
  c === 0x2029 ||
  c === 0x202f ||
  c === 0x205f ||
  c === 0x3000 ||
  c === 0xfeff;
const isAlnum = (c: number): boolean =>
  (c >= 48 && c <= 57) ||
  (c >= 65 && c <= 90) ||
  (c >= 97 && c <= 122) ||
  (c >= 0x80 && !isSpace(c));
const isName = (c: number): boolean =>
  isAlnum(c) || c === 46 || c === 95 || c === 37 || c === 43 || c === 45 || c === 64; // . _ % + - @
const isDomain = (c: number): boolean => isAlnum(c) || c === 46 || c === 45; // . -
const isLetter = (c: number): boolean =>
  (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || (c >= 0x80 && !isSpace(c));

/** The next `@` or `%40` at or after `from`: its index and length, or undefined. */
function nextAt(text: string, from: number): [number, number] | undefined {
  for (let i = from; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (c === 64) return [i, 1];
    if (c === 37 && text[i + 1] === '4' && text[i + 2] === '0') return [i, 3];
  }
  return undefined;
}

/** [start, end) of each email-like span, in order and not overlapping. */
export function emailSpans(text: string): Array<[number, number]> {
  const spans: Array<[number, number]> = [];
  // The previous `@` and where its run of name characters began: a later
  // `@` in the same run starts there too, so no character is scanned twice.
  let prevAt = -1;
  let prevRunStart = 0;
  for (let found = nextAt(text, 0); found;) {
    const [at, width] = found;
    let start = at;
    while (start > prevAt + 1 && isName(text.charCodeAt(start - 1))) start--;
    if (prevAt >= 0 && start === prevAt + 1) start = prevRunStart;
    prevAt = at;
    prevRunStart = start;

    const host = at + width;
    let end = host;
    while (end < text.length && isDomain(text.charCodeAt(end))) end++;
    // A trailing dot or hyphen ends the sentence or the word, not the domain.
    while (end > host && (text[end - 1] === '.' || text[end - 1] === '-')) end--;
    let domain = false;
    for (let i = host + 1; i + 2 < end && !domain; i++) {
      domain =
        text[i] === '.' && isLetter(text.charCodeAt(i + 1)) && isLetter(text.charCodeAt(i + 2));
    }
    if (start < at && domain) {
      const last = spans[spans.length - 1];
      if (last && start <= last[1]) last[1] = end;
      else spans.push([start, end]);
    }
    // The domain run holds no `@` (a `%40` inside it is found again here).
    found = nextAt(text, Math.max(at + 1, host));
  }
  return spans;
}

/** `text` with every email-like span replaced by `marker`. */
export function replaceEmails(text: string, marker = '<email>'): string {
  const spans = emailSpans(text);
  if (spans.length === 0) return text;
  let out = '';
  let last = 0;
  for (const [s, e] of spans) {
    out += text.slice(last, s) + marker;
    last = e;
  }
  return out + text.slice(last);
}
