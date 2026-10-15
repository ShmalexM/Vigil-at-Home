/**
 * Email-like spans, found in one linear pass for privacy redaction.
 *
 * Each `@` is grown left over name characters and right over domain
 * characters, with no length limits, so a long or dotted name (a URL-encoded
 * mailto, `report.2026.10.alice@…`) is hidden whole. A span counts when its
 * domain has a dot followed by two letters. This over-redacts on purpose: a
 * missed address leaks, an extra `<email>` costs nothing.
 */
const isName = (c: number): boolean =>
  (c >= 48 && c <= 57) || // 0-9
  (c >= 65 && c <= 90) || // A-Z
  (c >= 97 && c <= 122) || // a-z
  c === 46 || // .
  c === 95 || // _
  c === 37 || // %
  c === 43 || // +
  c === 45; // -
const isDomain = (c: number): boolean =>
  (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || c === 46 || c === 45;
const isLetter = (c: number): boolean => (c >= 65 && c <= 90) || (c >= 97 && c <= 122);

/** [start, end) of each email-like span, in order and not overlapping. */
export function emailSpans(text: string): Array<[number, number]> {
  const spans: Array<[number, number]> = [];
  let floor = 0;
  for (let at = text.indexOf('@'); at >= 0; at = text.indexOf('@', at + 1)) {
    let start = at;
    while (start > floor && isName(text.charCodeAt(start - 1))) start--;
    let end = at + 1;
    while (end < text.length && isDomain(text.charCodeAt(end))) end++;
    // A trailing dot or hyphen ends the sentence or the word, not the domain.
    while (end > at + 1 && (text[end - 1] === '.' || text[end - 1] === '-')) end--;
    let domain = false;
    for (let i = at + 2; i + 2 < end && !domain; i++) {
      domain =
        text[i] === '.' && isLetter(text.charCodeAt(i + 1)) && isLetter(text.charCodeAt(i + 2));
    }
    if (start < at && domain) {
      spans.push([start, end]);
      floor = end;
    }
    // The domain run holds no `@`, so the next search can start past it.
    at = Math.max(at, end - 1);
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
