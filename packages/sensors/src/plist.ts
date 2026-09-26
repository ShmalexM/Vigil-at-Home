// Minimal XML property list writer, enough for configuration profiles and
// launchd plists. Values: string, number (integers only), boolean, Date,
// arrays and plain objects.

export type PlistValue =
  string | number | boolean | Date | PlistValue[] | { [key: string]: PlistValue | undefined };

function escapeXml(s: string): string {
  return s.replace(
    /[<>&"']/g,
    (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;', "'": '&apos;' })[c]!,
  );
}

function render(value: PlistValue, indent: string): string {
  const next = indent + '\t';
  if (typeof value === 'string') return `${indent}<string>${escapeXml(value)}</string>`;
  if (typeof value === 'boolean') return `${indent}<${value}/>`;
  if (typeof value === 'number') {
    if (!Number.isInteger(value))
      throw new Error(`plist: only integers are supported, got ${value}`);
    return `${indent}<integer>${value}</integer>`;
  }
  if (value instanceof Date)
    return `${indent}<date>${value.toISOString().replace(/\.\d{3}Z$/, 'Z')}</date>`;
  if (Array.isArray(value)) {
    if (value.length === 0) return `${indent}<array/>`;
    return `${indent}<array>\n${value.map((v) => render(v, next)).join('\n')}\n${indent}</array>`;
  }
  const entries = Object.entries(value).filter(([, v]) => v !== undefined) as [
    string,
    PlistValue,
  ][];
  if (entries.length === 0) return `${indent}<dict/>`;
  const body = entries
    .map(([k, v]) => `${next}<key>${escapeXml(k)}</key>\n${render(v, next)}`)
    .join('\n');
  return `${indent}<dict>\n${body}\n${indent}</dict>`;
}

export function toPlist(value: PlistValue): string {
  return (
    '<?xml version="1.0" encoding="UTF-8"?>\n' +
    '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n' +
    '<plist version="1.0">\n' +
    render(value, '') +
    '\n</plist>\n'
  );
}
