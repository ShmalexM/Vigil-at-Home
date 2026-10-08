import type { DogNote, DogNoteKind, NoteToolCall, NoteUsage } from '../../shared/pack';

export const NOTE_KIND: Record<DogNoteKind, string> = {
  chat: 'Chat',
  job: 'Job',
  judge: 'Risk check',
  explain: 'Explanation',
  label: 'Labels',
  review: 'Rule review',
};

export const CALL_OUTCOME: Record<NoteToolCall['outcome'], string> = {
  ran: 'Ran',
  'not-run': 'Not run',
  failed: 'Failed',
};

/** "1,234 tokens in (200 cached), 310 out · about $0.0123", as the Usage page counts them. */
export function usageWords(u: NoteUsage): string {
  const n = (x: number) => x.toLocaleString('en-US');
  const cached = u.cachedInputTokens > 0 ? ` (${n(u.cachedInputTokens)} cached)` : '';
  const cost =
    u.costUsd === null
      ? 'no price from the provider'
      : u.costUsd === 0
        ? 'free'
        : `about $${u.costUsd < 0.01 ? u.costUsd.toFixed(4) : u.costUsd.toFixed(2)}`;
  return `${n(u.inputTokens)} tokens in${cached}, ${n(u.outputTokens)} out · ${cost}`;
}

/** A dog's notes as Markdown, newest first, for pasting into an issue or a file. */
export function notesMarkdown(
  title: string,
  notes: readonly DogNote[],
  opts: { names?: Record<string, string>; now?: number } = {},
): string {
  const out = [
    `# ${title}`,
    '',
    `Exported ${stamp(opts.now ?? Date.now())}. ${notes.length} ${notes.length === 1 ? 'entry' : 'entries'}, newest first. Reasons are the model’s own words; arguments and results are redacted.`,
  ];
  for (const n of notes) {
    const who = opts.names?.[n.dog];
    out.push(
      '',
      `## ${stamp(n.at)} · ${NOTE_KIND[n.kind]}${who ? ` · ${who}` : ''}${n.ok ? '' : ' · didn’t finish'}`,
      '',
      `**Asked:** ${oneLine(n.ask)}`,
    );
    if (n.lookedAt.length) out.push('', `**Looked at:** ${n.lookedAt.join(', ')}`);
    out.push('', `**${n.ok ? 'Answered' : 'What happened'}:** ${n.answer}`);
    if (n.reasons.length) out.push('', '**Reasons given:**', '', ...n.reasons.map((r) => `- ${r}`));
    if (n.thinking) out.push('', '**Thinking summary (from the provider):**', '', n.thinking);
    if (n.calls?.length) {
      out.push('', '**Tool calls:**');
      n.calls.forEach((c, i) => {
        out.push(
          '',
          `${i + 1}. ${c.title} (\`${c.tool}\`): ${CALL_OUTCOME[c.outcome]}${c.reason ? `, ${c.reason}` : ''}`,
          '',
          '   Arguments:',
          '',
          indent(fence(c.args, 'json')),
        );
        if (c.result !== undefined) out.push('', '   Result:', '', indent(fence(c.result)));
      });
    }
    const ran = [n.provider, n.model].filter(Boolean).join(' · ');
    if (ran || n.usage)
      out.push(
        '',
        `**Ran on:** ${[ran, n.usage && usageWords(n.usage)].filter(Boolean).join(' · ')}`,
      );
  }
  return `${out.join('\n')}\n`;
}

/** The same notes as JSON, exactly as stored. */
export function notesJson(dog: string | undefined, notes: readonly DogNote[], now = Date.now()) {
  return `${JSON.stringify({ ...(dog ? { dog } : {}), exportedAt: now, notes }, null, 2)}\n`;
}

function stamp(at: number): string {
  return new Date(at).toISOString().slice(0, 16).replace('T', ' ') + ' UTC';
}

function oneLine(s: string): string {
  return s.replace(/\s*\n\s*/g, ' ');
}

/** A code block that a backtick run in the text can't close early. */
function fence(text: string, lang = ''): string {
  const longest = Math.max(2, ...[...text.matchAll(/`+/g)].map((m) => m[0].length));
  const f = '`'.repeat(longest + 1);
  return `${f}${lang}\n${text}\n${f}`;
}

function indent(s: string): string {
  return s
    .split('\n')
    .map((l) => `   ${l}`)
    .join('\n');
}
