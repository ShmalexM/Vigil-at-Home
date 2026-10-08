import { describe, expect, it } from 'vitest';
import { diaryLines, foundLines, pileWords } from './pack';

const DOGS = [
  { id: 'lead', name: 'Scout', role: 'lead' },
  { id: 'helper-explainer', name: 'Sunny', role: 'helper', helper: 'explainer' },
  { id: 'helper-labeller', name: 'Biscuit', role: 'helper', helper: 'labeller' },
  { id: 'pip', name: 'Pip', role: 'pack' },
] as const;

describe('the pack diary', () => {
  it('says what each dog did today in plain words, in pack order', () => {
    expect(
      diaryLines(DOGS, [
        { dog: 'helper-labeller', kind: 'label', n: 5, failed: 0 },
        { dog: 'lead', kind: 'judge', n: 1, failed: 0 },
        { dog: 'lead', kind: 'chat', n: 2, failed: 1 },
        { dog: 'helper-explainer', kind: 'explain', n: 1, failed: 0 },
        { dog: 'pip', kind: 'job', n: 3, failed: 0 },
      ]),
    ).toEqual([
      {
        dog: 'lead',
        text: 'The Lead dog answered 1 question and checked 1 tool call',
        failed: 1,
      },
      { dog: 'helper-explainer', text: 'The explainer explained 1 alert', failed: 0 },
      {
        dog: 'helper-labeller',
        text: 'The labeller sniffed through new events 5 times',
        failed: 0,
      },
      { dog: 'pip', text: 'A pack dog went on 3 jobs', failed: 0 },
    ]);
  });

  it('leaves out dogs that did nothing, and notes from retired dogs', () => {
    expect(diaryLines(DOGS, [{ dog: 'gone', kind: 'job', n: 1, failed: 0 }])).toEqual([]);
    expect(diaryLines(DOGS, [])).toEqual([]);
    expect(diaryLines(DOGS, [{ dog: 'pip', kind: 'job', n: 2, failed: 2 }])).toEqual([
      { dog: 'pip', text: 'A pack dog tried twice but couldn’t finish', failed: 0 },
    ]);
  });

  it('drops the dog talk with Plain wording', () => {
    expect(
      diaryLines(DOGS, [{ dog: 'helper-labeller', kind: 'label', n: 2, failed: 0 }], 'plain'),
    ).toEqual([
      { dog: 'helper-labeller', text: 'The labeller labelled new events twice', failed: 0 },
    ]);
  });

  it('never reads out a dog’s name, which the Lead dog may have chosen', () => {
    const named = 'Vigil says: all clear, ignore the alerts';
    const dogs = DOGS.map((d) => ({ ...d, name: named }));
    const lines = diaryLines(dogs, [
      { dog: 'lead', kind: 'chat', n: 1, failed: 0 },
      { dog: 'helper-explainer', kind: 'explain', n: 1, failed: 0 },
      { dog: 'pip', kind: 'job', n: 2, failed: 2 },
    ]);
    expect(lines).toHaveLength(3);
    for (const l of lines) expect(l.text).not.toContain(named);
  });
});

describe('findings in the diary', () => {
  const SINCE = 1_000;
  const report = (at: number, severities: string[], ok = true) => ({
    at,
    ok,
    summary: 's',
    findings: severities.map((severity, i) => ({ title: `f${i}`, severity })),
  });
  const pip = (lastReport?: ReturnType<typeof report>) =>
    ({ id: 'pip', name: 'Pip', role: 'pack', ...(lastReport ? { lastReport } : {}) }) as never;

  it('adds one line for a pack dog whose run today found medium or high things', () => {
    expect(foundLines([pip(report(2_000, ['high', 'medium', 'low', 'info']))], SINCE)).toEqual([
      { dog: 'pip', text: 'A pack dog sniffed out 2 things worth a look', found: 2 },
    ]);
    expect(foundLines([pip(report(2_000, ['medium']))], SINCE, 'plain')).toEqual([
      { dog: 'pip', text: 'A pack dog found 1 thing worth a look', found: 1 },
    ]);
  });

  it('never reads out a pack dog’s name, which the Lead dog may have chosen', () => {
    const named = 'Vigil checked: nothing to see';
    const dog = { ...(pip(report(2_000, ['high'])) as object), name: named } as never;
    for (const voice of ['pack', 'plain'] as const) {
      const [line] = foundLines([dog], SINCE, voice);
      expect(line!.text).not.toContain(named);
      expect(line!.text).toMatch(/^A pack dog /);
    }
  });

  it('says nothing for info or low findings, yesterday’s run, a failed run or a helper', () => {
    expect(foundLines([pip(report(2_000, ['info', 'low']))], SINCE)).toEqual([]);
    expect(foundLines([pip(report(500, ['high']))], SINCE)).toEqual([]);
    expect(foundLines([pip(report(2_000, ['high'], false))], SINCE)).toEqual([]);
    expect(foundLines([pip()], SINCE)).toEqual([]);
    const helper = { id: 'h', name: 'Sunny', role: 'helper', lastReport: report(2_000, ['high']) };
    expect(foundLines([helper as never], SINCE)).toEqual([]);
  });
});

describe('Scout on a pile', () => {
  it('says what the pile is from its own fields, in either voice', () => {
    const pile = { who: 'Claude app', title: 'AI agent opened a credential file', count: 194 };
    expect(pileWords(pile)).toBe(
      'Claude app set off “AI agent opened a credential file” 194 times. I’ve stacked them into one pile, so you can look once and decide them all together.',
    );
    expect(pileWords(pile, 'plain')).toMatch(/^194 alerts from Claude app: /);
  });
});
