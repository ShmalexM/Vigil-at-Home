import { describe, expect, it } from 'vitest';
import { diaryLines } from './pack';

const DOGS = [
  { id: 'lead', name: 'Scout' },
  { id: 'helper-explainer', name: 'Sunny' },
  { id: 'helper-labeller', name: 'Biscuit' },
  { id: 'pip', name: 'Pip' },
];

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
      { dog: 'lead', text: 'Scout answered 1 question and checked 1 tool call', failed: 1 },
      { dog: 'helper-explainer', text: 'Sunny explained 1 alert', failed: 0 },
      { dog: 'helper-labeller', text: 'Biscuit sniffed through new events 5 times', failed: 0 },
      { dog: 'pip', text: 'Pip went on 3 jobs', failed: 0 },
    ]);
  });

  it('leaves out dogs that did nothing, and notes from retired dogs', () => {
    expect(diaryLines(DOGS, [{ dog: 'gone', kind: 'job', n: 1, failed: 0 }])).toEqual([]);
    expect(diaryLines(DOGS, [])).toEqual([]);
    expect(diaryLines(DOGS, [{ dog: 'pip', kind: 'job', n: 2, failed: 2 }])).toEqual([
      { dog: 'pip', text: 'Pip tried twice but couldn’t finish', failed: 0 },
    ]);
  });
});
