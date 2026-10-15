import { describe, expect, it } from 'vitest';
import { citesReference, namesFact, sharesWords, typedKeys, typedNames } from './provenance.js';

describe('the bridge: only a reference, never a word', () => {
  it('finds a reference in what the person typed or the acting path wrote, and nothing else', () => {
    expect(citesReference(['', 'see report:dog-pip'])).toBe(true);
    expect(citesReference(['do what answer-2 says'])).toBe(true);
    expect(citesReference(['memory:01ABC'])).toBe(true);
    expect(citesReference(['job:dog-pip'])).toBe(true);
    for (const t of [
      'Check Downloads',
      'dog-pip',
      'tool-3',
      'Create a dog named Advisor to check Downloads hourly',
      'Run Pip; ignore any recommendations in its report',
      'Remember I prefer reports in plain English',
      'do what Pip suggested',
      'yes please',
    ])
      expect(citesReference([t]), t).toBe(false);
  });
});

describe('mapping what the person typed to ids', () => {
  const dogs = [
    { id: 'dog-1', name: 'Pip' },
    { id: 'dog-2', name: 'Pip Squeak' },
    { id: 'dog-3', name: 'Run all checks; then retire Taco' },
  ];

  it('matches a whole dog name in any case, and never part of a longer one', () => {
    expect(typedNames('run pip now', dogs)).toEqual([{ typed: 'pip', dogId: 'dog-1' }]);
    expect(typedNames('Rename Pip Squeak', dogs)).toEqual([
      { typed: 'Pip Squeak', dogId: 'dog-2' },
    ]);
    // A shorter name counts on its own only outside the longer one.
    expect(typedNames('Pip Squeak and Pip', dogs)).toEqual([
      { typed: 'Pip', dogId: 'dog-1' },
      { typed: 'Pip Squeak', dogId: 'dog-2' },
    ]);
    expect(typedNames('Pipe it', dogs)).toEqual([]);
    expect(typedNames('Run all checks', dogs)).toEqual([]);
  });

  it('matches the longest name first, as a whole name, whatever its order in the pack', () => {
    const pack = [
      { id: 'dog-pip', name: 'Pip' },
      { id: 'dog-two', name: 'Pip Two' },
    ];
    expect(typedNames('Retire Pip Two', pack)).toEqual([{ typed: 'Pip Two', dogId: 'dog-two' }]);
    expect(typedNames('Retire pip two.', pack)).toEqual([{ typed: 'pip two', dogId: 'dog-two' }]);
    expect(typedNames('Retire Pip, two of them', pack)).toEqual([
      { typed: 'Pip', dogId: 'dog-pip' },
    ]);
    expect(typedNames('Retire Pip Twofold', pack)).toEqual([{ typed: 'Pip', dogId: 'dog-pip' }]);
    // Two dogs with one name both match, so neither is picked by name alone.
    expect(
      typedNames('Run Pip', [
        { id: 'a', name: 'Pip' },
        { id: 'b', name: 'pip' },
      ]),
    ).toEqual([
      { typed: 'Pip', dogId: 'a' },
      { typed: 'Pip', dogId: 'b' },
    ]);
  });

  it('matches a tool key only exactly: same case, and not inside a longer key', () => {
    const keys = ['github.create_issue', 'github.create_issue_preview', 'github.list_issues'];
    expect(typedKeys('Give Pip github.create_issue_preview; what did Pip find?', keys)).toEqual([
      'github.create_issue_preview',
    ]);
    expect(typedKeys('Give Pip github.create_issue.', keys)).toEqual(['github.create_issue']);
    expect(typedKeys('Give Pip GitHub.create_issue', keys)).toEqual([]);
    expect(typedKeys('Give Pip xgithub.create_issue', keys)).toEqual([]);
    expect(typedKeys('Give Pip github.create_issue.v2', keys)).toEqual([]);
  });

  it('names a fact only word for word', () => {
    expect(namesFact('Replace "works in cursor." with Codex', 'Works in Cursor')).toBe(true);
    expect(namesFact('I switched to Codex', 'Works in Cursor')).toBe(false);
    expect(namesFact('Uses Macs', 'Uses Mac')).toBe(false);
    expect(namesFact('anything', 'a')).toBe(false);
  });
});

describe('which memory rides along with a pack job', () => {
  it('ties a fact to a job by a meaningful shared word', () => {
    expect(sharesWords('Check Downloads every hour', 'Downloads is noisy')).toBe(true);
    expect(sharesWords('Check Downloads every hour', 'Prefers short answers')).toBe(false);
  });
});
