import { describe, expect, it } from 'vitest';
import {
  asksToRead,
  citesReference,
  isFollowUp,
  leansOn,
  namesFact,
  sharesWords,
  typedKeys,
  typedNames,
} from './provenance.js';

describe('routing to the reading path', () => {
  it('spots a question about what a dog found, or the memory', () => {
    for (const t of [
      'What did Pip find on its last run?',
      'what has Bolt reported',
      'Any findings?',
      'show me the latest run',
      'What do you remember about me?',
    ])
      expect(asksToRead(t), t).toBe(true);
    for (const t of [
      'Create a dog to find duplicate files',
      'Rename Pip to Spot',
      'Change Pip’s job to check Downloads',
      'Remember I prefer short answers',
    ])
      expect(asksToRead(t), t).toBe(false);
  });
});

describe('the bridge: a message that leans on text the acting path never saw', () => {
  it('knows a short yes from a fresh request', () => {
    for (const t of ['yes', 'Do it', 'go ahead!', 'ok, do it please', 'Yes please.', 'sure'])
      expect(isFollowUp(t), t).toBe(true);
    for (const t of ['Rename Pip to Spot', 'do what the report says', 'yes, and add Taco', ''])
      expect(isFollowUp(t), t).toBe(false);
  });

  it('defers to a suggestion, a reference, or says yes right after outside text', () => {
    for (const t of [
      'do what Pip suggested',
      'carry out the recommendation',
      'Follow the report',
      'do what answer-2 says',
      'apply report:dog-pip',
      'set it up as you proposed',
    ])
      expect(leansOn(t, false), t).toBe(true);
    expect(leansOn('yes please', true)).toBe(true);
    expect(leansOn('yes please', false)).toBe(false);
    for (const t of [
      'Rename Pip to Spot',
      'Create a dog to find duplicate files',
      "What did Pip find? Change Pip's job to Check Downloads",
      'Run Pip',
    ])
      expect(leansOn(t, true), t).toBe(false);
  });

  it('finds a reference in what the acting path wrote', () => {
    expect(citesReference(['', 'see report:dog-pip'])).toBe(true);
    expect(citesReference(['memory:01ABC'])).toBe(true);
    expect(citesReference(['Check Downloads', 'dog-pip', 'tool-3'])).toBe(false);
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
      { typed: 'Pip', dogId: 'dog-1' },
      { typed: 'Pip Squeak', dogId: 'dog-2' },
    ]);
    expect(typedNames('Pipe it', dogs)).toEqual([]);
    expect(typedNames('Run all checks', dogs)).toEqual([]);
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
