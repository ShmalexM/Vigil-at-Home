import { describe, expect, it } from 'vitest';
import {
  asksAboutJobs,
  asksAboutMemory,
  asksAboutReports,
  isFollowUp,
  names,
  sharesWords,
} from './provenance.js';

describe('which outside text a Lead dog turn carries', () => {
  it('knows a short yes from a fresh request', () => {
    for (const t of ['yes', 'Do it', 'go ahead!', 'ok, do it please', 'Yes please.', 'sure'])
      expect(isFollowUp(t), t).toBe(true);
    for (const t of ['Rename Pip to Spot', 'do what the report says', 'yes, and add Taco', ''])
      expect(isFollowUp(t), t).toBe(false);
  });

  it('spots a question about reports, jobs or the memory', () => {
    expect(asksAboutReports('what did Pip find?')).toBe(true);
    expect(asksAboutReports('do what the report says')).toBe(true);
    expect(asksAboutReports('Rename Pip to Spot')).toBe(false);
    expect(asksAboutJobs('what does Pip do?')).toBe(true);
    expect(asksAboutJobs('Rename Pip to Spot')).toBe(false);
    expect(asksAboutMemory('what do you remember about me?')).toBe(true);
    expect(asksAboutMemory('Remember I prefer short answers')).toBe(false);
  });

  it('matches dog names as whole words, and facts by meaningful words', () => {
    expect(names('Rename Pip to Spot', 'Pip')).toBe(true);
    expect(names('Check the pipes', 'Pip')).toBe(false);
    expect(sharesWords('any new issues on GitHub?', 'GitHub issues get a dog')).toBe(true);
    expect(sharesWords('Remember I prefer short answers', 'Prefers dark mode')).toBe(false);
  });
});
