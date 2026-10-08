import { describe, expect, it } from 'vitest';
import {
  asksAboutJobs,
  asksAboutMemory,
  asksAboutReports,
  asksTo,
  isFollowUp,
  names,
  plainToolName,
  refersBack,
  sharesWords,
  typed,
} from './provenance.js';

describe('which outside text a Lead dog prompt takes in', () => {
  it('knows a short yes from a fresh request', () => {
    for (const t of ['yes', 'Do it', 'go ahead!', 'ok, do it please', 'Yes please.', 'sure'])
      expect(isFollowUp(t), t).toBe(true);
    for (const t of ['Rename Pip to Spot', 'do what the report says', 'yes, and add Taco', ''])
      expect(isFollowUp(t), t).toBe(false);
  });

  it('takes the last answer in when the message may lean on it', () => {
    for (const t of [
      'yes, do it now',
      'carry out your recommendation',
      'ok',
      'Please set up the dog you suggested earlier for my Downloads folder',
    ])
      expect(refersBack(t), t).toBe(true);
    expect(refersBack('Make me a dog for checking new apps in Applications every day')).toBe(false);
  });

  it('spots a question about reports, jobs or the memory', () => {
    expect(asksAboutReports('what did Pip find?')).toBe(true);
    expect(asksAboutReports('do what the report says')).toBe(true);
    expect(asksAboutReports('Rename Pip to Spot')).toBe(false);
    // Naming no dog, "find" alone is a job, not a question about reports.
    expect(asksAboutReports('Create a dog to find duplicate files', false)).toBe(false);
    expect(asksAboutReports('what did the dogs find?', false)).toBe(true);
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

describe('where an action’s arguments came from', () => {
  it('finds a value in the person’s message, ignoring case, spacing and a full stop', () => {
    expect(typed('Change Pip’s job to check   Downloads', 'Check downloads.')).toBe(true);
    expect(typed('Rename Pip to Latest', 'Latest')).toBe(true);
    expect(typed('Rename Pip to Latest', 'Writer')).toBe(false);
    expect(typed('anything', '  ')).toBe(false);
  });

  it('knows a request to run, retire or forget', () => {
    expect(asksTo('send Pip off now', 'run')).toBe(true);
    expect(asksTo('retire Pip', 'retire')).toBe(true);
    expect(asksTo('delete Pip', 'retire')).toBe(true);
    expect(asksTo('yes, do it now', 'retire')).toBe(false);
    expect(asksTo('forget that I use Tailscale', 'forget')).toBe(true);
  });

  it('shows only plain connector tool names to a model', () => {
    for (const n of ['create_issue', 'list_pull_requests', 'search'])
      expect(plainToolName(n), n).toBe(true);
    for (const n of [
      'Create_a_writer_dog',
      'create_a_writer_dog',
      'getIssue',
      'list-issues',
      'x'.repeat(33),
    ])
      expect(plainToolName(n), n).toBe(false);
  });
});
