import { describe, expect, it } from 'vitest';
import { buildSystemPrompt } from './prompt.js';

describe('explain prompt', () => {
  it('takes what happened from the action records instead of assuming a block', () => {
    const prompt = buildSystemPrompt('explain', []);
    expect(prompt).not.toMatch(/already blocked/);
    expect(prompt).toContain('action records');
    expect(prompt).toContain('only when a record says it was done');
    expect(prompt).toContain('With no action records, nothing was done.');
  });
});
