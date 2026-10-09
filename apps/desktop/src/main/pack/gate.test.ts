import { describe, expect, it } from 'vitest';
import { afterJudge, gateAction, gateTool, type GateInput } from './gate.js';

const base: GateInput = {
  mode: 'ask',
  choice: 'auto',
  readOnly: false,
  rules: { decision: 'none' },
};

describe('the pack tool gate', () => {
  it('follows the permission mode for tools that can change things', () => {
    expect(gateTool(base)).toEqual({ kind: 'ask', why: 'mode' });
    expect(gateTool({ ...base, mode: 'auto' })).toEqual({ kind: 'judge' });
    expect(gateTool({ ...base, mode: 'full' })).toEqual({ kind: 'run' });
  });

  it('lets tools that only read go ahead in every mode', () => {
    for (const mode of ['ask', 'auto', 'full'] as const)
      expect(gateTool({ ...base, mode, readOnly: true })).toEqual({ kind: 'run' });
  });

  it('asks before every call that can change things once a run read a tainted report', () => {
    for (const mode of ['ask', 'auto', 'full'] as const)
      for (const choice of ['auto', 'ask', 'allow'] as const) {
        expect(gateTool({ ...base, mode, choice, outsideText: true })).toEqual({
          kind: 'ask',
          why: 'outside-text',
        });
        // Vigil's own tools only read, so they still go ahead.
        if (choice !== 'ask')
          expect(gateTool({ ...base, mode, choice, readOnly: true, outsideText: true })).toEqual({
            kind: 'run',
          });
      }
    expect(gateTool({ ...base, choice: 'off', outsideText: true })).toMatchObject({ kind: 'deny' });
  });

  it('puts Vigil’s rules above every mode and every choice', () => {
    const deny = { decision: 'deny' as const, reason: 'Sends keys off the Mac' };
    const ask = { decision: 'ask' as const, reason: 'Force push' };
    for (const mode of ['ask', 'auto', 'full'] as const) {
      for (const choice of ['auto', 'ask', 'allow'] as const) {
        expect(gateTool({ ...base, mode, choice, readOnly: true, rules: deny })).toEqual({
          kind: 'deny',
          reason: 'Sends keys off the Mac',
        });
        expect(gateTool({ ...base, mode, choice, readOnly: true, rules: ask })).toEqual({
          kind: 'ask',
          why: 'rule',
          reason: 'Force push',
        });
      }
    }
  });

  it('applies the user’s own choice before the mode', () => {
    expect(gateTool({ ...base, mode: 'full', choice: 'ask', readOnly: true })).toEqual({
      kind: 'ask',
      why: 'always-ask',
    });
    expect(gateTool({ ...base, choice: 'allow' })).toEqual({ kind: 'run' });
    expect(gateTool({ ...base, mode: 'full', choice: 'off' }).kind).toBe('deny');
  });

  it('only runs what the AI rated low risk, and asks when it couldn’t rate', () => {
    expect(afterJudge({ risk: 'low', reason: 'reads' })).toEqual({ kind: 'run' });
    expect(afterJudge({ risk: 'medium', reason: 'posts' })).toEqual({
      kind: 'ask',
      why: 'judged-risky',
      reason: 'posts',
    });
    expect(afterJudge(undefined)).toEqual({ kind: 'ask', why: 'no-judge' });
  });

  it('gates the Lead dog’s changes to the pack by mode', () => {
    expect(gateAction('ask', 'run', false, false)).toBe('ask');
    expect(gateAction('full', 'retire', false, false)).toBe('apply');
    expect(gateAction('full', 'create', true, false)).toBe('apply');
    expect(gateAction('full', 'create', true, true)).toBe('ask');
    expect(gateAction('ask', 'create', true, false)).toBe('ask');
    expect(gateAction('full', 'run', false, true)).toBe('ask');
    expect(gateAction('auto', 'create', false, false)).toBe('apply');
    expect(gateAction('auto', 'update', false, true)).toBe('ask');
    expect(gateAction('auto', 'create', true, false)).toBe('ask');
    expect(gateAction('auto', 'update', true, false)).toBe('ask');
    expect(gateAction('auto', 'retire', false, false)).toBe('ask');
  });
});
