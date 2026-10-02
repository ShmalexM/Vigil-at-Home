import { describe, expect, it } from 'vitest';
import { DetectionRule } from '../types.js';
import { SafetyFloor } from '../safety.js';
import { agentWatchRules } from '../packs/agent-watch.js';
import { agentTree, CLAUDE_BIN } from './fixtures.js';

const VIGIL_APP = '/Applications/Vigil at Home.app/Contents/MacOS/Vigil at Home';

/**
 * Invariant 7: agent roots get no containment immunity. The safety floor does
 * not treat the agent's own process as protected (nothing stops a user's own
 * block rule from pausing it); the only thing keeping Vigil from stopping the
 * agent is the agent pack itself, whose responses target one pid and appear
 * only on exec rules at depth > 0.
 */
describe('invariant 7: agent roots get no containment immunity', () => {
  it('the safety floor grants the agent root no special protection', () => {
    const claude = agentTree(CLAUDE_BIN);
    const root = claude.root.process;
    expect(root.agent?.depth).toBe(0);
    const floor = new SafetyFloor({ selfPaths: [VIGIL_APP] });
    // The agent root is an ordinary developer-signed process: no immunity.
    expect(floor.processProtection(root)).toBeUndefined();
    // Vigil's own process, by contrast, is always protected.
    expect(
      floor.processProtection({ pid: 501, ppid: 1, path: VIGIL_APP, args: ['Vigil at Home'] }),
    ).toBeDefined();
  });

  it('every agent-pack response targets one pid and only fires below the agent', () => {
    const CHILD = { field: 'process.agent.depth', op: 'gt', value: 0 };
    for (const r of agentWatchRules.map((x) => DetectionRule.parse(x))) {
      if (r.response.length === 0) continue;
      expect(r.eventKinds, r.id).toEqual(['process.exec']);
      expect('all' in r.condition && r.condition.all, r.id).toContainEqual(CHILD);
      for (const t of r.response) {
        expect(t, r.id).toMatchObject({ kind: 'process.suspend', pid: '{{process.pid}}' });
      }
    }
  });
});
