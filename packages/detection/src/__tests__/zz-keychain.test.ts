import { it } from 'vitest';
import { DetectionEngine } from '../engine.js';
import { builtinRules } from '../packs/agent-preflight.js';
import { memoryStores } from '../state/stores.js';
import { exec, proc } from './fixtures.js';
const home = '/Users/alexmargaris';
const SESSION = '0123456789abcdef';
const cmd = 'security find-generic-password -a "alexmargaris" -w -s "Claude Code-credentials"';
const secArgs = (svc: string) => [
  '/usr/bin/security',
  'find-generic-password',
  '-a',
  'alexmargaris',
  '-w',
  '-s',
  svc,
];
const tag = (depth: number, id = 'claude-code') => ({ id, session: SESSION, depth });
const anc = ['2.1.280', '    claude', '    -zsh', 'login'];
const appCli = `${home}/Library/Application Support/Claude/claude-code/2.1.286/f2326db61802/claude.app/Contents/MacOS/claude`;
const native = `${home}/.local/share/claude/versions/2.1.283`;
const sdk = `${home}/code/x/node_modules/@anthropic-ai/claude-agent-sdk-darwin-arm64/claude`;
const cases: Record<string, any> = {
  sh_noparent: proc({
    path: '/bin/sh',
    args: ['/bin/sh', '-c', cmd],
    parentPath: '',
    ancestors: anc,
    agent: tag(1),
  }),
  sh_noparent_undef: proc({
    path: '/bin/sh',
    args: ['/bin/sh', '-c', cmd],
    ancestors: anc,
    agent: tag(1),
  }),
  sec_under_sh: proc({
    path: '/usr/bin/security',
    args: secArgs('Claude Code-credentials'),
    parentPath: '/bin/sh',
    ancestors: ['sh', ...anc],
    agent: tag(2),
  }),
  sec_under_sh_bash: proc({
    path: '/usr/bin/security',
    args: secArgs('Claude Code-credentials'),
    parentPath: '/bin/bash',
    ancestors: ['bash', ...anc],
    agent: tag(2),
  }),
  appcli: proc({
    path: '/usr/bin/security',
    args: secArgs('Claude Code'),
    parentPath: appCli,
    ancestors: ['claude', 'disclaimer', 'Claude', 'launchd'],
    agent: tag(1),
  }),
  native: proc({
    path: '/usr/bin/security',
    args: secArgs('Claude Code-credentials'),
    parentPath: native,
    ancestors: ['2.1.283', 'Electron', 'node', 'zsh'],
    agent: tag(1),
  }),
  sdk: proc({
    path: '/usr/bin/security',
    args: secArgs('Claude Code-5225c161'),
    parentPath: sdk,
    ancestors: ['claude', 'node'],
    agent: tag(1),
  }),
  sdk2: proc({
    path: '/usr/bin/security',
    args: secArgs('Claude Code-credentials-5ce4712a'),
    parentPath: sdk,
    ancestors: ['claude', 'node'],
    agent: tag(1),
  }),
  native280: proc({
    path: '/usr/bin/security',
    args: secArgs('Claude Code-credentials'),
    parentPath: `${home}/.local/share/claude/versions/2.1.280`,
    ancestors: anc,
    agent: tag(1),
  }),
  vigilself: proc({
    path: '/usr/bin/security',
    args: secArgs('Claude Code-credentials'),
    parentPath: native,
    ancestors: ['2.1.283', 'Vigil at Home'],
    agent: tag(2, 'vigil-self'),
  }),
  control_other: proc({
    path: '/usr/bin/security',
    args: secArgs('Chrome Safe Storage'),
    parentPath: native,
    ancestors: ['2.1.283'],
    agent: tag(1),
  }),
  control_sh_other: proc({
    path: '/bin/sh',
    args: ['/bin/sh', '-c', cmd.replace('Claude Code-credentials', 'Chrome Safe Storage')],
    parentPath: '',
    ancestors: anc,
    agent: tag(1),
  }),
  sec_under_sh_other: proc({
    path: '/usr/bin/security',
    args: secArgs('Chrome Safe Storage'),
    parentPath: '/bin/sh',
    ancestors: ['sh', ...anc],
    agent: tag(2),
  }),
};
it('which fire', () => {
  for (const [k, p] of Object.entries(cases)) {
    const e = new DetectionEngine(builtinRules, memoryStores());
    const ids = e.evaluate(exec(p)).map((d) => d.match.ruleId);
    console.log(k, ids.includes('agent-keychain-secret') ? 'FIRES' : 'quiet', ids.join(','));
  }
});
