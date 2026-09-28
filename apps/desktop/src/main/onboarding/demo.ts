import type { Probe } from './checks.js';

/**
 * A Mac halfway through setup, for `VIGIL_DEMO=1` in development: Homebrew,
 * Santa and osquery installed, Santa not yet allowed, Ollama running with no
 * model, Claude Code installed but signed out.
 */
export function demoProbe(): Probe {
  const bins = new Set(['/opt/homebrew/bin/brew', '/Users/demo/.local/bin/claude']);
  const files = new Set(['/Applications/Santa.app', '/usr/local/bin/osqueryi']);
  return {
    home: '/Users/demo',
    exists: (p) => files.has(p) || bins.has(p),
    executable: (p) => bins.has(p),
    run: async () => ({ code: 1, stdout: '' }),
    getJson: async () => ({ models: [] }),
  };
}
