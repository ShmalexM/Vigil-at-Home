import { describe, expect, it } from 'vitest';
import { aboutText, systemName } from './about';

describe('About', () => {
  it('names the system in words', () => {
    expect(systemName('darwin', 'arm64')).toBe('macOS, Apple silicon');
    expect(systemName('linux', 'x64')).toBe('Linux, Intel or AMD (x64)');
  });

  it('copies versions and protection, nothing personal', () => {
    const text = aboutText(
      { version: '0.1.0-alpha.4', commit: '04a2874', platform: 'darwin', arch: 'arm64' },
      {
        level: 'fair',
        dryRun: true,
        sensors: [
          { id: 'santa', state: 'ok' },
          { id: 'helper', state: 'not_installed' },
        ],
      },
    );
    expect(text).toBe(
      [
        'Vigil at Home 0.1.0-alpha.4 (04a2874)',
        'System: macOS, Apple silicon (darwin arm64)',
        'Protection: fair, blocks simulated',
        'Layers: santa ok, helper not_installed',
      ].join('\n'),
    );
  });
});
