import { describe, expect, it } from 'vitest';
import { compareVersions, newest, UpdateChecker } from './updates.js';

const release = (tag: string, o: { draft?: boolean; prerelease?: boolean } = {}) => ({
  tag_name: `v${tag}`,
  html_url: `https://github.com/ShmalexM/Vigil-at-Home/releases/tag/v${tag}`,
  draft: o.draft ?? false,
  prerelease: o.prerelease ?? tag.includes('-'),
  published_at: '2026-09-28T22:00:00Z',
  assets: ['arm64', 'x64'].map((arch) => ({
    name: `Vigil-at-Home-${tag}-${arch}.dmg`,
    browser_download_url: `https://github.com/ShmalexM/Vigil-at-Home/releases/download/v${tag}/Vigil-at-Home-${tag}-${arch}.dmg`,
  })),
});

describe('compareVersions', () => {
  it('orders releases and pre-releases', () => {
    const sorted = ['0.1.0', '0.1.0-alpha.10', '0.1.0-alpha.2', '0.2.0', '0.1.0-beta.1'].sort(
      compareVersions,
    );
    expect(sorted).toEqual(['0.1.0-alpha.2', '0.1.0-alpha.10', '0.1.0-beta.1', '0.1.0', '0.2.0']);
  });
});

describe('newest', () => {
  it('picks the newest published release and the DMG for this chip', () => {
    const a = newest(
      [
        release('0.1.0-alpha.3'),
        release('0.1.0-alpha.5', { draft: true }),
        release('0.1.0-alpha.4'),
      ],
      '0.1.0-alpha.2',
      'arm64',
    );
    expect(a?.version).toBe('0.1.0-alpha.4');
    expect(a?.downloadUrl).toMatch(/-arm64\.dmg$/);
    expect(newest([release('0.1.0-alpha.3')], '0.1.0-alpha.2', 'x64')?.downloadUrl).toMatch(
      /-x64\.dmg$/,
    );
  });

  it('says nothing when this is the newest, and skips pre-releases on a full release', () => {
    expect(newest([release('0.1.0-alpha.2')], '0.1.0-alpha.2', 'arm64')).toBeUndefined();
    expect(newest([release('0.2.0-alpha.1'), release('0.1.0')], '0.1.0', 'arm64')).toBeUndefined();
    expect(newest([release('0.1.1')], '0.1.0', 'arm64')?.version).toBe('0.1.1');
  });

  it('offers pre-releases to a full-release build while no full release is published', () => {
    // What GitHub lists today: alpha.1 tagged without the v and no assets, and alpha.3.
    const list = [
      release('0.1.0-alpha.3'),
      { ...release('0.1.0-alpha.1'), tag_name: '0.1.0-alpha.1', assets: [] },
    ];
    expect(newest(list, '0.0.1', 'arm64')).toMatchObject({
      version: '0.1.0-alpha.3',
      downloadUrl: expect.stringMatching(/0\.1\.0-alpha\.3-arm64\.dmg$/),
    });
    // A published full release ends that: pre-releases stay hidden on 0.0.1 again.
    expect(newest([...list, release('0.0.2')], '0.0.1', 'arm64')?.version).toBe('0.0.2');
  });

  it('ignores links that are not github.com', () => {
    const r = release('0.1.0-alpha.3');
    r.assets[0]!.browser_download_url = 'https://example.com/Vigil-at-Home-0.1.0-alpha.3-arm64.dmg';
    expect(newest([r], '0.1.0-alpha.2', 'arm64')?.downloadUrl).toBeUndefined();
    expect(
      newest([{ ...r, html_url: 'https://evil.test/x' }], '0.1.0-alpha.2', 'arm64'),
    ).toBeUndefined();
  });
});

describe('UpdateChecker', () => {
  function checker(body: unknown, ok = true) {
    let saved: unknown = {};
    const opened: string[] = [];
    const found: string[] = [];
    const c = new UpdateChecker({
      current: '0.1.0-alpha.2',
      arch: 'arm64',
      load: () => saved,
      save: (s) => void (saved = s),
      fetch: (async () => ({ ok, status: ok ? 200 : 403, json: async () => body })) as never,
      openExternal: async (u) => void opened.push(u),
      onFound: (v) => found.push(v),
      now: () => 1000,
    });
    return { c, opened, found };
  }

  it('finds an update, tells once, downloads the DMG, and remembers Later', async () => {
    const { c, opened, found } = checker([release('0.1.0-alpha.3')]);
    const v = await c.check();
    expect(v.available?.version).toBe('0.1.0-alpha.3');
    expect(v.dismissed).toBe(false);
    await c.check();
    expect(found).toEqual(['0.1.0-alpha.3']);
    await c.download();
    expect(opened[0]).toMatch(/0\.1\.0-alpha\.3-arm64\.dmg$/);
    c.dismiss();
    expect(c.view().dismissed).toBe(true);
    c.setAuto(false);
    expect(c.view()).toMatchObject({ auto: false, dismissed: true });
  });

  it('opens the release page for What’s new', async () => {
    const { c, opened } = checker([release('0.1.0-alpha.3')]);
    await c.openNotes();
    expect(opened).toEqual([]);
    await c.check();
    await c.openNotes();
    expect(opened[0]).toMatch(/\/releases\/tag\/v0\.1\.0-alpha\.3$/);
  });

  it('reports a failed check in words', async () => {
    const { c } = checker(null, false);
    expect((await c.check()).error).toMatch(/403/);
  });
});

describe('newest on Linux', () => {
  it('never offers a Mac DMG to an x64 Linux machine: the release page opens instead', () => {
    const a = newest([release('0.1.0-alpha.3')], '0.1.0-alpha.2', 'x64', 'linux');
    expect(a?.version).toBe('0.1.0-alpha.3');
    expect(a?.downloadUrl).toBeUndefined();
    expect(a?.notesUrl).toMatch(/^https:\/\/github\.com\//);
  });
});
