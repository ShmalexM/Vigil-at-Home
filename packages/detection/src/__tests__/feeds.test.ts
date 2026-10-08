import { DatabaseSync } from 'node:sqlite';
import { describe, expect, it } from 'vitest';
import { DetectionEngine } from '../engine.js';
import {
  cleanEntries,
  DEFAULT_FEEDS,
  FeedImporter,
  MemoryFeedStateStore,
  parseFeed,
  type FeedSource,
  type FetchLike,
} from '../feeds/index.js';
import { macosCoreRules } from '../packs/macos-core.js';
import { sqliteStores, type SqlDatabase } from '../state/sqlite.js';
import { memoryStores } from '../state/stores.js';
import { chrome, connect, DAY, HOUR, proc, T0 } from './fixtures.js';

const sha = (c: string) => c.repeat(64);

describe('parseFeed', () => {
  it('reads one value per line and skips comments and trailing columns', () => {
    const text = '# Feodo\n; note\n\n  45.9.1.2  \n45.9.1.3,2026-09-01\n45.9.1.4 # c2\r\n';
    expect(parseFeed(text, 'lines')).toEqual(['45.9.1.2', '45.9.1.3', '45.9.1.4']);
  });
  it('reads host names out of a hosts file', () => {
    const text = '# URLhaus\n127.0.0.1\tbad.example\n0.0.0.0 a.example b.example\nlone.example\n';
    expect(parseFeed(text, 'hosts')).toEqual([
      'bad.example',
      'a.example',
      'b.example',
      'lone.example',
    ]);
  });
});

describe('cleanEntries', () => {
  it('keeps well-formed hashes, lowercased and deduplicated', () => {
    const r = cleanEntries('known_bad_sha256', [sha('A'), sha('a'), 'abc', sha('g')]);
    expect(r.entries).toEqual([sha('a')]);
    expect(r.dropped).toEqual({ malformed: 2 });
  });

  it('never lists shared platforms, their subdomains or their parents', () => {
    const r = cleanEntries(
      'known_bad_domains',
      [
        'evil.example',
        'Evil.Example.',
        'github.com',
        'raw.githubusercontent.com',
        'x.pages.dev',
        'com',
        'icloud.com',
        '1.2.3.4',
        'bad_host!.example',
        'mine.corp',
        'corp',
      ],
      { neverListDomains: ['mine.corp'] },
    );
    expect(r.entries).toEqual(['evil.example']);
    expect(r.dropped).toEqual({ protected_domain: 5, malformed: 3, ip_in_domain_list: 1 });
  });

  it('refuses private, reserved and very wide address ranges', () => {
    const r = cleanEntries(
      'known_bad_ips',
      [
        '45.9.1.2',
        '45.9.1.2/32',
        '45.9.2.0/24',
        '10.1.2.3',
        '192.168.1.1',
        '127.0.0.1',
        '8.0.0.0/8',
        '2a01:4f8::1',
        'fe80::1',
        '1.2.3.4/40',
        'nonsense',
        '5.6.7.8',
      ],
      { neverListNetworks: ['5.6.7.0/24'] },
    );
    expect(r.entries).toEqual(['45.9.1.2', '45.9.2.0/24', '2a01:4f8::1']);
    expect(r.dropped).toEqual({ reserved_address: 5, range_too_wide: 1, malformed: 2 });
  });
});

function fakeFetch(
  bodies: Record<string, () => { status?: number; body?: string; etag?: string }>,
) {
  const calls: Array<{ url: string; headers: Record<string, string> }> = [];
  const fetch: FetchLike = async (url, init) => {
    calls.push({ url, headers: init.headers });
    const r = bodies[url];
    if (!r) throw new Error('network down');
    const { status = 200, body = '', etag } = r();
    return {
      status,
      headers: { get: (n: string) => (n.toLowerCase() === 'etag' ? (etag ?? null) : null) },
      text: async () => body,
    };
  };
  return { fetch, calls };
}

const src = (over: Partial<FeedSource> & { id: string; url: string }): FeedSource => ({
  name: over.id,
  list: 'known_bad_ips',
  format: 'lines',
  intervalHours: 6,
  retainDays: 0,
  license: 'CC0-1.0',
  homepage: 'https://example.test/',
  ...over,
});

describe('FeedImporter', () => {
  it("combines sources into one list and keeps a failed source's old entries", async () => {
    const stores = memoryStores();
    let bFails = false;
    const { fetch } = fakeFetch({
      'https://a.test/ips': () => ({ body: '45.9.1.2\n' }),
      'https://b.test/ips': () => (bFails ? { status: 500 } : { body: '45.9.1.3\n' }),
    });
    let now = T0;
    const imp = new FeedImporter(
      [src({ id: 'a', url: 'https://a.test/ips' }), src({ id: 'b', url: 'https://b.test/ips' })],
      stores.lists,
      new MemoryFeedStateStore(),
      { fetch, now: () => now },
    );
    const first = await imp.run();
    expect(first.map((r) => r.status)).toEqual(['updated', 'updated']);
    expect(stores.lists.has('known_bad_ips', '45.9.1.2')).toBe(true);
    expect(stores.lists.has('known_bad_ips', '45.9.1.3')).toBe(true);

    bFails = true;
    now += 7 * HOUR;
    const second = await imp.run();
    expect(second[1]).toMatchObject({ status: 'failed', error: 'HTTP 500', entries: 1 });
    expect(stores.lists.has('known_bad_ips', '45.9.1.3')).toBe(true);
    expect(imp.status()[1]).toMatchObject({ lastError: 'HTTP 500', stale: false });
  });

  it('only fetches when due, and retries a failure sooner', async () => {
    const { fetch, calls } = fakeFetch({ 'https://a.test/ips': () => ({ body: '45.9.1.2' }) });
    let now = T0;
    const imp = new FeedImporter(
      [src({ id: 'a', url: 'https://a.test/ips' }), src({ id: 'down', url: 'https://down.test/' })],
      memoryStores().lists,
      new MemoryFeedStateStore(),
      { fetch, now: () => now },
    );
    await imp.run();
    now += 0.5 * HOUR;
    const r = await imp.run();
    expect(r.map((x) => x.status)).toEqual(['skipped', 'skipped']);
    now += 0.5 * HOUR; // after an hour the failed source retries; the healthy one waits 6 h
    expect((await imp.run()).map((x) => x.status)).toEqual(['skipped', 'failed']);
    expect(calls.filter((c) => c.url === 'https://a.test/ips')).toHaveLength(1);
    expect((await imp.run({ force: true }))[0]!.status).toBe('updated');
  });

  it('sends the ETag back and handles "not modified"', async () => {
    const { fetch, calls } = fakeFetch({
      'https://a.test/ips': () =>
        calls.length > 1 ? { status: 304 } : { body: '45.9.1.2', etag: '"v1"' },
    });
    const stores = memoryStores();
    const imp = new FeedImporter(
      [src({ id: 'a', url: 'https://a.test/ips' })],
      stores.lists,
      new MemoryFeedStateStore(),
      { fetch },
    );
    await imp.run({ force: true });
    const r = await imp.run({ force: true });
    expect(calls[1]!.headers['If-None-Match']).toBe('"v1"');
    expect(r[0]).toMatchObject({ status: 'not_modified', entries: 1 });
    expect(stores.lists.has('known_bad_ips', '45.9.1.2')).toBe(true);
  });

  it('keeps the old list when a full feed suddenly shrinks', async () => {
    const big = Array.from({ length: 100 }, (_, i) => `45.9.${i}.1`).join('\n');
    let body = big;
    const { fetch } = fakeFetch({ 'https://a.test/ips': () => ({ body }) });
    const stores = memoryStores();
    const imp = new FeedImporter(
      [src({ id: 'a', url: 'https://a.test/ips' })],
      stores.lists,
      new MemoryFeedStateStore(),
      { fetch },
    );
    await imp.run({ force: true });
    body = '<html>maintenance</html>';
    const r = await imp.run({ force: true });
    expect(r[0]!.status).toBe('failed');
    expect(r[0]!.error).toMatch(/shrank from 100 to 0/);
    expect(stores.lists.size('known_bad_ips')).toBe(100);
  });

  it("sends the user's key to a feed that needs one", async () => {
    const { fetch, calls } = fakeFetch({ 'https://k.test/ips': () => ({ body: '45.9.1.2' }) });
    const stores = memoryStores();
    const imp = new FeedImporter(
      [src({ id: 'k', url: 'https://k.test/ips', auth: { key: 'abusech', header: 'Auth-Key' } })],
      stores.lists,
      new MemoryFeedStateStore(),
      { fetch, keys: (name) => (name === 'abusech' ? 'user-key-0123456789' : undefined) },
    );
    expect((await imp.run())[0]).toMatchObject({ status: 'updated', entries: 1 });
    expect(calls[0]!.headers['Auth-Key']).toBe('user-key-0123456789');
    expect(imp.status()[0]!.needsKey).toBeUndefined();
  });

  it('leaves out a feed whose key is missing and keeps what it already listed', async () => {
    const big = Array.from({ length: 100 }, (_, i) => `45.9.${i}.1`).join('\n');
    const { fetch, calls } = fakeFetch({
      'https://k.test/ips': () => ({ body: big }),
      'https://open.test/ips': () => ({ body: '45.8.1.1' }),
    });
    let key: string | undefined = 'user-key-0123456789';
    let now = T0;
    const stores = memoryStores();
    const state = new MemoryFeedStateStore();
    const imp = new FeedImporter(
      [
        src({ id: 'k', url: 'https://k.test/ips', auth: { key: 'abusech', header: 'Auth-Key' } }),
        src({ id: 'open', url: 'https://open.test/ips' }),
      ],
      stores.lists,
      state,
      { fetch, keys: () => key, now: () => now },
    );
    await imp.run();
    expect(stores.lists.size('known_bad_ips')).toBe(101);

    // An earlier refusal (as before keys were supported) is not reported while the key is missing.
    state.put({ ...state.get('k')!, lastError: 'HTTP 401' });
    key = undefined;
    now += 7 * HOUR;
    const before = state.get('k');
    const r = await imp.run({ force: true });
    expect(r.map((x) => x.status)).toEqual(['needs_key', 'updated']);
    expect(r[0]).toMatchObject({ entries: 100 });
    expect(r[0]!.error).toBeUndefined();
    expect(calls.filter((c) => c.url === 'https://k.test/ips')).toHaveLength(1);
    // Nothing recorded as a failure, and the other feed's rebuild keeps its entries.
    expect(state.get('k')).toEqual(before);
    expect(stores.lists.size('known_bad_ips')).toBe(101);
    expect(imp.status()[0]).toMatchObject({ needsKey: true, stale: false, entries: 100 });
    expect(imp.status()[0]!.lastError).toBeUndefined();
  });

  it('never fetches a keyed feed before a key is added', async () => {
    const { fetch, calls } = fakeFetch({});
    const imp = new FeedImporter(
      DEFAULT_FEEDS.filter((f) => f.auth),
      memoryStores().lists,
      new MemoryFeedStateStore(),
      { fetch },
    );
    expect((await imp.run({ force: true })).map((r) => r.status)).toEqual([
      'needs_key',
      'needs_key',
    ]);
    expect(calls).toHaveLength(0);
  });

  it('runs once when asked again while a run is in progress', async () => {
    const { fetch, calls } = fakeFetch({ 'https://a.test/ips': () => ({ body: '45.9.1.2' }) });
    const imp = new FeedImporter(
      [src({ id: 'a', url: 'https://a.test/ips' })],
      memoryStores().lists,
      new MemoryFeedStateStore(),
      { fetch },
    );
    const [a, b] = await Promise.all([imp.run({ force: true }), imp.run({ force: true })]);
    expect(a).toBe(b);
    expect(calls).toHaveLength(1);
  });

  it('accumulates recent-only feeds and expires entries after retainDays', async () => {
    let body = sha('a');
    const { fetch } = fakeFetch({ 'https://h.test/recent': () => ({ body }) });
    let now = T0;
    const stores = memoryStores();
    const imp = new FeedImporter(
      [src({ id: 'h', url: 'https://h.test/recent', list: 'known_bad_sha256', retainDays: 30 })],
      stores.lists,
      new MemoryFeedStateStore(),
      { fetch, now: () => now },
    );
    await imp.run();
    body = sha('b');
    now += DAY;
    expect((await imp.run())[0]).toMatchObject({ added: 1, removed: 0, entries: 2 });
    expect(stores.lists.has('known_bad_sha256', sha('a'))).toBe(true);
    now += 30 * DAY;
    expect((await imp.run())[0]).toMatchObject({ removed: 1, entries: 1 });
    expect(stores.lists.has('known_bad_sha256', sha('a'))).toBe(false);
  });

  it("never writes the user's own list and refuses unsafe configuration", () => {
    const lists = memoryStores().lists;
    const st = new MemoryFeedStateStore();
    const bad = (s: Partial<FeedSource>) => () =>
      new FeedImporter([src({ id: 'x', url: 'https://x.test/', ...s })], lists, st, {
        fetch: fakeFetch({}).fetch,
      });
    expect(bad({ list: 'user_blocked_sha256' as never })).toThrow(/may only fill/);
    expect(bad({ url: 'http://x.test/' })).toThrow(/https/);
    expect(bad({ id: 'Bad Id' })).toThrow(/lowercase/);
  });

  it('leaves the user-blocked list alone when rebuilding', async () => {
    const stores = memoryStores();
    stores.lists.add('user_blocked_sha256', sha('d'), { source: 'user', updatedAt: T0 });
    const { fetch } = fakeFetch({ 'https://h.test/': () => ({ body: sha('a') }) });
    await new FeedImporter(
      [src({ id: 'h', url: 'https://h.test/', list: 'known_bad_sha256' })],
      stores.lists,
      new MemoryFeedStateStore(),
      { fetch },
    ).run();
    expect(stores.lists.has('user_blocked_sha256', sha('d'))).toBe(true);
  });

  it('feeds the known-bad rules: an IP hit blocks, a domain hit asks', async () => {
    const stores = memoryStores();
    const { fetch } = fakeFetch({
      'https://a.test/ips': () => ({ body: '45.9.1.2' }),
      'https://a.test/hosts': () => ({ body: '0.0.0.0 payload.evil.example' }),
    });
    await new FeedImporter(
      [
        src({ id: 'ips', url: 'https://a.test/ips' }),
        src({
          id: 'hosts',
          url: 'https://a.test/hosts',
          list: 'known_bad_domains',
          format: 'hosts',
        }),
      ],
      stores.lists,
      new MemoryFeedStateStore(),
      { fetch },
    ).run();
    const engine = new DetectionEngine(macosCoreRules, stores);
    const tool = proc({ path: '/Users/alex/Downloads/tool', pid: 4242, signing: 'unsigned' });
    const ip = engine
      .evaluate(connect(tool, '45.9.1.2'))
      .find((d) => d.match.ruleId === 'known-bad-destination');
    expect(ip?.execute).toEqual([{ kind: 'network.block', address: '45.9.1.2' }]);
    const dom = engine
      .evaluate(connect(chrome, '104.16.1.1', 'cdn.payload.evil.example'))
      .find((d) => d.match.ruleId === 'known-bad-domain');
    expect(dom?.execute).toEqual([]);
    expect(dom?.propose).toEqual([{ kind: 'network.block', address: '104.16.1.1' }]);
  });

  it('persists feed state in SQLite', async () => {
    const db = new DatabaseSync(':memory:') as unknown as SqlDatabase;
    const { fetch } = fakeFetch({
      'https://a.test/ips': () => ({ body: '45.9.1.2', etag: '"e"' }),
    });
    const s1 = sqliteStores(db);
    await new FeedImporter([src({ id: 'a', url: 'https://a.test/ips' })], s1.lists, s1.feeds, {
      fetch,
    }).run();
    const s2 = sqliteStores(db);
    expect(s2.feeds.get('a')).toMatchObject({
      etag: '"e"',
      entries: { '45.9.1.2': expect.any(Number) },
    });
    expect(s2.lists.has('known_bad_ips', '45.9.1.2')).toBe(true);
  });

  it('ships valid default sources', () => {
    expect(
      () =>
        new FeedImporter(DEFAULT_FEEDS, memoryStores().lists, new MemoryFeedStateStore(), {
          fetch: fakeFetch({}).fetch,
        }),
    ).not.toThrow();
    expect(new Set(DEFAULT_FEEDS.map((f) => f.list))).toEqual(
      new Set(['known_bad_ips', 'known_bad_domains', 'known_bad_sha256']),
    );
    // URLhaus and MalwareBazaar need the user's own abuse.ch key; none is shipped.
    expect(DEFAULT_FEEDS.filter((f) => f.auth).map((f) => f.id)).toEqual([
      'urlhaus-hosts',
      'malwarebazaar-recent',
    ]);
    for (const f of DEFAULT_FEEDS) expect(f.headers).toBeUndefined();
  });
});
