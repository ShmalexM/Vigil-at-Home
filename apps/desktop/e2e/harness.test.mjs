import { afterEach, describe, expect, it, vi } from 'vitest';
import { existsSync } from 'node:fs';
import { isolatedRun, loadKit, newTestRunId, realRun, teardownRealRun } from './harness.mjs';

afterEach(() => {
  vi.restoreAllMocks();
});

describe('realRun', () => {
  it('stops the script before anything runs unless it opted in', () => {
    const exit = vi.spyOn(process, 'exit').mockImplementation((code) => {
      throw new Error(`exit ${code}`);
    });
    vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(() => realRun('flow', {})).toThrow('exit 2');
    expect(() => realRun('flow', { VIGIL_ALLOW_REAL_ENFORCEMENT: 'true' })).toThrow('exit 2');
    expect(exit).toHaveBeenCalledTimes(2);
  });

  it('tags the app with a test-run id when it did', () => {
    vi.spyOn(console, 'log').mockImplementation(() => {});
    const run = realRun('flow', { VIGIL_ALLOW_REAL_ENFORCEMENT: '1' });
    expect(run.testRun).toMatch(/^e2e-\d{4}-\d{2}-\d{2}-[a-f0-9]{8}$/);
    expect(run.env).toMatchObject({
      VIGIL_E2E: '1',
      VIGIL_ALLOW_REAL_ENFORCEMENT: '1',
      VIGIL_TEST_RUN_ID: run.testRun,
    });
  });

  it('keeps a valid run id the caller gave', () => {
    expect(newTestRunId({ VIGIL_TEST_RUN_ID: 'ci-123.4' })).toBe('ci-123.4');
    expect(newTestRunId({ VIGIL_TEST_RUN_ID: 'no spaces' })).toMatch(/^e2e-/);
  });
});

describe('isolatedRun', () => {
  it('gives the app its own helper and profile, and no way to enforce for real', async () => {
    vi.stubEnv('VIGIL_ALLOW_REAL_ENFORCEMENT', '1');
    vi.stubEnv('VIGIL_TEST_RUN_ID', 'leaked');
    const iso = await isolatedRun();
    try {
      expect(iso.env.VIGIL_E2E).toBe('1');
      expect(iso.env.VIGIL_HELPER_SOCKET).toBe(iso.helper.socket);
      expect(iso.env.VIGIL_USER_DATA).toBe(iso.userData);
      expect(iso.env.VIGIL_HELPER_APPROVALS).toBe(iso.helper.paths.approvalsDir);
      expect(iso.env).not.toHaveProperty('VIGIL_ALLOW_REAL_ENFORCEMENT');
      expect(iso.env).not.toHaveProperty('VIGIL_TEST_RUN_ID');
      expect(existsSync(iso.helper.socket)).toBe(true);
    } finally {
      await iso.cleanup();
      vi.unstubAllEnvs();
    }
    expect(existsSync(iso.helper.root)).toBe(false);
    expect(existsSync(iso.userData)).toBe(false);
  });
});

describe('teardownRealRun', () => {
  it('undoes what the run left on the helper, through the bundled kit', async () => {
    const { startIsolatedHelper, HelperClient } = await loadKit();
    const helper = await startIsolatedHelper();
    try {
      const run = await HelperClient.connect(helper.socket, helper.approver(), 'e2e-harness-1');
      await run.call({ kind: 'network.block', address: '192.0.2.44' });
      run.close();
      expect(helper.sys.pfTable.has('192.0.2.44')).toBe(true);

      const report = await teardownRealRun({
        testRun: 'e2e-harness-1',
        socket: helper.socket,
        approver: helper.approver(),
      });
      expect(report.undone).toEqual(['blocked network traffic with 192.0.2.44']);
      expect(helper.sys.pfTable.has('192.0.2.44')).toBe(false);

      // Refused releases: the teardown rejects, naming what stays.
      const again = await HelperClient.connect(helper.socket, helper.approver(), 'e2e-harness-2');
      await again.call({ kind: 'network.block', address: '192.0.2.45' });
      again.close();
      await expect(
        teardownRealRun({
          testRun: 'e2e-harness-2',
          socket: helper.socket,
          approver: helper.approver(() => false),
        }),
      ).rejects.toThrow(/left enforcement in force[\s\S]*192\.0\.2\.45/);
    } finally {
      await helper.stop();
    }
  }, 60_000);
});
