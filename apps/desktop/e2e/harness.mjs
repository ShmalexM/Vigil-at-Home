// What every e2e script runs the app with, so a run can't leave enforcement
// or alerts behind on the machine it runs on (docs/e2e-safety.md).
//
// isolatedRun(): the default. The app gets a throwaway profile and an
// isolated helper (packages/helper/src/testing/isolatedHelper.ts): its own
// socket, state and approvals folders in a temporary folder, with a fake
// pf, Santa and launchd. The installed helper and the real vigil.db are
// never touched.
//
// realRun(): for a check that must enforce for real (flow.e2e.mjs). It
// refuses unless VIGIL_ALLOW_REAL_ENFORCEMENT=1, tags everything the run
// asks the helper to do with a test-run id, and its teardown undoes whatever
// that id still has in force, failing the run if anything stays.
import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import { BUNDLE_OPTIONS } from '../scripts/bundle-options.mjs';

const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../../..');
export const ALLOW_REAL_ENFORCEMENT_ENV = 'VIGIL_ALLOW_REAL_ENFORCEMENT';

let kit;
/** The helper's test kit (testing/e2eKit.ts), bundled for plain node once per run. */
export async function loadKit() {
  if (kit) return kit;
  const dir = mkdtempSync(join(tmpdir(), 'vigil-e2e-kit-'));
  const outfile = join(dir, 'kit.mjs');
  await build({
    ...BUNDLE_OPTIONS,
    entryPoints: [join(repo, 'packages/helper/src/testing/e2eKit.ts')],
    outfile,
  });
  kit = await import(pathToFileURL(outfile).href);
  rmSync(dir, { recursive: true, force: true });
  return kit;
}

/** The environment for the app, without anything that would let it enforce for real. */
function baseEnv() {
  const env = { ...process.env, VIGIL_E2E: '1' };
  delete env[ALLOW_REAL_ENFORCEMENT_ENV];
  delete env.VIGIL_TEST_RUN_ID;
  return env;
}

/**
 * A throwaway profile and an isolated helper. Pass `env` to electron.launch
 * and call `cleanup()` when done.
 */
export async function isolatedRun() {
  const { startIsolatedHelper } = await loadKit();
  const helper = await startIsolatedHelper();
  const userData = mkdtempSync(join(tmpdir(), 'vigil-e2e-profile-'));
  return {
    helper,
    userData,
    env: {
      ...baseEnv(),
      VIGIL_USER_DATA: userData,
      VIGIL_HELPER_SOCKET: helper.socket,
      // The app answers this helper's password dialog itself, so no real one opens.
      VIGIL_HELPER_APPROVALS: helper.paths.approvalsDir,
    },
    async cleanup() {
      await helper.stop();
      rmSync(userData, { recursive: true, force: true });
    },
  };
}

/** A new test-run id, or VIGIL_TEST_RUN_ID when the caller set one. */
export function newTestRunId(env = process.env) {
  const given = env.VIGIL_TEST_RUN_ID;
  if (given && /^[A-Za-z0-9._-]{1,64}$/.test(given)) return given;
  return `e2e-${new Date().toISOString().slice(0, 10)}-${randomBytes(4).toString('hex')}`;
}

/**
 * For a check that enforces on this machine for real. Exits with status 2
 * unless the caller opted in, before anything has run.
 */
export function realRun(name, env = process.env) {
  if (env[ALLOW_REAL_ENFORCEMENT_ENV] !== '1') {
    console.error(
      `${name} blocks addresses with pf, turns off startup items and pauses processes ` +
        `through the installed helper. It runs only on a throwaway Mac (a CI runner or a VM) ` +
        `with ${ALLOW_REAL_ENFORCEMENT_ENV}=1 set. See docs/e2e-safety.md.`,
    );
    process.exit(2);
  }
  const testRun = newTestRunId(env);
  console.log(`test run ${testRun}: everything it asks the helper to do is tagged with this id`);
  return {
    testRun,
    env: {
      ...baseEnv(),
      [ALLOW_REAL_ENFORCEMENT_ENV]: '1',
      VIGIL_TEST_RUN_ID: testRun,
    },
  };
}

/** Answers the helper's password dialog through `sudo -n <helper> approve`, as on a CI runner. */
export function sudoApprover(helperExecutable) {
  return (nonce, _prompt, also = []) =>
    new Promise((res) => {
      execFile('sudo', ['-n', helperExecutable, 'approve', nonce, ...also], (err) => res(!err));
    });
}

/**
 * Undo everything `testRun` still has in force on the helper at `socket`.
 * Resolves with the report; rejects with a TeardownError naming what stays.
 */
export async function teardownRealRun({ testRun, socket, approver }) {
  const { HelperClient, teardownTestRun } = await loadKit();
  // Untagged (''), or the clearing sync would belong to the run again.
  const client = await HelperClient.connect(socket, approver, '');
  try {
    return await teardownTestRun(client, testRun);
  } finally {
    client.close();
  }
}
