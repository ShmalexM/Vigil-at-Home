// What the e2e scripts use from the helper, bundled for plain node by
// apps/desktop/e2e/harness.mjs.
export { startIsolatedHelper, type IsolatedHelper } from './isolatedHelper.js';
export { teardownTestRun, TeardownError, type TeardownReport } from './teardown.js';
export { HelperClient } from '../client.js';
export { defaultPaths } from '../config.js';
