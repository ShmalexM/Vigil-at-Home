import { userInfo } from 'node:os';

/**
 * Variables a vendor CLI may inherit from Vigil. Everything else (cloud keys,
 * GitHub tokens, other API keys) is dropped so it can't reach the agent.
 */
const INHERITED = [
  'PATH',
  'HOME',
  'USER',
  'LOGNAME',
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  'TMPDIR',
  // Needed on networks that route through a proxy with its own certificate.
  'HTTPS_PROXY',
  'HTTP_PROXY',
  'NO_PROXY',
  'https_proxy',
  'http_proxy',
  'no_proxy',
  'NODE_EXTRA_CA_CERTS',
  'SSL_CERT_FILE',
] as const;

export function buildChildEnv(
  extra: Readonly<Record<string, string | undefined>> = {},
  base: NodeJS.ProcessEnv = process.env,
): Record<string, string> {
  const env: Record<string, string> = {};
  for (const name of INHERITED) {
    const value = base[name];
    if (value !== undefined) env[name] = value;
  }
  // Claude Code finds its claude.ai sign-in in the Keychain only when USER is
  // set (checked on a Mac, 2026-09-28), and an app started by launchd may not
  // have it.
  if (env.USER === undefined && base === process.env) {
    try {
      env.USER = userInfo().username;
    } catch {
      // No user record; leave it unset.
    }
  }
  for (const [name, value] of Object.entries(extra)) {
    if (value !== undefined) env[name] = value;
  }
  return env;
}
