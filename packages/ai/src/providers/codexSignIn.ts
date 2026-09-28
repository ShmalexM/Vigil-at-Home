import { lstat, mkdir, rm, symlink, unlink, writeFile } from 'node:fs/promises';
import { homedir } from 'node:os';
import { join } from 'node:path';

/**
 * Lets Vigil's own Codex folder use the sign-in the user already has, without
 * the rest of their Codex setup. Vigil links its folder's auth.json to the
 * user's; only the Codex binary opens it. Vigil checks that the file exists
 * and never reads it. Codex writes refreshed sign-ins through the link
 * (checked on 0.158.0), so both folders stay signed in. The user's
 * config.toml, MCP servers, plugins and instructions stay where they are.
 *
 * Needs a file sign-in: a Codex set to keep its login in the Keychain has no
 * auth.json, and then the user signs in from Vigil instead.
 */
export const DEFAULT_USER_CODEX_HOME = join(homedir(), '.codex');

const AUTH_FILE = 'auth.json';
/** Records that the user chose to share, so a link that later vanishes is noticed. */
const SHARED_MARKER = 'vigil-shared-sign-in';

/** Whether the user's Codex has a sign-in file Vigil could link to. */
export async function canShareCodexSignIn(
  userCodexHome = DEFAULT_USER_CODEX_HOME,
): Promise<boolean> {
  return (await kind(join(userCodexHome, AUTH_FILE))) === 'file';
}

/** Whether Vigil's Codex folder currently uses the user's sign-in. */
export async function isCodexSignInShared(codexHome: string): Promise<boolean> {
  return (await kind(join(codexHome, AUTH_FILE))) === 'link';
}

export type ShareCodexSignInResult =
  { readonly ok: true } | { readonly ok: false; readonly reason: 'no_sign_in_file' };

/**
 * Points Vigil's Codex folder at the user's sign-in. Replaces a sign-in Vigil's
 * folder had of its own. Call only when the user asks for it.
 */
export async function shareCodexSignIn(
  codexHome: string,
  userCodexHome = DEFAULT_USER_CODEX_HOME,
): Promise<ShareCodexSignInResult> {
  const target = join(userCodexHome, AUTH_FILE);
  if (!(await canShareCodexSignIn(userCodexHome))) return { ok: false, reason: 'no_sign_in_file' };
  await mkdir(codexHome, { recursive: true, mode: 0o700 });
  const link = join(codexHome, AUTH_FILE);
  if ((await kind(link)) !== 'missing') await unlink(link);
  await symlink(target, link);
  await writeFile(join(codexHome, SHARED_MARKER), '', { mode: 0o600 });
  return { ok: true };
}

/** Removes the link. The user's own sign-in is untouched. */
export async function stopSharingCodexSignIn(codexHome: string): Promise<void> {
  const link = join(codexHome, AUTH_FILE);
  if ((await kind(link)) === 'link') await unlink(link);
  await rm(join(codexHome, SHARED_MARKER), { force: true });
}

/**
 * True when the user shared their sign-in but the link is no longer there.
 * Codex 0.158.0 rewrites auth.json in place (open with truncate, no rename),
 * which keeps the link; a future Codex that saved by renaming a new file over
 * it would leave Vigil a copy of its own, and a refresh there could sign the
 * user's own Codex out. Vigil then stops using that copy and asks again.
 */
export async function isCodexSignInLinkBroken(codexHome: string): Promise<boolean> {
  if ((await kind(join(codexHome, SHARED_MARKER))) === 'missing') return false;
  return (await kind(join(codexHome, AUTH_FILE))) !== 'link';
}

async function kind(path: string): Promise<'file' | 'link' | 'other' | 'missing'> {
  try {
    const st = await lstat(path);
    return st.isSymbolicLink() ? 'link' : st.isFile() ? 'file' : 'other';
  } catch {
    return 'missing';
  }
}
