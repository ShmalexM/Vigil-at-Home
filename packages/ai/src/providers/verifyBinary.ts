import { checkPin, findExecutable, resolveExecutable, type PinStore } from '../executable.js';

export type BinaryCheck =
  | { readonly state: 'ok'; readonly path: string }
  | { readonly state: 'not_installed' }
  | { readonly state: 'binary_changed'; readonly path: string };

/**
 * Find a vendor CLI and compare it with what was recorded at setup. The first
 * binary seen is recorded; a later change (different signer, or a different
 * hash for an unsigned binary) stops runs until the user accepts it in settings.
 */
export async function verifyBinary(
  provider: string,
  name: string,
  pins: PinStore,
  explicitPath?: string,
): Promise<BinaryCheck> {
  const found = await findExecutable(name, explicitPath ? { explicitPath } : {});
  if (!found) return { state: 'not_installed' };
  const resolved = await resolveExecutable(found);
  const pin = await pins.get(provider);
  switch (checkPin(resolved, pin)) {
    case 'new':
      await pins.set(provider, resolved);
      return { state: 'ok', path: resolved.realPath };
    case 'ok':
      return { state: 'ok', path: resolved.realPath };
    case 'changed':
      return { state: 'binary_changed', path: resolved.realPath };
  }
}
