import { chmodSync, existsSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { z } from 'zod';
import {
  ApiKeyInput,
  ApiKeyProvider,
  FeedKey,
  FeedKeyName,
  type FeedKeysView,
} from '../../shared/setup.js';
import { API_KEYS } from './plan.js';

/** Encrypts with a key only this app can get from the macOS Keychain (Electron's safeStorage). */
export interface Cipher {
  available(): boolean;
  encrypt(plain: string): Buffer;
  decrypt(data: Buffer): string;
}

const Entry = z.object({
  enc: z.string(),
  last4: z.string().max(4),
  baseUrl: z.string().optional(),
});
const File = z.partialRecord(ApiKeyProvider, Entry);
type File = z.infer<typeof File>;

/**
 * API keys for cloud AI. Encrypted at rest, file readable only by the user,
 * and `get` is for the main process only: the renderer sees the last four
 * characters and nothing else.
 */
export class KeyStore {
  constructor(
    private readonly path: string,
    private readonly cipher: Cipher,
  ) {}

  canSave(): boolean {
    return this.cipher.available();
  }

  list(): Partial<Record<ApiKeyProvider, { last4: string; baseUrl?: string }>> {
    const out: Partial<Record<ApiKeyProvider, { last4: string; baseUrl?: string }>> = {};
    for (const [p, e] of Object.entries(this.read()) as [ApiKeyProvider, File[ApiKeyProvider]][]) {
      if (e) out[p] = { last4: e.last4, ...(e.baseUrl ? { baseUrl: e.baseUrl } : {}) };
    }
    return out;
  }

  /** The key itself, for the AI package in the main process. */
  get(provider: ApiKeyProvider): { key: string; baseUrl?: string } | undefined {
    const e = this.read()[provider];
    if (!e) return undefined;
    try {
      const key = this.cipher.decrypt(Buffer.from(e.enc, 'base64'));
      return { key, ...(e.baseUrl ? { baseUrl: e.baseUrl } : {}) };
    } catch {
      return undefined;
    }
  }

  set(raw: ApiKeyInput): void {
    const input = ApiKeyInput.parse(raw);
    const def = API_KEYS.find((k) => k.provider === input.provider);
    if (def?.prefix && !input.key.startsWith(def.prefix)) {
      throw new Error(`${def.name} keys start with ${def.prefix}`);
    }
    if (def?.needsBaseUrl && !input.baseUrl) throw new Error('Add the gateway’s address too');
    if (input.baseUrl && !isSafeBaseUrl(input.baseUrl)) {
      throw new Error('Use https, or http only for a gateway on this Mac');
    }
    if (!this.cipher.available()) throw new Error('The macOS Keychain isn’t available');
    const file = this.read();
    file[input.provider] = {
      enc: this.cipher.encrypt(input.key).toString('base64'),
      last4: input.key.slice(-4),
      ...(input.baseUrl ? { baseUrl: input.baseUrl } : {}),
    };
    this.write(file);
  }

  clear(provider: ApiKeyProvider): void {
    const file = this.read();
    delete file[provider];
    this.write(file);
  }

  private read(): File {
    return readPrivate(this.path, File);
  }

  private write(file: File): void {
    writePrivate(this.path, file);
  }
}

const FeedFile = z.partialRecord(FeedKeyName, z.object({ enc: z.string() }));
type FeedFile = z.infer<typeof FeedFile>;

/**
 * Keys for threat feeds, such as the user's abuse.ch Auth-Key. Kept like the
 * AI keys, in a file of their own, and the renderer only learns whether one
 * is saved. Vigil never ships a key of its own.
 */
export class FeedKeyStore {
  constructor(
    private readonly path: string,
    private readonly cipher: Cipher,
  ) {}

  /** Whether a feed is refused without a key comes from the importer; see ipc.ts. */
  view(): Omit<FeedKeysView, 'feeds'> {
    const file = readPrivate(this.path, FeedFile);
    return {
      saved: Object.fromEntries(FeedKeyName.options.map((n) => [n, !!file[n]])) as Record<
        FeedKeyName,
        boolean
      >,
      canSave: this.cipher.available(),
    };
  }

  /** The key itself, for the feed importer in the main process. */
  get(name: FeedKeyName): string | undefined {
    const e = readPrivate(this.path, FeedFile)[name];
    if (!e) return undefined;
    try {
      return this.cipher.decrypt(Buffer.from(e.enc, 'base64'));
    } catch {
      return undefined;
    }
  }

  set(name: FeedKeyName, raw: string): void {
    const key = FeedKey.parse(raw);
    if (!this.cipher.available()) throw new Error('The macOS Keychain isn’t available');
    const file = readPrivate(this.path, FeedFile);
    file[name] = { enc: this.cipher.encrypt(key).toString('base64') };
    writePrivate(this.path, file);
  }

  clear(name: FeedKeyName): void {
    const file = readPrivate(this.path, FeedFile);
    delete file[name];
    writePrivate(this.path, file);
  }
}

function readPrivate<T>(path: string, schema: z.ZodType<T>): T {
  if (!existsSync(path)) return {} as T;
  try {
    return schema.parse(JSON.parse(readFileSync(path, 'utf8')));
  } catch {
    return {} as T;
  }
}

/** Written whole and renamed into place, readable only by the user. */
function writePrivate(path: string, data: unknown): void {
  const tmp = `${path}.tmp`;
  writeFileSync(tmp, JSON.stringify(data), { mode: 0o600 });
  chmodSync(tmp, 0o600);
  renameSync(tmp, path);
}

/** Keys must not travel in the clear, except to a gateway on this Mac. */
function isSafeBaseUrl(url: string): boolean {
  const u = new URL(url);
  if (u.protocol === 'https:') return true;
  return ['127.0.0.1', 'localhost', '[::1]'].includes(u.hostname);
}
