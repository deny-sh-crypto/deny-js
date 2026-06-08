/**
 * deny-sh/client — minimal HTTP client for the deny.sh managed vault.
 *
 * Lets server-side agent code retrieve a stored credential by label,
 * decrypt it locally, and use it inside a tool call boundary so the
 * plaintext never enters the LLM context window.
 *
 * The wire shape matches what `web/js/vault-app.js` writes:
 *   client-side AES-256-CTR with an Argon2id-derived key. Salt + IV
 *   are stored alongside the ciphertext; the server never sees the
 *   plaintext or the password.
 *
 * Quick start:
 *
 *   import { vaultGet } from 'deny-sh/client';
 *
 *   const stripeKey = await vaultGet('stripe-prod', process.env.VAULT_PW!);
 *
 * Configuration via env (optional overrides):
 *   DENY_API_KEY   bearer token for deny.sh (cs_...)  REQUIRED
 *   DENY_API_URL   base URL, default 'https://deny.sh/api'
 *   DENY_VAULT_LABEL_INDEX_LIMIT  max vault items to scan when resolving a label, default 200
 *
 * If you prefer explicit configuration over env, pass apiKey + baseUrl in opts.
 */

import { argon2id } from 'hash-wasm';
import { createDecipheriv } from 'node:crypto';

const ARGON2_T_COST = 3;
const ARGON2_M_COST = 65536;
const ARGON2_P = 1;
const KEY_LEN = 32;

const DEFAULT_BASE_URL = 'https://deny.sh/api';
const DEFAULT_LABEL_INDEX_LIMIT = 200;

export interface VaultGetOptions {
  /** Override the bearer API key. Defaults to process.env.DENY_API_KEY. */
  apiKey?: string;
  /** Override the API base URL. Defaults to process.env.DENY_API_URL || 'https://deny.sh/api'. */
  baseUrl?: string;
  /**
   * Maximum number of vault items to scan when resolving a label.
   * Defaults to process.env.DENY_VAULT_LABEL_INDEX_LIMIT or 200.
   */
  labelIndexLimit?: number;
  /** Optional AbortSignal for cancelling in-flight requests. */
  signal?: AbortSignal;
  /** Optional fetch implementation (for testing). Defaults to globalThis.fetch. */
  fetch?: typeof fetch;
}

export class VaultError extends Error {
  readonly status?: number;
  readonly code: string;
  constructor(code: string, message: string, status?: number) {
    super(message);
    this.name = 'VaultError';
    this.code = code;
    this.status = status;
  }
}

interface VaultListItem {
  id: string;
  label: string;
  size: number;
  category?: string;
  created_at?: string;
  updated_at?: string | null;
}

interface VaultItemFull {
  id: string;
  label: string;
  encryptedData: string;
  iv: string;
  salt: string;
  size: number;
  category?: string;
  created_at?: string;
  updated_at?: string | null;
}

function hexToBytes(hex: string): Uint8Array {
  if (typeof hex !== 'string' || hex.length === 0 || hex.length % 2 !== 0) {
    throw new VaultError('vault_bad_hex', 'Invalid hex string from vault.');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) {
    const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) {
      throw new VaultError('vault_bad_hex', 'Invalid hex character from vault.');
    }
    out[i] = byte;
  }
  return out;
}

async function deriveKey(password: string, salt: Uint8Array): Promise<Uint8Array> {
  const key = await argon2id({
    password: new TextEncoder().encode(password),
    salt,
    parallelism: ARGON2_P,
    iterations: ARGON2_T_COST,
    memorySize: ARGON2_M_COST,
    hashLength: KEY_LEN,
    outputType: 'binary',
  });
  return new Uint8Array(key);
}

function getApiKey(opts: VaultGetOptions): string {
  const apiKey = opts.apiKey ?? process.env.DENY_API_KEY;
  if (!apiKey || typeof apiKey !== 'string') {
    throw new VaultError(
      'vault_missing_api_key',
      'DENY_API_KEY is not set. Provide opts.apiKey or set the env var. See https://deny.sh/dashboard for your tenant key.',
    );
  }
  return apiKey;
}

function getBaseUrl(opts: VaultGetOptions): string {
  const url = opts.baseUrl ?? process.env.DENY_API_URL ?? DEFAULT_BASE_URL;
  return url.replace(/\/$/, '');
}

function getLabelLimit(opts: VaultGetOptions): number {
  if (typeof opts.labelIndexLimit === 'number') return opts.labelIndexLimit;
  const env = process.env.DENY_VAULT_LABEL_INDEX_LIMIT;
  if (env) {
    const n = Number.parseInt(env, 10);
    if (Number.isFinite(n) && n > 0) return n;
  }
  return DEFAULT_LABEL_INDEX_LIMIT;
}

async function apiFetch<T>(
  path: string,
  opts: VaultGetOptions,
  init?: RequestInit,
): Promise<T> {
  const apiKey = getApiKey(opts);
  const baseUrl = getBaseUrl(opts);
  const fetchImpl = opts.fetch ?? globalThis.fetch;
  if (!fetchImpl) {
    throw new VaultError(
      'vault_no_fetch',
      'No fetch implementation available. Pass opts.fetch or use Node 18+ / a runtime with global fetch.',
    );
  }
  const headers: Record<string, string> = {
    Authorization: `Bearer ${apiKey}`,
    Accept: 'application/json',
    ...(init?.headers as Record<string, string> | undefined),
  };
  let res: Response;
  try {
    res = await fetchImpl(`${baseUrl}${path}`, {
      ...init,
      headers,
      signal: opts.signal,
    });
  } catch (err) {
    throw new VaultError(
      'vault_network_error',
      `Network error calling deny.sh: ${(err as Error).message}`,
    );
  }
  if (res.status === 401) {
    throw new VaultError('vault_unauthorized', 'deny.sh rejected the API key.', 401);
  }
  if (res.status === 404) {
    throw new VaultError('vault_not_found', `Vault item not found at ${path}.`, 404);
  }
  if (!res.ok) {
    let body: string;
    try { body = await res.text(); } catch { body = '(no body)'; }
    throw new VaultError(
      'vault_http_error',
      `deny.sh returned ${res.status}: ${body.slice(0, 200)}`,
      res.status,
    );
  }
  try {
    return await res.json() as T;
  } catch {
    throw new VaultError('vault_bad_response', 'deny.sh returned non-JSON response.', res.status);
  }
}

async function listVault(opts: VaultGetOptions): Promise<VaultListItem[]> {
  const r = await apiFetch<{ items: VaultListItem[]; count: number }>('/vault/list', opts);
  if (!r || !Array.isArray(r.items)) {
    throw new VaultError('vault_bad_response', 'deny.sh vault list returned no items array.');
  }
  return r.items;
}

async function getVaultItem(id: string, opts: VaultGetOptions): Promise<VaultItemFull> {
  const r = await apiFetch<VaultItemFull>(`/vault/${encodeURIComponent(id)}`, opts);
  if (!r || typeof r.encryptedData !== 'string') {
    throw new VaultError('vault_bad_response', 'deny.sh vault item is missing encryptedData.');
  }
  return r;
}

/**
 * Resolve a label to a vault item id.
 *
 * The label index is server-side but cheap. We pull the list of vault items
 * (id + label + metadata, no plaintext, no ciphertext), filter by exact label
 * match, and pick the most recently created if there are duplicates.
 *
 * For deployments with thousands of items, prefer storing items with stable
 * ids and calling vaultGetById() directly instead of looking up by label.
 */
async function resolveLabel(label: string, opts: VaultGetOptions): Promise<string> {
  const items = await listVault(opts);
  const limit = getLabelLimit(opts);
  if (items.length > limit) {
    throw new VaultError(
      'vault_label_index_too_large',
      `Vault has ${items.length} items, exceeds DENY_VAULT_LABEL_INDEX_LIMIT (${limit}). Use vaultGetById() with a stable id, or raise the limit if you have audited the cost.`,
    );
  }
  const matches = items.filter((it) => it.label === label);
  if (matches.length === 0) {
    throw new VaultError('vault_label_not_found', `No vault item with label "${label}".`);
  }
  if (matches.length > 1) {
    matches.sort((a, b) => (b.created_at ?? '').localeCompare(a.created_at ?? ''));
  }
  return matches[0]!.id;
}

async function decryptItem(item: VaultItemFull, password: string): Promise<string> {
  const salt = hexToBytes(item.salt);
  const iv = hexToBytes(item.iv);
  const encrypted = hexToBytes(item.encryptedData);
  // Never trust server-supplied crypto params. A malicious or buggy server
  // returning a wrong-length salt/IV would otherwise make createDecipheriv throw
  // a native TypeError (ERR_CRYPTO_INVALID_IV) that escapes the VaultError
  // typed-catch contract callers rely on. Fail with a typed error instead.
  if (salt.length !== 32) {
    throw new VaultError(
      'vault_invalid_crypto_params',
      `Server returned salt of ${salt.length} bytes, expected 32.`,
    );
  }
  if (iv.length !== 16) {
    throw new VaultError(
      'vault_invalid_crypto_params',
      `Server returned IV of ${iv.length} bytes, expected 16.`,
    );
  }
  const keyBytes = await deriveKey(password, salt);
  const decipher = createDecipheriv('aes-256-ctr', keyBytes, iv);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return decrypted.toString('utf8');
}

/**
 * Retrieve a stored credential from the deny.sh managed vault and decrypt it.
 *
 * The password is used to derive an AES-256 key locally; the server never
 * sees the plaintext credential or the password. The resolved credential
 * should be consumed inside a tool boundary (e.g. the `execute` function of
 * a Vercel AI SDK tool) so the LLM never sees it.
 *
 * @param label The vault item label (e.g. 'stripe-prod')
 * @param password The vault wrap password (derives the decryption key)
 * @param opts Optional API key / base URL / fetch override
 * @returns The decrypted credential as a UTF-8 string
 *
 * @throws {VaultError} with .code in:
 *   - vault_missing_api_key
 *   - vault_unauthorized
 *   - vault_not_found
 *   - vault_label_not_found
 *   - vault_label_index_too_large
 *   - vault_http_error
 *   - vault_network_error
 *   - vault_bad_response
 *   - vault_bad_hex
 */
export async function vaultGet(
  label: string,
  password: string,
  opts: VaultGetOptions = {},
): Promise<string> {
  if (!label || typeof label !== 'string') {
    throw new VaultError('vault_bad_label', 'label is required.');
  }
  if (!password || typeof password !== 'string') {
    throw new VaultError('vault_bad_password', 'password is required.');
  }
  const id = await resolveLabel(label, opts);
  const item = await getVaultItem(id, opts);
  return decryptItem(item, password);
}

/**
 * Same as vaultGet() but takes a stable vault item id instead of a label.
 *
 * Skips the /vault/list label-index scan, so this is the recommended path
 * for high-volume agent code or large vaults. Get the id once at deploy
 * time from /dashboard/vault and store it alongside the password env var.
 */
export async function vaultGetById(
  id: string,
  password: string,
  opts: VaultGetOptions = {},
): Promise<string> {
  if (!id || typeof id !== 'string') {
    throw new VaultError('vault_bad_id', 'id is required.');
  }
  if (!password || typeof password !== 'string') {
    throw new VaultError('vault_bad_password', 'password is required.');
  }
  const item = await getVaultItem(id, opts);
  return decryptItem(item, password);
}

/**
 * List vault items (metadata only — no ciphertext, no plaintext, no password
 * needed). Useful for ops tools that need to know what is in the vault
 * without decrypting it.
 */
export async function vaultList(opts: VaultGetOptions = {}): Promise<VaultListItem[]> {
  return listVault(opts);
}
