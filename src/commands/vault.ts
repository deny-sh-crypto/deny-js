/**
 * vault.ts — deny-sh vault
 * Local encrypted key-value store using .deny/vault.enc
 */

import { existsSync, writeFileSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { randomBytes, createCipheriv, createDecipheriv } from 'node:crypto';
import { argon2id } from 'hash-wasm';
import { banner, success, warn, info, step, table, bold, dim, red, green } from '../utils/display.js';
import { hiddenInput, confirmedPassword } from '../utils/prompts.js';
import { findDenyDir, ensureDenyDir, ensureGitignore, VAULT_FILE } from '../utils/dotdeny.js';

// --- Vault format ---
// Version 0x03 (current) = Argon2id + AES-256-GCM (authenticated)
//   File = Version(1) + Salt(32) + IV(12) + Tag(16) + AES-256-GCM(JSON)
// Version 0x02 (legacy, read-only) = Argon2id + AES-256-CTR (unauthenticated)
//   File = Version(1) + Salt(32) + IV(16) + AES-256-CTR(JSON)
// Argon2id params (both versions): t=3, m=64 MiB, p=1.
// JSON = { entries: { KEY: { value, created, updated, type } } }
// GCM adds integrity: a tampered vault file fails decryption loudly instead of
// silently returning corrupted JSON (CTR was malleable). Old 0x02 files still
// open via the read-compat path below and are re-written as 0x03 on next save.

interface VaultEntry {
  value: string;
  created: string;
  updated: string;
  type: string; // 'string' | 'seed' | etc.
}

interface VaultData {
  entries: Record<string, VaultEntry>;
}

const VAULT_VERSION = 0x03;       // current: Argon2id + AES-256-GCM
const VAULT_VERSION_LEGACY = 0x02; // legacy read-only: Argon2id + AES-256-CTR
const SALT_LEN = 32;
const GCM_IV_LEN = 12;             // 96-bit nonce, standard for GCM
const GCM_TAG_LEN = 16;            // 128-bit auth tag
const CTR_IV_LEN = 16;             // legacy CTR IV
const GCM_HEADER_LEN = 1 + SALT_LEN + GCM_IV_LEN + GCM_TAG_LEN; // version+salt+iv+tag
const CTR_HEADER_LEN = 1 + SALT_LEN + CTR_IV_LEN;               // legacy version+salt+iv

async function deriveVaultKey(password: string, salt: Buffer): Promise<Uint8Array> {
  return argon2id({
    password: Buffer.from(password, 'utf8'),
    salt,
    parallelism: 1,
    iterations: 3,
    memorySize: 65536, // 64 MiB in KiB
    hashLength: 32,
    outputType: 'binary',
  });
}

export async function encryptVault(data: VaultData, password: string): Promise<Buffer> {
  // Always write the current authenticated GCM format (0x03).
  const salt = randomBytes(SALT_LEN);
  const iv   = randomBytes(GCM_IV_LEN);
  const key  = await deriveVaultKey(password, salt);
  const json = Buffer.from(JSON.stringify(data), 'utf8');
  const cipher = createCipheriv('aes-256-gcm', Buffer.from(key), iv);
  const encrypted = Buffer.concat([cipher.update(json), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([
    Buffer.from([VAULT_VERSION]),
    salt,
    iv,
    tag,
    encrypted,
  ]);
}

export async function decryptVault(raw: Buffer, password: string): Promise<VaultData> {
  if (raw.length < 1) {
    throw new Error('vault file too short');
  }
  const version = raw[0]!;

  if (version === VAULT_VERSION) {
    // 0x03 — authenticated GCM
    if (raw.length < GCM_HEADER_LEN) {
      throw new Error('vault file too short');
    }
    const salt = raw.subarray(1, 1 + SALT_LEN);
    const iv   = raw.subarray(1 + SALT_LEN, 1 + SALT_LEN + GCM_IV_LEN);
    const tag  = raw.subarray(1 + SALT_LEN + GCM_IV_LEN, GCM_HEADER_LEN);
    const data = raw.subarray(GCM_HEADER_LEN);
    const key  = await deriveVaultKey(password, salt);
    const decipher = createDecipheriv('aes-256-gcm', Buffer.from(key), iv);
    decipher.setAuthTag(tag);
    // GCM .final() throws if the tag does not verify (wrong password OR tampered
    // ciphertext) — that's the integrity guarantee CTR lacked.
    const json = Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
    return JSON.parse(json) as VaultData;
  }

  if (version === VAULT_VERSION_LEGACY) {
    // 0x02 — legacy unauthenticated CTR, read-only for backward compat.
    // Re-saving the vault upgrades it to 0x03 (authenticated) on next write.
    if (raw.length < CTR_HEADER_LEN) {
      throw new Error('vault file too short');
    }
    const salt = raw.subarray(1, 1 + SALT_LEN);
    const iv   = raw.subarray(1 + SALT_LEN, CTR_HEADER_LEN);
    const data = raw.subarray(CTR_HEADER_LEN);
    const key  = await deriveVaultKey(password, salt);
    const decipher = createDecipheriv('aes-256-ctr', Buffer.from(key), iv);
    const json = Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
    return JSON.parse(json) as VaultData;
  }

  throw new Error(`unsupported vault version: 0x${version.toString(16).padStart(2, '0')}`);
}

function getVaultPath(): string {
  const denyDir = findDenyDir() ?? ensureDenyDir();
  return join(denyDir, VAULT_FILE);
}

function detectType(value: string): string {
  const words = value.trim().split(/\s+/).filter(Boolean);
  if ([12, 15, 18, 21, 24].includes(words.length)) return 'seed';
  if (/^[A-Za-z0-9+/]{40,}={0,2}$/.test(value)) return 'token';
  return 'string';
}

async function loadVault(vaultPath: string, password: string): Promise<VaultData> {
  if (!existsSync(vaultPath)) return { entries: {} };
  const raw = readFileSync(vaultPath);
  try {
    return await decryptVault(raw, password);
  } catch (e: unknown) {
    const msg =
      e instanceof Error && e.message.startsWith('unsupported vault version')
        ? `${e.message}. You may be running an older deny-sh. Try upgrading.`
        : 'Wrong vault password or corrupted vault.';
    console.error(`  ${red('✗')} ${msg}`);
    process.exit(1);
  }
}

async function saveVault(vaultPath: string, data: VaultData, password: string): Promise<void> {
  const encrypted = await encryptVault(data, password);
  writeFileSync(vaultPath, encrypted);
}

// --- Commands ---

async function cmdVaultSet(key: string, value: string): Promise<void> {
  if (!key) { console.error('  Usage: deny-sh vault set KEY value'); process.exit(1); }
  if (!value) { console.error('  Usage: deny-sh vault set KEY value'); process.exit(1); }

  const vaultPath = getVaultPath();
  const isNew = !existsSync(vaultPath);

  let password: string;
  if (isNew) {
    console.log(`  Creating new vault. Set a master password.`);
    password = await confirmedPassword('  Master password: ', '  Confirm:         ');
  } else {
    password = await hiddenInput('  Vault password: ');
    process.stdout.write('\n');
  }

  const vault = await loadVault(vaultPath, password);
  const now = new Date().toISOString();
  const type = detectType(value);

  vault.entries[key] = {
    value,
    created: vault.entries[key]?.created ?? now,
    updated: now,
    type,
  };

  await saveVault(vaultPath, vault, password);
  success(`Stored: ${bold(key)} (${type})`);

  // Ensure gitignore
  const denyDir = findDenyDir() ?? ensureDenyDir();
  const base = resolve(denyDir, '..');
  ensureGitignore(base);
}

async function cmdVaultGet(key: string): Promise<void> {
  if (!key) { console.error('  Usage: deny-sh vault get KEY'); process.exit(1); }

  const vaultPath = getVaultPath();
  if (!existsSync(vaultPath)) {
    console.error('  No vault found. Run: deny-sh vault set KEY value');
    process.exit(1);
  }

  const password = await hiddenInput('  Vault password: ');
  process.stdout.write('\n');

  const vault = await loadVault(vaultPath, password);
  const entry = vault.entries[key];

  if (!entry) {
    console.error(`  Key not found: ${key}`);
    process.exit(1);
  }

  console.log(entry.value);
}

async function cmdVaultList(): Promise<void> {
  const vaultPath = getVaultPath();
  if (!existsSync(vaultPath)) {
    info('Vault is empty. Use: deny-sh vault set KEY value');
    return;
  }

  const password = await hiddenInput('  Vault password: ');
  process.stdout.write('\n\n');

  const vault = await loadVault(vaultPath, password);
  const entries = Object.entries(vault.entries);

  if (entries.length === 0) {
    info('Vault is empty.');
    return;
  }

  console.log(`  ${bold(String(entries.length))} entry(s) in vault:\n`);
  table(
    ['KEY', 'TYPE', 'UPDATED'],
    entries.map(([k, v]) => [k, v.type, v.updated.slice(0, 10)])
  );
  console.log();
}

async function cmdVaultDelete(key: string): Promise<void> {
  if (!key) { console.error('  Usage: deny-sh vault delete KEY'); process.exit(1); }

  const vaultPath = getVaultPath();
  if (!existsSync(vaultPath)) {
    console.error('  No vault found.');
    process.exit(1);
  }

  const password = await hiddenInput('  Vault password: ');
  process.stdout.write('\n');

  const vault = await loadVault(vaultPath, password);
  if (!vault.entries[key]) {
    console.error(`  Key not found: ${key}`);
    process.exit(1);
  }

  delete vault.entries[key];
  await saveVault(vaultPath, vault, password);
  success(`Deleted: ${bold(key)}`);
}

// --- Dispatch ---

export async function cmdVault(args: string[], _flags: Record<string, string>): Promise<void> {
  const sub  = args[0];
  const key  = args[1] ?? '';
  const value = args.slice(2).join(' '); // allow spaces in value

  switch (sub) {
    case 'set':    await cmdVaultSet(key, value); break;
    case 'get':    await cmdVaultGet(key); break;
    case 'list':   await cmdVaultList(); break;
    case 'delete':
    case 'rm':     await cmdVaultDelete(key); break;
    default:
      console.log(`
deny-sh vault — encrypted key-value store

Usage:
  deny-sh vault set KEY value    Store a secret
  deny-sh vault get KEY          Retrieve a secret (prompts for password)
  deny-sh vault list             List all keys
  deny-sh vault delete KEY       Remove a key

Storage: .deny/vault.enc (AES-256, master password protected)
`);
  }
}
