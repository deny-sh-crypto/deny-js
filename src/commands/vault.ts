/**
 * vault.ts — deny-sh vault
 * Local encrypted key-value store using .deny/vault.enc
 */

import { existsSync, writeFileSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { randomBytes, createCipheriv, createDecipheriv, scryptSync } from 'node:crypto';
import { banner, success, warn, info, step, table, bold, dim, red, green } from '../utils/display.js';
import { hiddenInput, confirmedPassword } from '../utils/prompts.js';
import { findDenyDir, ensureDenyDir, ensureGitignore, VAULT_FILE } from '../utils/dotdeny.js';

// --- Vault format ---
// File = Salt(32) + IV(16) + AES-256-CTR(JSON)
// JSON = { entries: { KEY: { value, created, updated, type } } }

interface VaultEntry {
  value: string;
  created: string;
  updated: string;
  type: string; // 'string' | 'seed' | etc.
}

interface VaultData {
  entries: Record<string, VaultEntry>;
}

const SALT_LEN = 32;
const IV_LEN = 16;

function deriveVaultKey(password: string, salt: Buffer): Buffer {
  return scryptSync(password, salt, 32, { N: 2 ** 14, r: 8, p: 1 }) as Buffer;
}

function encryptVault(data: VaultData, password: string): Buffer {
  const salt = randomBytes(SALT_LEN);
  const iv   = randomBytes(IV_LEN);
  const key  = deriveVaultKey(password, salt);
  const json = Buffer.from(JSON.stringify(data), 'utf8');
  const cipher = createCipheriv('aes-256-ctr', key, iv);
  const encrypted = Buffer.concat([cipher.update(json), cipher.final()]);
  return Buffer.concat([salt, iv, encrypted]);
}

function decryptVault(raw: Buffer, password: string): VaultData {
  const salt = raw.subarray(0, SALT_LEN);
  const iv   = raw.subarray(SALT_LEN, SALT_LEN + IV_LEN);
  const data = raw.subarray(SALT_LEN + IV_LEN);
  const key  = deriveVaultKey(password, salt);
  const decipher = createDecipheriv('aes-256-ctr', key, iv);
  const json = Buffer.concat([decipher.update(data), decipher.final()]).toString('utf8');
  return JSON.parse(json) as VaultData;
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
    return decryptVault(raw, password);
  } catch {
    console.error(`  ${red('✗')} Wrong vault password or corrupted vault.`);
    process.exit(1);
  }
}

function saveVault(vaultPath: string, data: VaultData, password: string): void {
  const encrypted = encryptVault(data, password);
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

  saveVault(vaultPath, vault, password);
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
  saveVault(vaultPath, vault, password);
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
