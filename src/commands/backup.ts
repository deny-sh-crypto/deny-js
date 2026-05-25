/**
 * backup.ts — Cloud backup command for deny-sh
 *
 * Subcommands:
 *   push   — Encrypt and push .deny/ contents to a backup destination
 *   pull   — Download and restore a backup to .deny/
 *   list   — List available backups from a provider
 *   config — Configure backup provider and credentials
 *   auto   — Enable/disable automatic backup after every encrypt
 */

import * as crypto  from 'node:crypto';
import * as fs      from 'node:fs';
import * as os      from 'node:os';
import * as path    from 'node:path';
import { argon2id } from 'hash-wasm';
import { spawnSync } from 'node:child_process';

import { validateS3Bucket, validateRcloneRemote, validateFilePath } from '../utils/exec-safety.js';
import { safeResolve } from '../utils/path-safety.js';

import {
  banner, success, warn, info, step, error as err,
  bold, dim, green, yellow, cyan, table,
} from '../utils/display.js';

import { findDenyDir, localDenyDir, DENY_DIR } from '../utils/dotdeny.js';
import { textInput, confirm, hiddenInput, confirmedPassword } from '../utils/prompts.js';

// ─── Types ──────────────────────────────────────────────────────────────────

interface ManifestEntry {
  path: string;
  size: number;
}

interface BackupManifest {
  version:  number;
  created:  string;
  hostname: string;
  files:    ManifestEntry[];
}

interface BackupConfig {
  provider:      'local' | 'gdrive' | 'dropbox' | 's3';
  localPath:     string;
  s3Bucket:      string;
  s3Prefix:      string;
  rcloneRemote:  string;
  autoBackup:    boolean;
  maxBackups:    number;
}

interface ParsedBackup {
  filename:  string;
  manifest:  BackupManifest;
  sizeBytes: number;
}

// ─── Constants ───────────────────────────────────────────────────────────────

const BACKUP_CONFIG_FILE   = 'backup-config.json';
const AUTO_BACKUP_FLAG     = 'auto-backup.flag';
const BACKUP_MAGIC         = 'DENY_BACKUP_V1';
const BACKUP_EXT           = '.deny-backup';
const BACKUP_ENC_EXT       = '.enc';
const DEFAULT_LOCAL_PATH   = path.join(os.homedir(), '.deny-backups');

const DEFAULT_CONFIG: BackupConfig = {
  provider:     'local',
  localPath:    DEFAULT_LOCAL_PATH,
  s3Bucket:     '',
  s3Prefix:     'deny-sh/',
  rcloneRemote: '',
  autoBackup:   false,
  maxBackups:   10,
};

// ─── Entry point ─────────────────────────────────────────────────────────────

export async function cmdBackup(
  subArgs: string[],
  flags: Record<string, string>,
): Promise<void> {
  const subCmd = subArgs[0];

  switch (subCmd) {
    case 'push':   return cmdPush(flags);
    case 'pull':   return cmdPull(flags);
    case 'list':   return cmdList(flags);
    case 'config': return cmdConfig();
    case 'auto':   return cmdAuto(flags);
    default:
      banner('deny-sh backup');
      console.log('');
      console.log('  Backup your .deny/ control files to keep them safe.\n');
      console.log(`  ${bold('Commands:')}`);
      console.log(`    ${cyan('push')}   ${dim('Encrypt and upload .deny/ to backup storage')}`);
      console.log(`    ${cyan('pull')}   ${dim('Restore .deny/ from a backup')}`);
      console.log(`    ${cyan('list')}   ${dim('List available backups')}`);
      console.log(`    ${cyan('config')} ${dim('Configure backup provider and credentials')}`);
      console.log(`    ${cyan('auto')}   ${dim('Enable/disable auto-backup after encrypt')}`);
      console.log('');
      console.log(`  ${bold('Flags:')}`);
      console.log(`    ${cyan('--provider')} ${dim('gdrive | dropbox | s3 | local')}`);
      console.log(`    ${cyan('--dest')}     ${dim('Destination path (push/local)')}`);
      console.log(`    ${cyan('--src')}      ${dim('Source path or backup filename (pull)')}`);
      console.log('');
      break;
  }
}

// ─── PUSH ─────────────────────────────────────────────────────────────────────

async function cmdPush(flags: Record<string, string>): Promise<void> {
  banner('deny-sh backup push');

  const denyDir = findDenyDir();
  if (!denyDir) {
    err('No .deny/ directory found. Run `deny-sh init` first.');
    process.exit(1);
  }

  const cfg    = loadBackupConfig(denyDir);
  const prov   = (flags['provider'] ?? cfg.provider) as BackupConfig['provider'];
  const dest   = flags['dest'] ?? undefined;

  info(`Backing up ${bold(denyDir)} → ${bold(prov)}`);
  console.log('');

  // Collect files
  step('Collecting files from .deny/ ...');
  const files = collectDenyFiles(denyDir);
  if (files.length === 0) {
    warn('Nothing to back up — .deny/ appears empty.');
    return;
  }
  files.forEach(f => step(`  ${dim(f)}`));
  console.log('');

  // Prompt for backup password
  const password = await confirmedPassword(
    '  Backup password: ',
    '  Confirm password: ',
  );
  console.log('');

  // Build bundle
  step('Building encrypted backup bundle ...');
  const bundle    = buildBundle(denyDir, files);
  const encrypted = await encryptBundle(bundle, password);
  const filename  = backupFilename();

  // Upload
  step(`Uploading as ${bold(filename)} ...`);
  switch (prov) {
    case 'local':   await pushLocal(encrypted, filename, dest ?? cfg.localPath); break;
    case 'gdrive':  await pushGDrive(encrypted, filename); break;
    case 'dropbox': await pushDropbox(encrypted, filename, cfg.rcloneRemote); break;
    case 's3':      await pushS3(encrypted, filename, cfg.s3Bucket, cfg.s3Prefix); break;
    default:
      err(`Unknown provider: ${prov}`);
      process.exit(1);
  }

  // Prune old local backups
  if (prov === 'local') {
    pruneLocalBackups(dest ?? cfg.localPath, cfg.maxBackups);
  }

  console.log('');
  success(`Backup complete → ${bold(filename)}`);
  info(`${files.length} file(s) backed up, ${fmtBytes(encrypted.length)} encrypted.`);
}

// ─── PULL ─────────────────────────────────────────────────────────────────────

async function cmdPull(flags: Record<string, string>): Promise<void> {
  banner('deny-sh backup pull');

  const denyDir = localDenyDir();
  const cfg     = loadBackupConfig(findDenyDir() ?? denyDir);
  const prov    = (flags['provider'] ?? cfg.provider) as BackupConfig['provider'];
  const src     = flags['src'] ?? undefined;

  // Resolve the backup file
  let encryptedData: Buffer;
  let backupFile: string;

  if (src && fs.existsSync(src)) {
    // Direct file path provided
    backupFile    = src;
    encryptedData = fs.readFileSync(src);
  } else {
    // List and let user pick
    info(`Fetching backup list from ${bold(prov)} ...`);
    const backups = await listBackups(prov, cfg, src);

    if (backups.length === 0) {
      warn('No backups found.');
      return;
    }

    // Show options
    console.log('');
    console.log(`  ${bold('Available backups:')}`);
    backups.forEach((b, i) => {
      const fileCount = b.manifest.files.length;
      const created   = new Date(b.manifest.created).toLocaleString();
      console.log(
        `  ${cyan(`${i + 1}.`)} ${b.filename}  ${dim(created)}  ${dim(`${fileCount} files, ${fmtBytes(b.sizeBytes)}`)}`,
      );
    });
    console.log('');

    let picked: ParsedBackup;
    if (backups.length === 1) {
      picked = backups[0];
      info(`Using ${bold(picked.filename)}`);
    } else {
      const choice = await textInput('  Select backup number: ', v => {
        const n = parseInt(v, 10);
        return (n >= 1 && n <= backups.length) ? null : `Enter 1–${backups.length}`;
      });
      picked = backups[parseInt(choice, 10) - 1];
    }

    backupFile    = await downloadBackup(prov, picked.filename, cfg);
    encryptedData = fs.readFileSync(backupFile);
  }

  console.log('');
  const password = await hiddenInput('  Backup password: ');
  process.stdout.write('\n');

  // Decrypt
  step('Decrypting backup ...');
  let bundle: string;
  try {
    bundle = await decryptBundle(encryptedData, password);
  } catch (e: unknown) {
    if (e instanceof Error && e.message.startsWith('unsupported backup version')) {
      err(e.message + ' — you may be running an older deny-sh. Try upgrading.');
    } else {
      err('Decryption failed — wrong password, or the file is corrupted.');
    }
    info(`Backup file: ${backupFile}`);
    info('Try again with the correct password, or restore from a different backup.');
    process.exit(1);
  }

  // Parse and validate
  let manifest: BackupManifest;
  let fileBlocks: string[];
  try {
    const parsed = parseBundle(bundle);
    manifest   = parsed.manifest;
    fileBlocks = parsed.fileBlocks;
  } catch (e: any) {
    err(`Backup file appears corrupted: ${e.message}`);
    info(`Backup file: ${backupFile}`);
    info('Try restoring from a different backup.');
    process.exit(1);
  }

  // Confirm restore
  console.log('');
  info(`This backup contains ${bold(String(manifest.files.length))} file(s) from ${bold(new Date(manifest.created).toLocaleString())}`);
  info(`Host: ${manifest.hostname}`);
  console.log('');

  const ok = await confirm(
    `  Restore to ${bold(denyDir)}? This will OVERWRITE existing .deny/ files.`,
    false,
  );
  if (!ok) {
    warn('Restore cancelled.');
    return;
  }

  // Write files
  step('Restoring files ...');
  restoreBundle(denyDir, manifest, fileBlocks);

  console.log('');
  success(`Restored ${manifest.files.length} file(s) to ${bold(denyDir)}`);
}

// ─── LIST ─────────────────────────────────────────────────────────────────────

async function cmdList(flags: Record<string, string>): Promise<void> {
  banner('deny-sh backup list');

  const denyDir = findDenyDir();
  const cfg     = loadBackupConfig(denyDir ?? '');
  const prov    = (flags['provider'] ?? cfg.provider) as BackupConfig['provider'];
  const src     = flags['src'] ?? undefined;

  info(`Listing backups from ${bold(prov)} ...`);
  console.log('');

  const backups = await listBackups(prov, cfg, src);

  if (backups.length === 0) {
    warn('No backups found.');
    return;
  }

  table(
    ['#', 'Filename', 'Created', 'Files', 'Size'],
    backups.map((b, i) => [
      String(i + 1),
      b.filename,
      new Date(b.manifest.created).toLocaleString(),
      String(b.manifest.files.length),
      fmtBytes(b.sizeBytes),
    ]),
  );

  console.log('');
  info(`${backups.length} backup(s) total.`);
}

// ─── CONFIG ───────────────────────────────────────────────────────────────────

async function cmdConfig(): Promise<void> {
  banner('deny-sh backup config');

  const denyDir = findDenyDir();
  if (!denyDir) {
    err('No .deny/ directory found. Run `deny-sh init` first.');
    process.exit(1);
  }

  const cfg = loadBackupConfig(denyDir);

  console.log('');
  info('Configure your backup provider. Press Enter to keep current value.');
  console.log('');

  // Provider
  const prov = await textInput(
    `  Provider [${cyan(cfg.provider)}] (local/gdrive/dropbox/s3): `,
    v => {
      if (!v) return null;
      return ['local', 'gdrive', 'dropbox', 's3'].includes(v) ? null : 'Enter: local, gdrive, dropbox, or s3';
    },
  );
  if (prov) cfg.provider = prov as BackupConfig['provider'];

  // Provider-specific config
  if (cfg.provider === 'local') {
    const lp = await textInput(`  Local backup path [${cyan(cfg.localPath)}]: `);
    if (lp) cfg.localPath = lp;
  }

  if (cfg.provider === 's3') {
    const bucket = await textInput(`  S3 bucket [${cyan(cfg.s3Bucket || 'none')}]: `);
    if (bucket) cfg.s3Bucket = bucket;
    const prefix = await textInput(`  S3 prefix [${cyan(cfg.s3Prefix)}]: `);
    if (prefix) cfg.s3Prefix = prefix;
  }

  if (cfg.provider === 'gdrive' || cfg.provider === 'dropbox') {
    const remote = await textInput(`  rclone remote name [${cyan(cfg.rcloneRemote || 'none')}] (e.g. "gdrive" or "dropbox"): `);
    if (remote) cfg.rcloneRemote = remote;
  }

  // Max backups
  const maxStr = await textInput(`  Max local backups to keep [${cyan(String(cfg.maxBackups))}]: `);
  if (maxStr && /^\d+$/.test(maxStr)) cfg.maxBackups = parseInt(maxStr, 10);

  // Auto-backup
  const autoStr = (cfg.autoBackup ? 'yes' : 'no');
  const autoAns = await textInput(`  Auto-backup after encrypt? [${cyan(autoStr)}] (yes/no): `);
  if (autoAns === 'yes' || autoAns === 'y') {
    cfg.autoBackup = true;
    enableAutoBackup(denyDir);
  } else if (autoAns === 'no' || autoAns === 'n') {
    cfg.autoBackup = false;
    disableAutoBackup(denyDir);
  }

  saveBackupConfig(denyDir, cfg);
  console.log('');
  success('Backup config saved.');
  showProviderHelp(cfg.provider);
}

// ─── AUTO ─────────────────────────────────────────────────────────────────────

async function cmdAuto(flags: Record<string, string>): Promise<void> {
  banner('deny-sh backup auto');

  const denyDir = findDenyDir();
  if (!denyDir) {
    err('No .deny/ directory found. Run `deny-sh init` first.');
    process.exit(1);
  }

  const cfg = loadBackupConfig(denyDir);

  if ('enable' in flags) {
    enableAutoBackup(denyDir);
    cfg.autoBackup = true;
    saveBackupConfig(denyDir, cfg);
    success('Auto-backup enabled. deny-sh will back up after every encrypt operation.');
    info(`Provider: ${bold(cfg.provider)}`);
  } else if ('disable' in flags) {
    disableAutoBackup(denyDir);
    cfg.autoBackup = false;
    saveBackupConfig(denyDir, cfg);
    success('Auto-backup disabled.');
  } else {
    const flag = path.join(denyDir, AUTO_BACKUP_FLAG);
    const active = fs.existsSync(flag);
    info(`Auto-backup is currently ${active ? green('enabled') : yellow('disabled')}.`);
    console.log('');
    console.log(`  Use ${cyan('--enable')} or ${cyan('--disable')} to change.`);
  }
}

// ─── Bundle building ──────────────────────────────────────────────────────────

function collectDenyFiles(denyDir: string): string[] {
  const result: string[] = [];
  const scanDir = (dir: string, prefix: string) => {
    for (const entry of fs.readdirSync(dir)) {
      // Skip internal config-ish files we'll handle separately, and flag files
      if (entry === BACKUP_CONFIG_FILE || entry === AUTO_BACKUP_FLAG) continue;
      const full = path.join(dir, entry);
      const rel  = prefix ? `${prefix}/${entry}` : entry;
      const st   = fs.statSync(full);
      if (st.isDirectory()) {
        scanDir(full, rel);
      } else {
        result.push(rel);
      }
    }
  };
  scanDir(denyDir, '');
  return result;
}

function buildBundle(denyDir: string, files: string[]): Buffer {
  const entries: ManifestEntry[] = files.map(f => {
    const fullPath = path.join(denyDir, f);
    const size     = fs.statSync(fullPath).size;
    return { path: f, size };
  });

  const manifest: BackupManifest = {
    version:  1,
    created:  new Date().toISOString(),
    hostname: os.hostname(),
    files:    entries,
  };

  const lines: string[] = [BACKUP_MAGIC, JSON.stringify(manifest)];
  for (const f of files) {
    const data = fs.readFileSync(path.join(denyDir, f));
    lines.push(data.toString('base64'));
  }

  return Buffer.from(lines.join('\n'), 'utf8');
}

function parseBundle(bundleText: string): { manifest: BackupManifest; fileBlocks: string[] } {
  const lines = bundleText.split('\n');
  if (lines[0] !== BACKUP_MAGIC) {
    throw new Error('Invalid backup magic header — not a deny-sh backup');
  }
  const manifest: BackupManifest = JSON.parse(lines[1]);
  const fileBlocks = lines.slice(2);
  if (fileBlocks.length !== manifest.files.length) {
    throw new Error(
      `File count mismatch: manifest says ${manifest.files.length}, found ${fileBlocks.length}`,
    );
  }
  return { manifest, fileBlocks };
}

function restoreBundle(denyDir: string, manifest: BackupManifest, fileBlocks: string[]): void {
  fs.mkdirSync(denyDir, { recursive: true });

  manifest.files.forEach((entry, i) => {
    const destPath = safeResolve(denyDir, entry.path);
    fs.mkdirSync(path.dirname(destPath), { recursive: true });
    const data = Buffer.from(fileBlocks[i], 'base64');
    fs.writeFileSync(destPath, data);
    step(`  ${dim(entry.path)} (${fmtBytes(data.length)})`);
  });
}

// ─── Encryption ───────────────────────────────────────────────────────────────

// Version constants for encryptBundle / decryptBundle:
// 0x02 = Argon2id, 16-byte salt (shipped 2026-05-25 in commit 5564687 for ~1 hour;
//        superseded same day. Pre-launch: no real user bundles at this version.)
// 0x03 = Argon2id, 32-byte salt (current, consistent with vault.ts + consumer.ts)
const BUNDLE_VERSION = 0x03;

/**
 * Encrypt a bundle using Argon2id + AES-256-CTR.
 * Output layout: [1 version][32 salt][16 iv][ciphertext]
 * Version 0x03 = Argon2id (t=3, m=64 MiB, p=1), 32-byte salt.
 */
export async function encryptBundle(plaintext: Buffer, password: string): Promise<Buffer> {
  const salt = crypto.randomBytes(32);
  const iv   = crypto.randomBytes(16);
  const key  = await argon2id({
    password: Buffer.from(password, 'utf8'),
    salt,
    parallelism: 1,
    iterations: 3,
    memorySize: 65536,
    hashLength: 32,
    outputType: 'binary',
  });
  const cipher = crypto.createCipheriv('aes-256-ctr', Buffer.from(key), iv);
  const enc  = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return Buffer.concat([Buffer.from([BUNDLE_VERSION]), salt, iv, enc]);
}

/**
 * Decrypt a bundle. Supports version 0x02 (16-byte salt) and 0x03 (32-byte salt).
 * Throws a descriptive error on unknown versions.
 */
export async function decryptBundle(data: Buffer, password: string): Promise<string> {
  const version = data.length > 0 ? data[0]! : 0;
  let salt: Buffer, iv: Buffer, ciphertext: Buffer;
  if (version === 0x03) {
    // Current layout: [0x03][32 salt][16 iv][ciphertext], header = 49 bytes
    if (data.length < 50) throw new Error('Data too short');
    salt       = data.subarray(1, 33);
    iv         = data.subarray(33, 49);
    ciphertext = data.subarray(49);
  } else if (version === 0x02) {
    // Legacy layout (16-byte salt, shipped briefly): [0x02][16 salt][16 iv][ciphertext]
    if (data.length < 34) throw new Error('Data too short');
    salt       = data.subarray(1, 17);
    iv         = data.subarray(17, 33);
    ciphertext = data.subarray(33);
  } else {
    throw new Error(`unsupported backup version: 0x${version.toString(16).padStart(2, '0')}`);
  }
  const key        = await argon2id({
    password: Buffer.from(password, 'utf8'),
    salt,
    parallelism: 1,
    iterations: 3,
    memorySize: 65536,
    hashLength: 32,
    outputType: 'binary',
  });
  const decipher   = crypto.createDecipheriv('aes-256-ctr', Buffer.from(key), iv);
  const plain      = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  const text       = plain.toString('utf8');
  // Validate header early so wrong-password is caught here
  if (!text.startsWith(BACKUP_MAGIC)) {
    throw new Error('Invalid decrypted content: wrong password or corrupted backup');
  }
  return text;
}

// ─── Provider: local ─────────────────────────────────────────────────────────

async function pushLocal(data: Buffer, filename: string, destDir: string): Promise<void> {
  const expanded = destDir.replace(/^~/, os.homedir());
  fs.mkdirSync(expanded, { recursive: true });
  const dest = path.join(expanded, filename);
  fs.writeFileSync(dest, data);
  info(`Saved to ${bold(dest)}`);
}

function pruneLocalBackups(destDir: string, maxBackups: number): void {
  const expanded = destDir.replace(/^~/, os.homedir());
  if (!fs.existsSync(expanded)) return;
  const files = fs.readdirSync(expanded)
    .filter(f => f.startsWith('deny-backup-') && f.endsWith(BACKUP_ENC_EXT))
    .map(f => ({ name: f, mtime: fs.statSync(path.join(expanded, f)).mtimeMs }))
    .sort((a, b) => b.mtime - a.mtime);

  if (files.length > maxBackups) {
    const toDelete = files.slice(maxBackups);
    toDelete.forEach(f => {
      fs.unlinkSync(path.join(expanded, f.name));
      step(`Pruned old backup: ${dim(f.name)}`);
    });
  }
}

async function listLocalBackups(destDir: string): Promise<ParsedBackup[]> {
  const expanded = destDir.replace(/^~/, os.homedir());
  if (!fs.existsSync(expanded)) return [];
  return fs.readdirSync(expanded)
    .filter(f => f.startsWith('deny-backup-') && f.endsWith(BACKUP_ENC_EXT))
    .map(f => {
      const full      = path.join(expanded, f);
      const sizeBytes = fs.statSync(full).size;
      // We can't decrypt without the password at list time, so synthesise a manifest
      const manifest  = inferManifestFromFilename(f, sizeBytes);
      return { filename: f, manifest, sizeBytes };
    })
    .sort((a, b) => b.manifest.created.localeCompare(a.manifest.created));
}

// ─── Provider: Google Drive ───────────────────────────────────────────────────

async function pushGDrive(data: Buffer, filename: string): Promise<void> {
  // Try rclone first, then gdrive
  if (which('rclone')) {
    await uploadViaRclone(data, filename, 'gdrive', 'gdrive:deny.sh Backups');
  } else if (which('gdrive')) {
    await uploadViaGdrive(data, filename);
  } else {
    err('Neither rclone nor gdrive CLI is installed.');
    showProviderHelp('gdrive');
    process.exit(1);
  }
}

async function uploadViaGdrive(data: Buffer, filename: string): Promise<void> {
  const tmpFile = writeTempFile(filename, data);
  validateFilePath(tmpFile);
  try {
    // Get or create the folder
    let folderId: string;
    try {
      const listRes = spawnSync(
        'gdrive',
        ['files', 'list',
          '--query', "name='deny.sh Backups' and mimeType='application/vnd.google-apps.folder'",
          '--field-separator', '|'],
        { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] },
      );
      const res  = listRes.status === 0 ? (listRes.stdout as string) : '';
      const line = res.split('\n').find(l => l.includes('deny.sh Backups'));
      if (line) {
        folderId = line.split('|')[0].trim();
      } else {
        const mkdirRes = spawnSync(
          'gdrive',
          ['files', 'mkdir', 'deny.sh Backups'],
          { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] },
        );
        const created = mkdirRes.status === 0 ? (mkdirRes.stdout as string) : '';
        folderId = created.match(/[0-9A-Za-z_-]{25,}/)?.[0] ?? '';
      }
    } catch {
      folderId = '';
    }
    const uploadArgs = ['files', 'upload', ...(folderId ? ['--parent', folderId] : []), tmpFile];
    const uploadResult = spawnSync('gdrive', uploadArgs, { stdio: 'inherit' });
    if (uploadResult.status !== 0) {
      err('gdrive upload failed. Check your gdrive CLI configuration.');
      process.exit(1);
    }
    info(`Uploaded to Google Drive: deny.sh Backups/${filename}`);
  } finally {
    fs.unlinkSync(tmpFile);
  }
}

// ─── Provider: Dropbox ───────────────────────────────────────────────────────

async function pushDropbox(data: Buffer, filename: string, remote: string): Promise<void> {
  if (!which('rclone')) {
    err('rclone is not installed. Dropbox backup requires rclone.');
    showProviderHelp('dropbox');
    process.exit(1);
  }
  const remoteName = remote || 'dropbox';
  validateRcloneRemote(remoteName);
  await uploadViaRclone(data, filename, remoteName, `${remoteName}:deny.sh-backups`);
}

// ─── Provider: S3 ────────────────────────────────────────────────────────────

async function pushS3(data: Buffer, filename: string, bucket: string, prefix: string): Promise<void> {
  if (!bucket) {
    err('No S3 bucket configured. Run `deny-sh backup config` first.');
    process.exit(1);
  }
  validateS3Bucket(bucket);
  if (!which('aws')) {
    err('AWS CLI is not installed.');
    showProviderHelp('s3');
    process.exit(1);
  }

  const tmpFile = writeTempFile(filename, data);
  try {
    const s3Path = `s3://${bucket}/${prefix.replace(/\/$/, '')}/${filename}`;
    const result = spawnSync('aws', ['s3', 'cp', tmpFile, s3Path], { stdio: 'inherit' });
    if (result.status !== 0) {
      err('AWS S3 upload failed. Check your credentials and bucket name.');
      process.exit(1);
    }
    info(`Uploaded to ${bold(s3Path)}`);
  } finally {
    fs.unlinkSync(tmpFile);
  }
}

async function listS3Backups(bucket: string, prefix: string): Promise<ParsedBackup[]> {
  if (!bucket || !which('aws')) return [];
  try {
    validateS3Bucket(bucket);
    const s3Prefix = `${prefix.replace(/\/$/, '')}/`;
    const lsResult = spawnSync(
      'aws', ['s3', 'ls', `s3://${bucket}/${s3Prefix}`],
      { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] },
    );
    if (lsResult.status !== 0) return [];
    const out = lsResult.stdout as string;
    return out.split('\n')
      .filter(l => l.includes('.enc'))
      .map(line => {
        const parts    = line.trim().split(/\s+/);
        const filename = parts[parts.length - 1];
        const sizeBytes = parseInt(parts[2] ?? '0', 10);
        const manifest  = inferManifestFromFilename(filename, sizeBytes);
        return { filename, manifest, sizeBytes };
      })
      .filter(b => b.filename.startsWith('deny-backup-'))
      .sort((a, b) => b.manifest.created.localeCompare(a.manifest.created));
  } catch {
    return [];
  }
}

// ─── Provider: rclone shared ─────────────────────────────────────────────────

async function uploadViaRclone(data: Buffer, filename: string, remoteName: string, dest: string): Promise<void> {
  const tmpFile = writeTempFile(filename, data);
  try {
    // Ensure destination folder exists
    spawnSync('rclone', ['mkdir', dest], { stdio: 'pipe' });
    const result = spawnSync('rclone', ['copy', tmpFile, dest], { stdio: 'inherit' });
    if (result.status !== 0) {
      err(`rclone upload failed. Check that the remote ${bold(remoteName)} is configured.`);
      err(`Run: rclone config`);
      process.exit(1);
    }
    info(`Uploaded via rclone → ${bold(`${dest}/${filename}`)}`);
  } finally {
    fs.unlinkSync(tmpFile);
  }
}

async function listRcloneBackups(remote: string, folder: string): Promise<ParsedBackup[]> {
  if (!which('rclone')) return [];
  try {
    validateRcloneRemote(remote);
    const lslResult = spawnSync(
      'rclone', ['lsl', `${remote}:${folder}`, '--include', 'deny-backup-*.enc'],
      { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] },
    );
    if (lslResult.status !== 0) return [];
    const out = lslResult.stdout as string;
    return out.split('\n')
      .filter(l => l.trim().length > 0)
      .map(line => {
        const parts     = line.trim().split(/\s+/);
        const filename  = parts[parts.length - 1];
        const sizeBytes = parseInt(parts[0] ?? '0', 10);
        const manifest  = inferManifestFromFilename(filename, sizeBytes);
        return { filename, manifest, sizeBytes };
      })
      .sort((a, b) => b.manifest.created.localeCompare(a.manifest.created));
  } catch {
    return [];
  }
}

// ─── List & Download helpers ──────────────────────────────────────────────────

async function listBackups(
  prov: BackupConfig['provider'],
  cfg: BackupConfig,
  srcOverride?: string,
): Promise<ParsedBackup[]> {
  switch (prov) {
    case 'local':
      return listLocalBackups(srcOverride ?? cfg.localPath);
    case 's3':
      return listS3Backups(cfg.s3Bucket, cfg.s3Prefix);
    case 'gdrive': {
      const remote = cfg.rcloneRemote || 'gdrive';
      return listRcloneBackups(remote, 'deny.sh Backups');
    }
    case 'dropbox': {
      const remote = cfg.rcloneRemote || 'dropbox';
      return listRcloneBackups(remote, 'deny.sh-backups');
    }
    default:
      return [];
  }
}

async function downloadBackup(
  prov: BackupConfig['provider'],
  filename: string,
  cfg: BackupConfig,
): Promise<string> {
  const tmpDir = os.tmpdir();
  const dest   = path.join(tmpDir, filename);

  switch (prov) {
    case 'local': {
      const src = path.join(cfg.localPath.replace(/^~/, os.homedir()), filename);
      fs.copyFileSync(src, dest);
      return dest;
    }
    case 's3': {
      const s3Path = `s3://${cfg.s3Bucket}/${cfg.s3Prefix.replace(/\/$/, '')}/${filename}`;
      const result = spawnSync('aws', ['s3', 'cp', s3Path, dest], { stdio: 'inherit' });
      if (result.status !== 0) {
        err('Failed to download from S3.');
        process.exit(1);
      }
      return dest;
    }
    case 'gdrive':
    case 'dropbox': {
      const remote = cfg.rcloneRemote || prov;
      const folder = prov === 'gdrive' ? 'deny.sh Backups' : 'deny.sh-backups';
      const result = spawnSync(
        'rclone', ['copy', `${remote}:${folder}/${filename}`, tmpDir],
        { stdio: 'inherit' },
      );
      if (result.status !== 0) {
        err('Failed to download via rclone.');
        process.exit(1);
      }
      return dest;
    }
    default:
      err(`Unknown provider: ${prov}`);
      process.exit(1);
  }
}

// ─── Config helpers ───────────────────────────────────────────────────────────

function loadBackupConfig(denyDir: string): BackupConfig {
  if (!denyDir) return { ...DEFAULT_CONFIG };
  const cfgFile = path.join(denyDir, BACKUP_CONFIG_FILE);
  if (!fs.existsSync(cfgFile)) return { ...DEFAULT_CONFIG };
  try {
    return { ...DEFAULT_CONFIG, ...JSON.parse(fs.readFileSync(cfgFile, 'utf8')) };
  } catch {
    return { ...DEFAULT_CONFIG };
  }
}

function saveBackupConfig(denyDir: string, cfg: BackupConfig): void {
  const cfgFile = path.join(denyDir, BACKUP_CONFIG_FILE);
  fs.writeFileSync(cfgFile, JSON.stringify(cfg, null, 2), 'utf8');
}

function enableAutoBackup(denyDir: string): void {
  const flag = path.join(denyDir, AUTO_BACKUP_FLAG);
  fs.writeFileSync(flag, new Date().toISOString(), 'utf8');
}

function disableAutoBackup(denyDir: string): void {
  const flag = path.join(denyDir, AUTO_BACKUP_FLAG);
  if (fs.existsSync(flag)) fs.unlinkSync(flag);
}

// ─── Misc helpers ─────────────────────────────────────────────────────────────

function backupFilename(): string {
  const now = new Date();
  const pad = (n: number) => String(n).padStart(2, '0');
  const ts  = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}-` +
               `${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`;
  return `deny-backup-${ts}${BACKUP_ENC_EXT}`;
}

/**
 * Infer a synthetic manifest from a filename when we can't decrypt at list time.
 * filename format: deny-backup-YYYY-MM-DD-HHmmss.enc
 */
function inferManifestFromFilename(filename: string, sizeBytes: number): BackupManifest {
  const match = filename.match(/deny-backup-(\d{4})-(\d{2})-(\d{2})-(\d{2})(\d{2})(\d{2})/);
  let created = new Date().toISOString();
  if (match) {
    const [, y, mo, d, h, mi, s] = match;
    created = `${y}-${mo}-${d}T${h}:${mi}:${s}Z`;
  }
  return {
    version:  1,
    created,
    hostname: '?',
    files:    [{ path: '(encrypted)', size: sizeBytes }],
  };
}

function which(cmd: string): boolean {
  const result = spawnSync('which', [cmd], { stdio: 'pipe' });
  return result.status === 0;
}

function writeTempFile(name: string, data: Buffer): string {
  const tmp = path.join(os.tmpdir(), name);
  fs.writeFileSync(tmp, data);
  return tmp;
}

function fmtBytes(bytes: number): string {
  if (bytes < 1024)        return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
}

function showProviderHelp(provider: BackupConfig['provider']): void {
  console.log('');
  switch (provider) {
    case 'gdrive':
      info('To use Google Drive backups, install rclone:');
      step('https://rclone.org/install/');
      step(`Then run: ${cyan('rclone config')} and add a remote named "gdrive"`);
      step(`Or install the gdrive CLI: ${cyan('https://github.com/prasmussen/gdrive')}`);
      break;
    case 'dropbox':
      info('To use Dropbox backups, install rclone:');
      step('https://rclone.org/install/');
      step(`Then run: ${cyan('rclone config')} and add a remote named "dropbox"`);
      break;
    case 's3':
      info('To use S3 backups, install the AWS CLI:');
      step('https://aws.amazon.com/cli/');
      step(`Then run: ${cyan('aws configure')} to set up credentials`);
      step(`And run: ${cyan('deny-sh backup config')} to set your bucket name`);
      break;
    case 'local':
    default:
      info(`Local backups are stored in ${cyan(DEFAULT_LOCAL_PATH)}`);
      step(`Run ${cyan('deny-sh backup config')} to change the path`);
      break;
  }
}
