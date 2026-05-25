/**
 * env.ts — deny-sh env protect / env restore
 * Encrypt and restore .env files.
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve, basename, dirname, join } from 'node:path';
import { encrypt, decrypt, generateControlData } from '../index.js';
import {
  banner, success, warn, info, step, bold, dim, progressBar
} from '../utils/display.js';
import { confirmedPassword, hiddenInput } from '../utils/prompts.js';
import { ensureDenyDir, ensureGitignore, storeDefaultControl, getDefaultControl } from '../utils/dotdeny.js';

async function animateProgress(label: string): Promise<void> {
  process.stdout.write('\n');
  for (const pct of [0, 20, 45, 70, 90, 100]) {
    process.stdout.write(`\r  ${label} ${progressBar(pct)}   `);
    await new Promise(r => setTimeout(r, 60));
  }
  process.stdout.write('\n');
}

export async function cmdEnvProtect(flags: Record<string, string>): Promise<void> {
  banner('Environment File Protector');

  const envPath = flags['_arg'] || flags['f'] || '.env';
  const resolvedEnv = resolve(envPath);

  if (!existsSync(resolvedEnv)) {
    console.error(`  Error: File not found: ${resolvedEnv}`);
    process.exit(1);
  }

  const envContent = readFileSync(resolvedEnv, 'utf8');
  const vars = envContent.split('\n').filter(l => l.trim() && !l.startsWith('#'));
  info(`Found ${vars.length} variable(s) in ${envPath}`);
  console.log();

  // Passwords
  const pw1 = await confirmedPassword('  Enter password 1: ', '  Confirm:          ');
  const pw2 = await confirmedPassword('  Enter password 2: ', '  Confirm:          ');
  console.log();

  await animateProgress('Encrypting');

  const plaintext = new TextEncoder().encode(envContent);
  const controlData = generateControlData(Math.max(plaintext.length + 4, 256));
  const { ciphertext } = await encrypt(plaintext, { password1: pw1, password2: pw2, controlData });

  // Output paths
  const envDir   = dirname(resolvedEnv);
  const baseName = basename(envPath);
  const denyFile = resolve(envDir, `${baseName}.deny`);

  writeFileSync(denyFile, ciphertext);

  // Store control file in .deny/
  const denyDir = ensureDenyDir(envDir);
  storeDefaultControl(denyDir, controlData);

  const controlPath = join(denyDir, 'control.dat');
  success(`Created: ${bold(denyFile)}`);
  step(`Control file: ${bold(controlPath)}`);
  console.log();

  // Gitignore
  const changed = ensureGitignore(envDir);
  if (changed) success('Added .deny/ to .gitignore');
  else info('.gitignore already contains .deny/');

  console.log();
  warn('Back up control.dat separately from .env.deny!');
  console.log();
  console.log(`  Restore with: ${dim(`deny-sh env restore ${denyFile}`)}`);
  console.log();
}

export async function cmdEnvRestore(flags: Record<string, string>): Promise<void> {
  banner('Environment File Restore');

  const denyFile = flags['_arg'] || flags['f'] || '.env.deny';
  const resolvedDeny = resolve(denyFile);

  if (!existsSync(resolvedDeny)) {
    console.error(`  Error: File not found: ${resolvedDeny}`);
    process.exit(1);
  }

  // Look for control file
  const envDir = dirname(resolvedDeny);
  const denyDir = join(envDir, '.deny');
  const controlData = getDefaultControl(denyDir);

  if (!controlData) {
    // Try explicit -c flag
    const controlPath = flags['c'];
    if (!controlPath || !existsSync(controlPath)) {
      console.error(`  Error: Control file not found at ${denyDir}/control.dat`);
      console.error(`  Pass -c <control.dat> to specify manually.`);
      process.exit(1);
    }
  }

  const control = controlData ?? new Uint8Array(readFileSync(resolve(flags['c']!)));

  const pw1 = await hiddenInput('  Enter password 1: ');
  process.stdout.write('\n');
  const pw2 = await hiddenInput('  Enter password 2: ');
  process.stdout.write('\n\n');

  const ciphertext = new Uint8Array(readFileSync(resolvedDeny));

  let plaintext: Uint8Array;
  try {
    const result = await decrypt(ciphertext, { password1: pw1, password2: pw2, controlData: control });
    plaintext = result.plaintext;
  } catch (e) {
    console.error(`  Error: Decryption failed — wrong password or control file?`);
    process.exit(1);
  }

  const envContent = new TextDecoder().decode(plaintext);

  // Determine output path
  let outPath = flags['o'];
  if (!outPath) {
    // Strip .deny suffix
    outPath = resolvedDeny.replace(/\.deny$/, '');
    if (outPath === resolvedDeny) outPath = resolvedDeny + '.restored';
  }

  writeFileSync(outPath, envContent, 'utf8');

  const vars = envContent.split('\n').filter(l => l.trim() && !l.startsWith('#'));
  success(`Restored: ${bold(outPath)} (${vars.length} variable(s))`);
  console.log();
}

export async function cmdEnv(args: string[], flags: Record<string, string>): Promise<void> {
  const sub = args[0];
  if (sub === 'protect') {
    flags['_arg'] = args[1] ?? '';
    await cmdEnvProtect(flags);
  } else if (sub === 'restore') {
    flags['_arg'] = args[1] ?? '';
    await cmdEnvRestore(flags);
  } else {
    console.log(`
deny-sh env — .env file protection

Usage:
  deny-sh env protect .env         Encrypt .env → .env.deny + .deny/control.dat
  deny-sh env restore .env.deny    Decrypt .env.deny → .env

Options:
  -o   Output path (restore only, default: strips .deny suffix)
  -c   Control file path (restore only, if not in .deny/)
`);
  }
}
