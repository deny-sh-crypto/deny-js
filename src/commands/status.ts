/**
 * status.ts — deny-sh status
 * Show .deny/ state, control files, vault entries, version.
 */

import { existsSync, readdirSync, statSync, readFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { createHash } from 'node:crypto';
import { banner, bold, dim, green, yellow, red, info, warn } from '../utils/display.js';
import {
  findDenyDir, localDenyDir, readConfig, listControls, VAULT_FILE
} from '../utils/dotdeny.js';

function fileSize(path: string): string {
  try {
    const s = statSync(path);
    if (s.size < 1024) return `${s.size}B`;
    return `${(s.size / 1024).toFixed(1)}KB`;
  } catch { return '?'; }
}

function shortHash(path: string): string {
  try {
    const data = readFileSync(path);
    return createHash('sha256').update(data).digest('hex').slice(0, 8);
  } catch { return '........'; }
}

export async function cmdStatus(_flags: Record<string, string>): Promise<void> {
  banner('Status');

  // Package version — search upward from dist/src/commands/ to find package.json
  try {
    const { fileURLToPath } = await import('node:url');
    const { dirname } = await import('node:path');
    let dir = dirname(fileURLToPath(import.meta.url));
    let pkg: { version: string } | null = null;
    for (let i = 0; i < 5; i++) {
      const candidate = join(dir, 'package.json');
      if (existsSync(candidate)) {
        pkg = JSON.parse(readFileSync(candidate, 'utf8')) as { version: string };
        break;
      }
      dir = join(dir, '..');
    }
    console.log(`  Version: ${pkg ? bold(pkg.version) : dim('unknown')}`);
  } catch {
    console.log(`  Version: ${dim('unknown')}`);
  }
  console.log(`  Node:    ${bold(process.version)}`);
  console.log(`  CWD:     ${dim(process.cwd())}`);
  console.log();

  // .deny/ search
  const local   = localDenyDir();
  const found   = findDenyDir();

  if (!found) {
    warn('.deny/ not found in this directory or any parent.');
    console.log(`  Run ${bold('deny-sh init')} to create one here.`);
    console.log();
    return;
  }

  const isLocal = resolve(found) === resolve(local);
  console.log(`  .deny/ directory: ${green(found)} ${isLocal ? '' : dim('(parent)')}`);

  // Config
  const config = readConfig(found);
  console.log(`  Initialised:      ${dim(config.created ?? 'unknown')}`);
  if (config.project) console.log(`  Project:          ${bold(config.project)}`);
  console.log();

  // Default control file
  const defaultControl = join(found, 'control.dat');
  if (existsSync(defaultControl)) {
    console.log(`  ${green('✓')} Default control.dat  ${dim(fileSize(defaultControl))}  ${dim(shortHash(defaultControl))}`);
  } else {
    console.log(`  ${yellow('○')} No default control.dat`);
  }

  // Named control files
  const controls = listControls(found);
  if (controls.length > 0) {
    console.log(`\n  Named control files (${controls.length}):`);
    for (const name of controls) {
      const path = join(found, 'controls', name);
      console.log(`    ${dim('•')} ${name}  ${dim(fileSize(path))}  ${dim(shortHash(path))}`);
    }
  }

  // Vault
  const vaultPath = join(found, VAULT_FILE);
  if (existsSync(vaultPath)) {
    console.log(`\n  ${green('✓')} Vault exists  ${dim(fileSize(vaultPath))}  ${dim('(encrypted)')}`);
    console.log(`    Use ${bold('deny-sh vault list')} to see entries.`);
  } else {
    console.log(`\n  ${dim('○')} No vault  (deny-sh vault set KEY value to create)`);
  }

  // .env.deny files in cwd
  const envDenyFiles = existsSync(process.cwd())
    ? readdirSync(process.cwd()).filter(f => f.endsWith('.deny'))
    : [];
  if (envDenyFiles.length > 0) {
    console.log(`\n  Encrypted .env files (${envDenyFiles.length}):`);
    for (const f of envDenyFiles) {
      const p = join(process.cwd(), f);
      console.log(`    ${dim('•')} ${f}  ${dim(fileSize(p))}`);
    }
  }

  console.log();
}
