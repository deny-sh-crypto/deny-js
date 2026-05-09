/**
 * init.ts — deny-sh init
 * Creates .deny/ directory structure in the current project.
 */

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import { generateControlData } from '../index.js';
import {
  ensureDenyDir, ensureGitignore, storeDefaultControl,
  listControls, localDenyDir
} from '../utils/dotdeny.js';
import { banner, success, warn, info, step } from '../utils/display.js';
import { confirm } from '../utils/prompts.js';

export async function cmdInit(_flags: Record<string, string>): Promise<void> {
  banner('Project Initialisation');

  const denyPath = localDenyDir();

  if (existsSync(denyPath)) {
    warn(`.deny/ already exists at ${denyPath}`);
    const controls = listControls(denyPath);
    info(`  ${controls.length} named control file(s) found`);
    const proceed = await confirm('Re-initialise anyway?', false);
    if (!proceed) {
      console.log('  Cancelled.');
      return;
    }
  }

  // Create .deny/ with config
  const denyDir = ensureDenyDir();
  success(`Created ${join(denyDir, '')}`);

  // Generate a default control file
  const defaultControlPath = join(denyDir, 'control.dat');
  if (!existsSync(defaultControlPath)) {
    const controlData = generateControlData(1024);
    storeDefaultControl(denyDir, controlData);
    step(`Generated control.dat (1024 bytes of random data)`);
  }

  // Ensure .gitignore
  const changed = ensureGitignore();
  if (changed) {
    success('Added .deny/ to .gitignore');
  } else {
    info('.gitignore already contains .deny/');
  }

  console.log();
  success('Project initialised.');
  console.log();
  console.log('  Next steps:');
  console.log('    deny-sh env protect .env        — encrypt your .env file');
  console.log('    deny-sh vault set MY_KEY value  — store a secret in the vault');
  console.log('    deny-sh protect                 — protect a seed phrase');
  console.log();
  warn('Back up .deny/control.dat separately from any encrypted files!');
  console.log();
}
