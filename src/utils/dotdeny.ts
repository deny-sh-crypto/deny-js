/**
 * dotdeny.ts — .deny/ directory management utilities
 */

import {
  existsSync, mkdirSync, readFileSync, writeFileSync,
  readdirSync, statSync
} from 'node:fs';
import { join, resolve, dirname } from 'node:path';
import { safeJoin } from './path-safety.js';

export const DENY_DIR = '.deny';
export const CONFIG_FILE = 'config.json';
export const DEFAULT_CONTROL = 'control.dat';
export const VAULT_FILE = 'vault.enc';
export const CONTROLS_DIR = 'controls';

export interface DenyConfig {
  version: string;
  created: string;
  project?: string;
}

// --- Directory Discovery ---

/**
 * Walk up the directory tree to find the nearest .deny/ directory.
 * Returns the absolute path if found, or null.
 */
export function findDenyDir(startDir = process.cwd()): string | null {
  let dir = resolve(startDir);
  while (true) {
    const candidate = join(dir, DENY_DIR);
    if (existsSync(candidate) && statSync(candidate).isDirectory()) {
      return candidate;
    }
    const parent = dirname(dir);
    if (parent === dir) return null; // filesystem root
    dir = parent;
  }
}

/**
 * Get the .deny/ directory in the current working directory (does not search up).
 */
export function localDenyDir(baseDir = process.cwd()): string {
  return join(resolve(baseDir), DENY_DIR);
}

// --- Initialisation ---

/**
 * Ensure .deny/ directory exists, with config.json.
 * Returns the path to the .deny/ directory.
 */
export function ensureDenyDir(baseDir = process.cwd()): string {
  const denyDir = localDenyDir(baseDir);
  if (!existsSync(denyDir)) {
    mkdirSync(denyDir, { recursive: true });
  }
  const configPath = join(denyDir, CONFIG_FILE);
  if (!existsSync(configPath)) {
    const config: DenyConfig = {
      version: '1',
      created: new Date().toISOString(),
    };
    writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf8');
  }
  return denyDir;
}

// --- Config ---

export function readConfig(denyDir: string): DenyConfig {
  const configPath = join(denyDir, CONFIG_FILE);
  if (!existsSync(configPath)) {
    return { version: '1', created: new Date().toISOString() };
  }
  return JSON.parse(readFileSync(configPath, 'utf8')) as DenyConfig;
}

export function writeConfig(denyDir: string, config: DenyConfig): void {
  writeFileSync(join(denyDir, CONFIG_FILE), JSON.stringify(config, null, 2), 'utf8');
}

// --- Control Files ---

export function storeControl(denyDir: string, name: string, data: Uint8Array): string {
  const controlsDir = join(denyDir, CONTROLS_DIR);
  if (!existsSync(controlsDir)) mkdirSync(controlsDir);
  const filePath = safeJoin(controlsDir, name);
  writeFileSync(filePath, data);
  return filePath;
}

export function getControl(denyDir: string, name: string): Uint8Array {
  const controlsDir = join(denyDir, CONTROLS_DIR);
  const filePath = safeJoin(controlsDir, name);
  if (!existsSync(filePath)) throw new Error(`Control file not found: ${filePath}`);
  return new Uint8Array(readFileSync(filePath));
}

export function listControls(denyDir: string): string[] {
  const controlsDir = join(denyDir, CONTROLS_DIR);
  if (!existsSync(controlsDir)) return [];
  return readdirSync(controlsDir).filter(f => f.endsWith('.dat'));
}

export function storeDefaultControl(denyDir: string, data: Uint8Array): string {
  const path = join(denyDir, DEFAULT_CONTROL);
  writeFileSync(path, data);
  return path;
}

export function getDefaultControl(denyDir: string): Uint8Array | null {
  const path = join(denyDir, DEFAULT_CONTROL);
  if (!existsSync(path)) return null;
  return new Uint8Array(readFileSync(path));
}

// --- .gitignore ---

/**
 * Ensure .deny/ is in the nearest .gitignore. Creates one if missing.
 * Returns true if a change was made.
 */
export function ensureGitignore(baseDir = process.cwd()): boolean {
  const gitignorePath = join(resolve(baseDir), '.gitignore');
  const entry = '.deny/';

  if (existsSync(gitignorePath)) {
    const content = readFileSync(gitignorePath, 'utf8');
    if (content.split('\n').some(line => line.trim() === entry || line.trim() === '.deny')) {
      return false; // already present
    }
    writeFileSync(gitignorePath, content.endsWith('\n') ? `${content}${entry}\n` : `${content}\n${entry}\n`, 'utf8');
  } else {
    writeFileSync(gitignorePath, `${entry}\n`, 'utf8');
  }
  return true;
}
