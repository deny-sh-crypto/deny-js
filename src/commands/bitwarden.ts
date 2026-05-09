/**
 * bitwarden.ts — Push/pull deny.sh control files to/from Bitwarden vault
 *
 * Usage:
 *   deny-sh bw status          Check bw CLI status
 *   deny-sh bw list            List deny.sh items in vault
 *   deny-sh bw push [name]     Push control file(s) to vault
 *   deny-sh bw pull [name]     Pull control file(s) from vault
 */

import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { join, basename } from 'node:path';
import { safeJoin } from '../utils/path-safety.js';
import {
  banner, success, warn, info, step, error as err,
  bold, dim, green, yellow, cyan, table,
} from '../utils/display.js';
import {
  findDenyDir, listControls, getControl, storeControl,
  getDefaultControl, storeDefaultControl,
  CONTROLS_DIR, DEFAULT_CONTROL,
} from '../utils/dotdeny.js';
import { textInput, confirm } from '../utils/prompts.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

interface BwStatus {
  status: 'unauthenticated' | 'locked' | 'unlocked';
  userEmail?: string;
  userId?: string;
}

interface BwField {
  name: string;
  value: string;
  type: number;
}

interface BwSecureNoteItem {
  id: string;
  name: string;
  notes: string;
  fields: BwField[];
  revisionDate?: string;
}

interface DenyBwItem {
  id: string;
  name: string;           // e.g. "deny.sh: seed-backup"
  controlName: string;    // e.g. "seed-backup"
  created: string;
  type: string;           // "real" | "decoy"
  originalPath: string;
  version?: string;
}

const BW_ITEM_PREFIX = 'deny.sh:';

// ---------------------------------------------------------------------------
// Bitwarden CLI helpers
// ---------------------------------------------------------------------------

/** Get BW_SESSION from env or throw with helpful message. */
function getSession(): string {
  const session = process.env.BW_SESSION;
  if (!session) {
    err('Bitwarden session not found.');
    info(`Unlock your vault first:`);
    console.log(`\n  ${cyan('export BW_SESSION=$(bw unlock --raw)')}\n`);
    process.exit(1);
  }
  return session;
}

/** Run a bw CLI command. Throws on non-zero exit. */
function bw(args: string[], opts: { input?: Buffer; session?: string } = {}): Buffer {
  const env: Record<string, string> = { ...process.env as Record<string, string> };
  if (opts.session) env.BW_SESSION = opts.session;

  return execFileSync('bw', args, {
    input: opts.input,
    env,
    stdio: opts.input ? ['pipe', 'pipe', 'pipe'] : ['inherit', 'pipe', 'pipe'],
  });
}

/** Check if bw CLI is installed. */
function isBwInstalled(): boolean {
  try {
    execFileSync('bw', ['--version'], { stdio: 'pipe' });
    return true;
  } catch {
    return false;
  }
}

/** Get current bw status. */
function getBwStatus(): BwStatus {
  try {
    const raw = bw(['status']);
    return JSON.parse(raw.toString().trim()) as BwStatus;
  } catch {
    return { status: 'unauthenticated' };
  }
}

/** List all deny.sh items in vault. */
function listBwItems(session: string): BwSecureNoteItem[] {
  try {
    const raw = bw(['list', 'items', '--search', BW_ITEM_PREFIX], { session });
    const items = JSON.parse(raw.toString().trim());
    if (!Array.isArray(items)) return [];
    return items as BwSecureNoteItem[];
  } catch {
    return [];
  }
}

/** Get a specific item by ID. */
function getBwItem(id: string, session: string): BwSecureNoteItem {
  const raw = bw(['get', 'item', id], { session });
  return JSON.parse(raw.toString().trim()) as BwSecureNoteItem;
}

/** Parse raw BW item into a DenyBwItem for display. */
function parseDenyItem(item: BwSecureNoteItem): DenyBwItem {
  const controlName = item.name.replace(/^deny\.sh:\s*/, '').trim();
  const getField = (name: string) =>
    item.fields?.find((f) => f.name === name)?.value ?? '';

  return {
    id: item.id,
    name: item.name,
    controlName,
    created: getField('created'),
    type: getField('type'),
    originalPath: getField('originalPath'),
    version: getField('version') || undefined,
  };
}

/** Build a Bitwarden secure note JSON for a control file. */
function buildBwItem(
  controlName: string,
  data: Uint8Array,
  opts: { type: string; originalPath: string; version?: string },
): string {
  const item = {
    type: 2,
    name: `${BW_ITEM_PREFIX} ${controlName}`,
    notes: Buffer.from(data).toString('base64'),
    secureNote: { type: 0 },
    fields: [
      { name: 'created', value: new Date().toISOString(), type: 0 },
      { name: 'type', value: opts.type, type: 0 },
      { name: 'originalPath', value: opts.originalPath, type: 0 },
      ...(opts.version ? [{ name: 'version', value: opts.version, type: 0 }] : []),
    ],
  };
  return JSON.stringify(item);
}

// ---------------------------------------------------------------------------
// Sub-commands
// ---------------------------------------------------------------------------

async function cmdStatus(): Promise<void> {
  banner('Bitwarden Status');

  if (!isBwInstalled()) {
    err('bw CLI is not installed.');
    info('Install it with one of:');
    console.log(`  ${cyan('npm install -g @bitwarden/cli')}`);
    console.log(`  ${cyan('brew install bitwarden-cli')}`);
    console.log(`  ${cyan('snap install bw')}`);
    return;
  }

  let version = '';
  try {
    version = execFileSync('bw', ['--version'], { stdio: 'pipe' }).toString().trim();
  } catch { /* ignore */ }

  success(`bw CLI installed${version ? ` (v${version})` : ''}`);

  const status = getBwStatus();
  switch (status.status) {
    case 'unlocked':
      success(`Vault unlocked${status.userEmail ? ` — ${cyan(status.userEmail)}` : ''}`);
      if (process.env.BW_SESSION) {
        success('BW_SESSION is set');
      } else {
        warn('BW_SESSION env var not set — commands may fail');
        info(`Run: ${cyan('export BW_SESSION=$(bw unlock --raw)')}`);
      }
      break;
    case 'locked':
      warn('Vault is locked');
      info(`Unlock with: ${cyan('export BW_SESSION=$(bw unlock --raw)')}`);
      break;
    case 'unauthenticated':
      warn('Not logged in');
      info(`Login with: ${cyan('bw login')}`);
      break;
  }
}

async function cmdList(nameFilter: string | undefined): Promise<void> {
  banner('Bitwarden — deny.sh items');

  const session = getSession();
  step('Fetching items from vault…');

  const rawItems = listBwItems(session);
  const items = rawItems.map(parseDenyItem);

  const filtered = nameFilter
    ? items.filter((i) => i.controlName.includes(nameFilter))
    : items;

  if (filtered.length === 0) {
    if (nameFilter) {
      warn(`No items matching ${bold(nameFilter)}`);
    } else {
      info('No deny.sh items found in vault.');
      info(`Push your first control file: ${cyan('deny-sh bw push')}`);
    }
    return;
  }

  console.log('');
  const rows = filtered.map((i) => [
    green(i.controlName),
    i.type === 'real' ? green('real') : yellow('decoy'),
    dim(i.created ? new Date(i.created).toLocaleDateString() : '—'),
    dim(i.originalPath || '—'),
  ]);

  table(
    ['Name', 'Type', 'Created', 'Path'],
    rows,
  );

  console.log('');
  info(`${bold(String(filtered.length))} item(s) found`);
}

async function cmdPush(nameFilter: string | undefined): Promise<void> {
  banner('Bitwarden — Push control files');

  const session = getSession();

  const denyDir = findDenyDir();
  if (!denyDir) {
    err('No .deny/ directory found. Run: deny-sh init');
    return;
  }

  // Gather controls to push
  const controls = listControls(denyDir);
  // Also include default control.dat if present
  const defaultData = getDefaultControl(denyDir);
  const allControls: Array<{ name: string; isDefault: boolean }> = [
    ...controls.map((c) => ({ name: c, isDefault: false })),
    ...(defaultData ? [{ name: DEFAULT_CONTROL, isDefault: true }] : []),
  ];

  if (allControls.length === 0) {
    warn('No control files found in .deny/');
    return;
  }

  const toProcess = nameFilter
    ? allControls.filter((c) => c.name.includes(nameFilter))
    : allControls;

  if (toProcess.length === 0) {
    warn(`No control files matching ${bold(nameFilter!)}`);
    return;
  }

  // Fetch existing items to detect updates vs creates
  step('Checking existing vault items…');
  const existing = listBwItems(session).map(parseDenyItem);
  const existingMap = new Map(existing.map((i) => [i.controlName, i]));

  let pushed = 0;
  let updated = 0;
  let skipped = 0;

  for (const ctrl of toProcess) {
    const controlName = ctrl.isDefault ? DEFAULT_CONTROL : ctrl.name;

    let data: Uint8Array | null = null;
    try {
      data = ctrl.isDefault
        ? getDefaultControl(denyDir)
        : getControl(denyDir, ctrl.name);
    } catch (e) {
      err(`Failed to read ${bold(controlName)}: ${(e as Error).message}`);
      skipped++;
      continue;
    }

    if (!data) {
      warn(`Skipping ${bold(controlName)}: empty`);
      skipped++;
      continue;
    }

    const originalPath = ctrl.isDefault
      ? DEFAULT_CONTROL
      : safeJoin(CONTROLS_DIR, ctrl.name);

    const existing_ = existingMap.get(controlName);

    if (existing_) {
      // Update existing item
      const ok = await confirm(
        `${bold(controlName)} already in vault — overwrite?`,
        false,
      );
      if (!ok) {
        info(`Skipped ${bold(controlName)}`);
        skipped++;
        continue;
      }

      step(`Updating ${bold(controlName)}…`);
      try {
        // Fetch full item to patch notes & fields
        const fullItem = getBwItem(existing_.id, session);
        fullItem.notes = Buffer.from(data).toString('base64');
        // Update fields
        const setField = (name: string, value: string) => {
          const f = fullItem.fields?.find((x) => x.name === name);
          if (f) f.value = value;
          else {
            fullItem.fields = fullItem.fields || [];
            fullItem.fields.push({ name, value, type: 0 });
          }
        };
        setField('created', new Date().toISOString());
        setField('originalPath', originalPath);

        const patchJson = Buffer.from(JSON.stringify(fullItem)).toString('base64');
        bw(['edit', 'item', existing_.id], {
          input: Buffer.from(patchJson),
          session,
        });
        success(`Updated  ${green(controlName)}`);
        updated++;
      } catch (e) {
        err(`Failed to update ${bold(controlName)}: ${(e as Error).message}`);
        skipped++;
      }
    } else {
      // Create new item
      step(`Pushing  ${bold(controlName)}…`);
      try {
        const itemJson = buildBwItem(controlName, data, {
          type: 'real',
          originalPath,
          version: '1',
        });
        const encoded = Buffer.from(itemJson).toString('base64');
        bw(['create', 'item'], {
          input: Buffer.from(encoded),
          session,
        });
        success(`Pushed   ${green(controlName)}`);
        pushed++;
      } catch (e) {
        err(`Failed to push ${bold(controlName)}: ${(e as Error).message}`);
        skipped++;
      }
    }
  }

  console.log('');
  info(
    `Done — ${bold(String(pushed))} created, ${bold(String(updated))} updated, ${bold(String(skipped))} skipped`,
  );
}

async function cmdPull(nameFilter: string | undefined): Promise<void> {
  banner('Bitwarden — Pull control files');

  const session = getSession();

  const denyDir = findDenyDir();
  if (!denyDir) {
    err('No .deny/ directory found. Run: deny-sh init');
    return;
  }

  step('Fetching items from vault…');
  const rawItems = listBwItems(session);
  const items = rawItems.map(parseDenyItem);

  if (items.length === 0) {
    warn('No deny.sh items found in vault.');
    return;
  }

  const toProcess = nameFilter
    ? items.filter((i) => i.controlName.includes(nameFilter))
    : items;

  if (toProcess.length === 0) {
    warn(`No items matching ${bold(nameFilter!)}`);
    return;
  }

  let pulled = 0;
  let skipped = 0;

  for (const item of toProcess) {
    step(`Pulling ${bold(item.controlName)}…`);

    let fullItem: BwSecureNoteItem;
    try {
      fullItem = getBwItem(item.id, session);
    } catch (e) {
      err(`Failed to fetch ${bold(item.controlName)}: ${(e as Error).message}`);
      skipped++;
      continue;
    }

    if (!fullItem.notes) {
      warn(`Item ${bold(item.controlName)} has no data — skipping`);
      skipped++;
      continue;
    }

    let data: Uint8Array;
    try {
      data = new Uint8Array(Buffer.from(fullItem.notes, 'base64'));
    } catch (e) {
      err(`Failed to decode ${bold(item.controlName)}: invalid base64`);
      skipped++;
      continue;
    }

    // Determine where to store it
    const isDefault = item.controlName === DEFAULT_CONTROL;

    // Check for existing local file
    const controls = listControls(denyDir);
    const existsLocally = isDefault
      ? getDefaultControl(denyDir) !== null
      : controls.includes(item.controlName);

    if (existsLocally) {
      const ok = await confirm(
        `${bold(item.controlName)} already exists locally — overwrite?`,
        false,
      );
      if (!ok) {
        info(`Skipped ${bold(item.controlName)}`);
        skipped++;
        continue;
      }
    }

    try {
      if (isDefault) {
        storeDefaultControl(denyDir, data);
      } else {
        storeControl(denyDir, item.controlName, data);
      }
      success(`Pulled  ${green(item.controlName)}`);
      pulled++;
    } catch (e) {
      err(`Failed to store ${bold(item.controlName)}: ${(e as Error).message}`);
      skipped++;
    }
  }

  console.log('');
  info(`Done — ${bold(String(pulled))} pulled, ${bold(String(skipped))} skipped`);
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

export async function cmdBitwarden(
  subArgs: string[],
  flags: Record<string, string>,
): Promise<void> {
  const subCmd = subArgs[0] ?? 'status';
  const nameFilter = subArgs[1];

  switch (subCmd) {
    case 'status':
      await cmdStatus();
      break;

    case 'list':
      await cmdList(nameFilter);
      break;

    case 'push':
      await cmdPush(nameFilter);
      break;

    case 'pull':
      await cmdPull(nameFilter);
      break;

    default:
      err(`Unknown subcommand: ${bold(subCmd)}`);
      info('Available subcommands:');
      console.log(`  ${cyan('deny-sh bw status')}   — check bw CLI status`);
      console.log(`  ${cyan('deny-sh bw list')}     — list vault items`);
      console.log(`  ${cyan('deny-sh bw push [name]')} — push control file(s) to vault`);
      console.log(`  ${cyan('deny-sh bw pull [name]')} — pull control file(s) from vault`);
  }
}
