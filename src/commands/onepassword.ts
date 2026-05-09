/**
 * onepassword.ts — 1Password integration for deny-sh
 *
 * Pushes/pulls .deny/ control files to/from 1Password via the `op` CLI.
 *
 * Commands:
 *   deny-sh 1p push [name]   Push control files to 1Password
 *   deny-sh 1p pull [name]   Pull control files from 1Password
 *   deny-sh 1p list          List deny.sh items in 1Password
 *   deny-sh 1p status        Check op CLI installation and auth
 */

import { execSync, execFileSync } from 'node:child_process';
import { banner, success, warn, info, step, error as err, bold, dim, green, yellow, cyan, table } from '../utils/display.js';
import { findDenyDir, listControls, getControl, storeControl, getDefaultControl, storeDefaultControl, CONTROLS_DIR, DEFAULT_CONTROL } from '../utils/dotdeny.js';
import { textInput, confirm } from '../utils/prompts.js';

// ─── Constants ────────────────────────────────────────────────────────────────

const OP_TAG = 'deny.sh';
const OP_CATEGORY = 'Secure Note';
const ITEM_PREFIX = 'deny.sh: ';
const DEFAULT_VAULT = 'Private';

// ─── op CLI helpers ───────────────────────────────────────────────────────────

function opExec(args: string[]): string {
  return execFileSync('op', args, { encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] }).trim();
}

function opJson<T>(args: string[]): T {
  const out = opExec([...args, '--format', 'json']);
  return JSON.parse(out) as T;
}

/** Returns true if `op` binary is in PATH. */
function isOpInstalled(): boolean {
  try {
    execSync('op --version', { stdio: 'pipe', encoding: 'utf8' });
    return true;
  } catch {
    return false;
  }
}

/** Returns true if `op` has an active session. */
function isOpSignedIn(): boolean {
  try {
    execFileSync('op', ['whoami'], { stdio: 'pipe', encoding: 'utf8' });
    return true;
  } catch {
    return false;
  }
}

function printInstallHelp(): void {
  err('1Password CLI (op) is not installed.');
  console.log('');
  info('Install it with:');
  console.log(`  ${bold('macOS:')}   brew install 1password-cli`);
  console.log(`  ${bold('Windows:')} scoop install 1password-cli`);
  console.log(`  ${bold('Linux:')}   https://developer.1password.com/docs/cli/get-started/`);
}

function printSignInHelp(): void {
  err('Not signed in to 1Password.');
  console.log('');
  info('Sign in with:');
  console.log(`  ${bold('eval $(op signin)')}`);
  console.log('');
  step('If you have multiple accounts, use: eval $(op signin --account <shorthand>)');
}

function requireOp(): boolean {
  if (!isOpInstalled()) {
    printInstallHelp();
    return false;
  }
  if (!isOpSignedIn()) {
    printSignInHelp();
    return false;
  }
  return true;
}

// ─── Vault helpers ────────────────────────────────────────────────────────────

interface OpVault {
  id: string;
  name: string;
}

function listVaults(): OpVault[] {
  return opJson<OpVault[]>(['vault', 'list']);
}

async function pickVault(flagVault?: string): Promise<string> {
  if (flagVault) return flagVault;

  let vaults: OpVault[];
  try {
    vaults = listVaults();
  } catch {
    return DEFAULT_VAULT;
  }

  if (vaults.length === 0) return DEFAULT_VAULT;

  // If "Private" exists, use it as default
  const hasPrivate = vaults.some(v => v.name === DEFAULT_VAULT);
  const defaultChoice = hasPrivate ? DEFAULT_VAULT : vaults[0].name;

  if (vaults.length === 1) return vaults[0].name;

  console.log('');
  info('Available vaults:');
  vaults.forEach((v, i) => {
    const marker = v.name === defaultChoice ? green('*') : ' ';
    console.log(`  ${marker} ${i + 1}. ${v.name} ${dim(`(${v.id.slice(0, 8)}...)`)}`);
  });
  console.log('');

  const chosen = (await textInput(`Vault name [${defaultChoice}]: `)) || defaultChoice;
  const match = vaults.find(v => v.name === chosen || v.id === chosen);
  if (!match) {
    warn(`Vault "${chosen}" not found — using "${defaultChoice}"`);
    return defaultChoice;
  }
  return match.name;
}

// ─── 1Password item helpers ───────────────────────────────────────────────────

interface OpItem {
  id: string;
  title: string;
  vault: { id: string; name: string };
  tags?: string[];
  created_at?: string;
  updated_at?: string;
  fields?: OpField[];
}

interface OpField {
  id: string;
  label: string;
  value?: string;
  type?: string;
  section?: { id: string; label: string };
}

function itemTitle(name: string): string {
  return `${ITEM_PREFIX}${name}`;
}

function nameFromTitle(title: string): string {
  return title.startsWith(ITEM_PREFIX) ? title.slice(ITEM_PREFIX.length) : title;
}

function listOpItems(vault: string): OpItem[] {
  return opJson<OpItem[]>([
    'item', 'list',
    '--vault', vault,
    '--tags', OP_TAG,
  ]);
}

function getOpItem(title: string, vault: string): OpItem {
  return opJson<OpItem>([
    'item', 'get', title,
    '--vault', vault,
  ]);
}

function fieldValue(item: OpItem, label: string): string | undefined {
  return item.fields?.find(f => f.label === label)?.value;
}

// ─── Push ─────────────────────────────────────────────────────────────────────

async function cmdPush(subArgs: string[], flags: Record<string, string>): Promise<void> {
  banner('1Password Push');

  const denyDir = findDenyDir();
  if (!denyDir) {
    err('No .deny/ directory found. Run `deny-sh init` first.');
    return;
  }

  const vault = await pickVault(flags['vault'] ?? flags['v']);

  const nameFilter = subArgs[0];
  let controls = listControls(denyDir);

  if (controls.length === 0) {
    warn('No control files found in .deny/controls/');
    return;
  }

  if (nameFilter) {
    controls = controls.filter(c => c === nameFilter || c === `${nameFilter}.dat`);
    if (controls.length === 0) {
      err(`No control file matching "${nameFilter}" found.`);
      info(`Available: ${listControls(denyDir).join(', ')}`);
      return;
    }
  }

  // Also push default control if it exists
  const defaultData = getDefaultControl(denyDir);
  const defaultName = DEFAULT_CONTROL;

  const allItems: Array<{ name: string; data: Uint8Array; isDefault: boolean }> = [
    ...controls.map(name => ({
      name,
      data: getControl(denyDir, name),
      isDefault: false,
    })),
  ];

  if (defaultData && !nameFilter) {
    allItems.push({ name: defaultName, data: defaultData, isDefault: true });
  }

  info(`Pushing ${allItems.length} control file(s) to vault "${bold(vault)}"...`);
  console.log('');

  let pushed = 0;
  let skipped = 0;

  for (const item of allItems) {
    const title = itemTitle(item.name);
    const b64 = Buffer.from(item.data).toString('base64');

    // Check if item already exists
    let exists = false;
    try {
      getOpItem(title, vault);
      exists = true;
    } catch {
      // doesn't exist, will create
    }

    if (exists) {
      const overwrite = await confirm(`  "${item.name}" already exists in 1Password. Overwrite?`);
      if (!overwrite) {
        step(`${yellow('skipped')} ${item.name}`);
        skipped++;
        continue;
      }
    }

    step(`Pushing ${bold(item.name)}...`);

    try {
      if (exists) {
        // Update existing item
        opExec([
          'item', 'edit', title,
          '--vault', vault,
          `controlData=${b64}`,
          `updatedAt=${new Date().toISOString()}`,
        ]);
      } else {
        // Create new item
        opExec([
          'item', 'create',
          '--category', OP_CATEGORY,
          '--title', title,
          '--vault', vault,
          '--tags', OP_TAG,
          `controlData=${b64}`,
          `itemName=${item.name}`,
          `createdAt=${new Date().toISOString()}`,
          `isDefault=${item.isDefault ? 'true' : 'false'}`,
        ]);
      }
      success(`  ${item.name} → 1Password`);
      pushed++;
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      err(`  Failed to push ${item.name}: ${msg}`);
    }
  }

  console.log('');
  if (pushed > 0) success(`${pushed} file(s) pushed to vault "${vault}".`);
  if (skipped > 0) info(`${skipped} file(s) skipped.`);
}

// ─── Pull ─────────────────────────────────────────────────────────────────────

async function cmdPull(subArgs: string[], flags: Record<string, string>): Promise<void> {
  banner('1Password Pull');

  const vault = await pickVault(flags['vault'] ?? flags['v']);
  const nameFilter = subArgs[0];

  step(`Listing items in vault "${bold(vault)}"...`);

  let items: OpItem[];
  try {
    items = listOpItems(vault);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    err(`Failed to list 1Password items: ${msg}`);
    return;
  }

  if (items.length === 0) {
    warn(`No deny.sh items found in vault "${vault}".`);
    info('Push some first with: deny-sh 1p push');
    return;
  }

  let filtered = items;
  if (nameFilter) {
    filtered = items.filter(i => {
      const n = nameFromTitle(i.title);
      return n === nameFilter || n === `${nameFilter}.dat`;
    });
    if (filtered.length === 0) {
      err(`No item matching "${nameFilter}" found in 1Password.`);
      info(`Available: ${items.map(i => nameFromTitle(i.title)).join(', ')}`);
      return;
    }
  }

  // Find or create .deny/ dir
  let denyDir = findDenyDir();
  if (!denyDir) {
    const create = await confirm('No .deny/ directory found. Create one here?');
    if (!create) return;
    // Use cwd — storeControl will handle dir creation
    denyDir = process.cwd();
  }

  info(`Pulling ${filtered.length} item(s) from vault "${bold(vault)}"...`);
  console.log('');

  let pulled = 0;

  for (const itemStub of filtered) {
    const name = nameFromTitle(itemStub.title);
    step(`Pulling ${bold(name)}...`);

    let item: OpItem;
    try {
      item = getOpItem(itemStub.title, vault);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      err(`  Failed to fetch "${name}": ${msg}`);
      continue;
    }

    const b64 = fieldValue(item, 'controlData');
    if (!b64) {
      warn(`  "${name}" has no controlData field — skipping.`);
      continue;
    }

    let data: Buffer;
    try {
      data = Buffer.from(b64, 'base64');
    } catch {
      err(`  Failed to decode controlData for "${name}"`);
      continue;
    }

    const isDefault = fieldValue(item, 'isDefault') === 'true';

    try {
      if (isDefault) {
        storeDefaultControl(denyDir, new Uint8Array(data));
        success(`  ${name} → .deny/${DEFAULT_CONTROL} (default control)`);
      } else {
        storeControl(denyDir, name, new Uint8Array(data));
        success(`  ${name} → .deny/${CONTROLS_DIR}/${name}`);
      }
      pulled++;
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e);
      err(`  Failed to write "${name}": ${msg}`);
    }
  }

  console.log('');
  if (pulled > 0) {
    success(`${pulled} control file(s) pulled.`);
  } else {
    warn('Nothing was pulled.');
  }
}

// ─── List ─────────────────────────────────────────────────────────────────────

async function cmdList(flags: Record<string, string>): Promise<void> {
  banner('1Password Items');

  const vault = await pickVault(flags['vault'] ?? flags['v']);

  step(`Fetching deny.sh items from vault "${bold(vault)}"...`);

  let items: OpItem[];
  try {
    items = listOpItems(vault);
  } catch (e: unknown) {
    const msg = e instanceof Error ? e.message : String(e);
    err(`Failed to list items: ${msg}`);
    return;
  }

  if (items.length === 0) {
    warn(`No deny.sh items found in vault "${vault}".`);
    info('Push control files with: deny-sh 1p push');
    return;
  }

  console.log('');

  const rows = items.map(item => {
    const name = nameFromTitle(item.title);
    const updated = item.updated_at
      ? new Date(item.updated_at).toLocaleDateString('en-GB', { day: '2-digit', month: 'short', year: 'numeric' })
      : dim('—');
    const vault = item.vault?.name ?? dim('—');
    return [green(name), vault, updated, item.id.slice(0, 8) + '...'];
  });

  table(['Name', 'Vault', 'Updated', 'ID'], rows);
  console.log('');
  info(`${items.length} item(s) in vault "${vault}".`);
}

// ─── Status ───────────────────────────────────────────────────────────────────

async function cmdStatus(): Promise<void> {
  banner('1Password Status');

  // Check op installed
  if (!isOpInstalled()) {
    err('op CLI: not installed');
    console.log('');
    printInstallHelp();
    return;
  }

  let version = '';
  try {
    version = execSync('op --version', { encoding: 'utf8', stdio: 'pipe' }).trim();
  } catch {
    version = 'unknown';
  }
  success(`op CLI: installed ${dim(`(v${version})`)}`);

  // Check signed in
  if (!isOpSignedIn()) {
    err('Session: not signed in');
    console.log('');
    printSignInHelp();
    return;
  }

  let whoami = '';
  try {
    whoami = opExec(['whoami']);
  } catch {
    whoami = 'unknown';
  }
  success(`Session: active ${dim(`(${whoami})`)}`);

  // List vaults
  console.log('');
  let vaults: OpVault[] = [];
  try {
    vaults = listVaults();
  } catch {
    warn('Could not fetch vault list.');
  }

  if (vaults.length > 0) {
    info(`${vaults.length} vault(s) accessible:`);
    vaults.forEach(v => {
      const marker = v.name === DEFAULT_VAULT ? green('*') : ' ';
      console.log(`  ${marker} ${bold(v.name)} ${dim(`(${v.id.slice(0, 8)}...)`)}`);
    });
  }

  // Check local .deny/ state
  console.log('');
  const denyDir = findDenyDir();
  if (denyDir) {
    const controls = listControls(denyDir);
    info(`Local .deny/ found at: ${dim(denyDir)}`);
    if (controls.length > 0) {
      step(`${controls.length} control file(s): ${controls.map(c => cyan(c)).join(', ')}`);
    } else {
      step('No control files yet.');
    }
  } else {
    warn('No .deny/ directory found in current path.');
    step('Run `deny-sh init` to create one.');
  }
}

// ─── Entry point ──────────────────────────────────────────────────────────────

export async function cmd1Password(subArgs: string[], flags: Record<string, string>): Promise<void> {
  const subCmd = subArgs[0];
  const restArgs = subArgs.slice(1);

  // status doesn't require op to be working (it checks for us)
  if (subCmd === 'status') {
    await cmdStatus();
    return;
  }

  if (!requireOp()) {
    process.exitCode = 1;
    return;
  }

  switch (subCmd) {
    case 'push':
      await cmdPush(restArgs, flags);
      break;

    case 'pull':
      await cmdPull(restArgs, flags);
      break;

    case 'list':
    case 'ls':
      await cmdList(flags);
      break;

    default: {
      if (subCmd) {
        err(`Unknown 1Password subcommand: "${subCmd}"`);
        console.log('');
      }
      info('Usage:');
      console.log(`  ${bold('deny-sh 1p push')} ${dim('[name]')}   Push control files to 1Password`);
      console.log(`  ${bold('deny-sh 1p pull')} ${dim('[name]')}   Pull control files from 1Password`);
      console.log(`  ${bold('deny-sh 1p list')}            List deny.sh items in 1Password`);
      console.log(`  ${bold('deny-sh 1p status')}          Check op CLI status and auth`);
      console.log('');
      step(`Use ${dim('--vault <name>')} to target a specific vault`);
    }
  }
}
