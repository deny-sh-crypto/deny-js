/**
 * tripwires.ts — deny-sh tripwires command
 *
 * Bulk-arm decoy tripwires at customer-DB scale. Shipped 2026-05-29 for the
 * "1M-row" use case where customers want a tripwire per row across known
 * field types (stripe keys, AWS keys, etc.).
 *
 * Subcommands:
 *   deny-sh tripwires list
 *     List existing tripwires for the current API key.
 *
 *   deny-sh tripwires arm-bulk --type <decoy-type> --count <N> [--label-prefix <s>] [--out <csv>]
 *     Generate <N> shape-matching decoys for the chosen type, compute their
 *     sha256, and register them as tripwires via /v1/decoy-tripwires/bulk.
 *     Writes a CSV mapping <label,decoy_value,sha256,tripwire_id> so the
 *     customer can store the decoy alongside their real row.
 *
 *   deny-sh tripwires arm-from-csv --type <decoy-type> --in <csv> --id-col <N> [--out <csv>]
 *     Same as arm-bulk but reads row ids from a CSV (one decoy per id).
 *     Label = `<label-prefix>{id}` interpolated.
 *
 *   deny-sh tripwires test <id>
 *     Fire a synthetic trigger for an existing tripwire id (proves webhook
 *     fan-out works end-to-end).
 *
 * All subcommands require DENY_API_KEY env var. DENY_API_URL defaults to
 * https://deny.sh/api.
 *
 * Bulk endpoint hard caps at 1000 tripwires per HTTP call; this command
 * batches transparently.
 */

import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync, createReadStream } from 'node:fs';
import { resolve } from 'node:path';
import { createInterface } from 'node:readline';
import { generateLocalDecoy } from '../record-decoy-generators.js';
import type { DecoyType } from '../decoy-engine/types.js';
import { bold, cyan, dim, green, red, yellow, success, error as printErr } from '../utils/display.js';

// Server hard cap on bulk register endpoint
const BATCH_SIZE = 1000;

// Known DecoyType strings the SDK can generate
const KNOWN_TYPES: DecoyType[] = [
  'stripe-test-key', 'stripe-live-key', 'github-pat-classic', 'github-pat-fine',
  'openai-key', 'anthropic-key', 'resend-key', 'aws-access-key', 'bip39-phrase',
  'jwt-token', 'iban', 'credit-card', 'private-key-pem', 'postgres-uri',
  'mongodb-uri', 'slack-bot-token', 'slack-user-token', 'discord-bot-token',
  'digitalocean-pat', 'gcp-api-key', 'gcp-service-account-key',
  'azure-client-secret', 'azure-storage-key', 'twilio-auth-token', 'sendgrid-key', 'huggingface-token',
  'npm-publish-token', 'pypi-token', 'gitlab-pat', 'mailgun-api-key',
  'linear-api-key', 'notion-token', 'shopify-token', 'square-token',
  'cloudflare-api-token', 'ethereum-private-key', 'bitcoin-wif',
  'solana-private-key', 'uk-nhs-number', 'us-ssn', 'uk-ni-number',
  'phone-e164', 'generic', 'freeform-secret',
];

// Same as the SDK helper — kept inline so we don't have a circular import
// or depend on the helper being published yet. Mirror this map when
// generateDecoyWithHash changes its defaults.
function defaultLengthForType(type: DecoyType): number {
  switch (type) {
    case 'stripe-test-key':       return 32;
    case 'stripe-live-key':       return 107;
    case 'github-pat-classic':    return 40;
    case 'github-pat-fine':       return 93;
    case 'openai-key':            return 51;
    case 'anthropic-key':         return 108;
    case 'resend-key':            return 36;
    case 'aws-access-key':        return 20;
    case 'bip39-phrase':          return 200;
    case 'jwt-token':             return 300;
    case 'iban':                  return 22;
    case 'credit-card':           return 16;
    case 'private-key-pem':       return 1700;
    case 'postgres-uri':          return 80;
    case 'mongodb-uri':           return 90;
    case 'slack-bot-token':       return 57;
    case 'slack-user-token':      return 57;
    case 'discord-bot-token':     return 72;
    case 'digitalocean-pat':      return 71;
    case 'gcp-api-key':           return 39;
    case 'gcp-service-account-key': return 1600;
    case 'azure-client-secret':   return 40;
    case 'azure-storage-key':     return 88;
    case 'twilio-auth-token':     return 32;
    case 'sendgrid-key':          return 69;
    case 'huggingface-token':     return 40;
    case 'npm-publish-token':     return 40;
    case 'pypi-token':            return 156;
    case 'gitlab-pat':            return 24;
    case 'mailgun-api-key':       return 36;
    case 'linear-api-key':        return 51;
    case 'notion-token':          return 50;
    case 'shopify-token':         return 38;
    case 'square-token':          return 64;
    case 'cloudflare-api-token':  return 40;
    case 'ethereum-private-key':  return 64;
    case 'bitcoin-wif':           return 51;
    case 'solana-private-key':    return 88;
    case 'uk-nhs-number':         return 10;
    case 'us-ssn':                return 11;
    case 'uk-ni-number':          return 9;
    case 'phone-e164':            return 14;
    case 'generic':               return 32;
    case 'freeform-secret':       return 32;
    default:                      return 32;
  }
}

function generateDecoyHash(type: DecoyType, lenHint?: number): { value: string; sha256: string } {
  const len = lenHint ?? defaultLengthForType(type);
  const dummy = 'x'.repeat(len);
  const value = generateLocalDecoy(dummy, type);
  const sha256 = createHash('sha256').update(value, 'utf8').digest('hex');
  return { value, sha256 };
}

function getApiCreds(flags: Record<string, string>): { apiKey: string; baseUrl: string } {
  const apiKey = flags['api-key'] || process.env.DENY_API_KEY || '';
  if (!apiKey) {
    printErr('DENY_API_KEY not set. Pass --api-key <cs_...> or export DENY_API_KEY=...');
    process.exit(1);
  }
  const baseUrl = (flags['api-url'] || process.env.DENY_API_URL || 'https://deny.sh/api').replace(/\/$/, '');
  return { apiKey, baseUrl };
}

async function postJson(url: string, apiKey: string, body: unknown): Promise<{ status: number; data: any }> {
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  let data: any = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  return { status: res.status, data };
}

async function getJson(url: string, apiKey: string): Promise<{ status: number; data: any }> {
  const res = await fetch(url, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${apiKey}`,
      'Accept': 'application/json',
    },
  });
  const text = await res.text();
  let data: any = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  return { status: res.status, data };
}

// ─── list ────────────────────────────────────────────────────────────────

async function cmdList(flags: Record<string, string>): Promise<void> {
  const { apiKey, baseUrl } = getApiCreds(flags);
  const { status, data } = await getJson(`${baseUrl}/v1/decoy-tripwires`, apiKey);
  if (status !== 200) {
    printErr(`list failed: ${status} ${typeof data === 'string' ? data : JSON.stringify(data)}`);
    process.exit(1);
  }
  const rows: any[] = data?.tripwires ?? [];
  if (rows.length === 0) {
    console.log(dim('No tripwires registered.'));
    return;
  }
  console.log(bold(`${rows.length} tripwire${rows.length === 1 ? '' : 's'} registered:`));
  console.log();
  for (const r of rows) {
    const enabled = r.enabled ? green('●') : dim('○');
    const kind = r.tripwire_kind || 'controldata';
    const triggers = r.trigger_count ?? 0;
    const lastTrig = r.last_triggered ? new Date(r.last_triggered * 1000).toISOString() : '—';
    // Server returns tripwire_hash_suffix (last 12 chars only) on list, never
    // the full hash; the full one only echoes back at registration time.
    const hashTag = r.tripwire_hash_suffix
      ? `…${r.tripwire_hash_suffix}`
      : (r.tripwire_hash ? `${r.tripwire_hash.slice(0, 12)}…` : '(no-hash)');
    console.log(`  ${enabled} ${cyan(`#${r.id}`)}  ${kind.padEnd(11)}  ${hashTag}  triggers=${triggers}  last=${lastTrig}  ${dim(r.label || '')}`);
  }
}

// ─── arm-bulk (--count) ──────────────────────────────────────────────────

async function cmdArmBulk(flags: Record<string, string>): Promise<void> {
  const type = (flags['type'] || '') as DecoyType;
  const count = parseInt(flags['count'] || '0', 10);
  const labelPrefix = flags['label-prefix'] || `arm-${type}-${Date.now()}-`;
  const outPath = flags['out'] || '';
  const lenHint = flags['length'] ? parseInt(flags['length'], 10) : undefined;
  const kind = (flags['kind'] || 'plaintext') as 'plaintext' | 'controldata';

  if (!KNOWN_TYPES.includes(type)) {
    printErr(`unknown --type "${type}". Run: deny-sh tripwires types`);
    process.exit(1);
  }
  if (!Number.isFinite(count) || count <= 0) {
    printErr('--count must be a positive integer');
    process.exit(1);
  }
  if (kind !== 'plaintext' && kind !== 'controldata') {
    printErr("--kind must be 'plaintext' or 'controldata'");
    process.exit(1);
  }

  const { apiKey, baseUrl } = getApiCreds(flags);

  console.log(bold(`Arming ${count.toLocaleString()} tripwires of type ${cyan(type)} (kind=${kind})…`));

  // We need to keep mapping from each generated decoy to its registered id,
  // so the CSV write-back is complete. We accumulate in memory only for the
  // --out write; for very large runs without --out we stream and discard.
  const rows: Array<{ label: string; value: string; sha256: string; tripwire_id?: number; error?: string }> = [];

  let armedTotal = 0;
  let failedTotal = 0;
  const startedAt = Date.now();

  for (let batchStart = 0; batchStart < count; batchStart += BATCH_SIZE) {
    const batchEnd = Math.min(batchStart + BATCH_SIZE, count);
    const batch: Array<{ tripwire_hash: string; label: string; tripwire_kind: string }> = [];
    const batchRows: typeof rows = [];

    for (let i = batchStart; i < batchEnd; i++) {
      const label = `${labelPrefix}${i + 1}`;
      const { value, sha256 } = generateDecoyHash(type, lenHint);
      batch.push({ tripwire_hash: sha256, label, tripwire_kind: kind });
      batchRows.push({ label, value, sha256 });
    }

    const { status, data } = await postJson(
      `${baseUrl}/v1/decoy-tripwires/bulk`,
      apiKey,
      { tripwires: batch },
    );

    if (status !== 200) {
      printErr(`batch ${batchStart}-${batchEnd} failed: ${status} ${typeof data === 'string' ? data : JSON.stringify(data)}`);
      // Mark every row in this batch as errored, but keep going so the CSV
      // is complete (customer can retry just the failed ones).
      for (const r of batchRows) {
        r.error = `http_${status}`;
        rows.push(r);
        failedTotal++;
      }
      continue;
    }

    const registered: Array<{ index: number; tripwire: any }> = data?.registered ?? [];
    const failed: Array<{ index: number; label: string; reason: string }> = data?.failed ?? [];

    for (const reg of registered) {
      const row = batchRows[reg.index];
      if (row) {
        row.tripwire_id = reg.tripwire?.id;
        rows.push(row);
        armedTotal++;
      }
    }
    for (const f of failed) {
      const row = batchRows[f.index];
      if (row) {
        row.error = f.reason;
        rows.push(row);
        failedTotal++;
      }
    }

    const elapsed = ((Date.now() - startedAt) / 1000).toFixed(1);
    process.stdout.write(`\r  ${armedTotal.toLocaleString()} armed, ${failedTotal.toLocaleString()} failed (${elapsed}s)…`);
  }

  process.stdout.write('\n');

  if (outPath) {
    const csvLines = ['label,decoy_value,sha256,tripwire_id,error'];
    for (const r of rows) {
      const v = r.value.replaceAll('"', '""');
      csvLines.push(`"${r.label}","${v}","${r.sha256}","${r.tripwire_id ?? ''}","${r.error ?? ''}"`);
    }
    writeFileSync(resolve(outPath), csvLines.join('\n') + '\n', { mode: 0o600 });
    success(`Wrote ${rows.length.toLocaleString()} rows to ${cyan(outPath)} (mode 0600)`);
  }

  success(`Done. ${armedTotal.toLocaleString()} tripwires armed, ${failedTotal.toLocaleString()} failed in ${((Date.now() - startedAt) / 1000).toFixed(1)}s.`);
  if (failedTotal > 0) {
    console.log(yellow(`  Common reasons for failure: tripwire_limit_reached (tier cap), duplicate hash, validation error. Inspect CSV column 'error'.`));
  }
}

// ─── arm-from-csv (--in, --id-col) ──────────────────────────────────────

async function cmdArmFromCsv(flags: Record<string, string>): Promise<void> {
  const type = (flags['type'] || '') as DecoyType;
  const inPath = flags['in'] || '';
  const idCol = parseInt(flags['id-col'] || '0', 10);
  const labelTemplate = flags['label-template'] || `arm-${type}-{id}`;
  const outPath = flags['out'] || '';
  const lenHint = flags['length'] ? parseInt(flags['length'], 10) : undefined;
  const kind = (flags['kind'] || 'plaintext') as 'plaintext' | 'controldata';
  const skipHeader = flags['skip-header'] === 'true';

  if (!KNOWN_TYPES.includes(type)) {
    printErr(`unknown --type "${type}". Run: deny-sh tripwires types`);
    process.exit(1);
  }
  if (!inPath) {
    printErr('--in <csv> required');
    process.exit(1);
  }
  if (!Number.isFinite(idCol) || idCol < 0) {
    printErr('--id-col must be a non-negative integer (column index, 0-based)');
    process.exit(1);
  }

  const { apiKey, baseUrl } = getApiCreds(flags);

  console.log(bold(`Streaming ids from ${cyan(inPath)}, col ${idCol}, type ${cyan(type)} (kind=${kind})…`));

  const ids: string[] = [];
  const rl = createInterface({
    input: createReadStream(resolve(inPath), { encoding: 'utf8' }),
    crlfDelay: Infinity,
  });
  let lineNo = 0;
  for await (const line of rl) {
    lineNo++;
    if (lineNo === 1 && skipHeader) continue;
    if (!line.trim()) continue;
    const cols = parseCsvLine(line);
    const id = cols[idCol];
    if (id === undefined) continue;
    ids.push(id);
  }
  console.log(`  Loaded ${ids.length.toLocaleString()} ids.`);

  // Reuse arm-bulk logic but with custom labels.
  const rows: Array<{ label: string; value: string; sha256: string; id: string; tripwire_id?: number; error?: string }> = [];
  let armedTotal = 0;
  let failedTotal = 0;
  const startedAt = Date.now();

  for (let batchStart = 0; batchStart < ids.length; batchStart += BATCH_SIZE) {
    const batchEnd = Math.min(batchStart + BATCH_SIZE, ids.length);
    const batch: Array<{ tripwire_hash: string; label: string; tripwire_kind: string }> = [];
    const batchRows: typeof rows = [];

    for (let i = batchStart; i < batchEnd; i++) {
      const id = ids[i]!;
      const label = labelTemplate.replaceAll('{id}', id);
      const { value, sha256 } = generateDecoyHash(type, lenHint);
      batch.push({ tripwire_hash: sha256, label, tripwire_kind: kind });
      batchRows.push({ id, label, value, sha256 });
    }

    const { status, data } = await postJson(
      `${baseUrl}/v1/decoy-tripwires/bulk`,
      apiKey,
      { tripwires: batch },
    );

    if (status !== 200) {
      printErr(`batch ${batchStart}-${batchEnd} failed: ${status} ${typeof data === 'string' ? data : JSON.stringify(data)}`);
      for (const r of batchRows) { r.error = `http_${status}`; rows.push(r); failedTotal++; }
      continue;
    }

    const registered: Array<{ index: number; tripwire: any }> = data?.registered ?? [];
    const failed: Array<{ index: number; label: string; reason: string }> = data?.failed ?? [];

    for (const reg of registered) {
      const row = batchRows[reg.index];
      if (row) { row.tripwire_id = reg.tripwire?.id; rows.push(row); armedTotal++; }
    }
    for (const f of failed) {
      const row = batchRows[f.index];
      if (row) { row.error = f.reason; rows.push(row); failedTotal++; }
    }

    const elapsed = ((Date.now() - startedAt) / 1000).toFixed(1);
    process.stdout.write(`\r  ${armedTotal.toLocaleString()} armed, ${failedTotal.toLocaleString()} failed (${elapsed}s)…`);
  }
  process.stdout.write('\n');

  if (outPath) {
    const csvLines = ['id,label,decoy_value,sha256,tripwire_id,error'];
    for (const r of rows) {
      const v = r.value.replaceAll('"', '""');
      const id = r.id.replaceAll('"', '""');
      csvLines.push(`"${id}","${r.label}","${v}","${r.sha256}","${r.tripwire_id ?? ''}","${r.error ?? ''}"`);
    }
    writeFileSync(resolve(outPath), csvLines.join('\n') + '\n', { mode: 0o600 });
    success(`Wrote ${rows.length.toLocaleString()} rows to ${cyan(outPath)} (mode 0600)`);
  }

  success(`Done. ${armedTotal.toLocaleString()} armed, ${failedTotal.toLocaleString()} failed in ${((Date.now() - startedAt) / 1000).toFixed(1)}s.`);
}

// ─── test <id> ──────────────────────────────────────────────────────────

async function cmdTest(subArgs: string[], flags: Record<string, string>): Promise<void> {
  const id = subArgs[0];
  if (!id) { printErr('usage: deny-sh tripwires test <id>'); process.exit(1); }
  const { apiKey, baseUrl } = getApiCreds(flags);
  const { status, data } = await postJson(`${baseUrl}/v1/decoy-tripwires/${id}/test`, apiKey, {});
  if (status !== 200) {
    printErr(`test fire failed: ${status} ${typeof data === 'string' ? data : JSON.stringify(data)}`);
    process.exit(1);
  }
  success(`Synthetic trigger fired for tripwire #${id}. Webhook fan-out (Datadog/PagerDuty/Slack) should arrive in seconds.`);
}

// ─── types ──────────────────────────────────────────────────────────────

function cmdTypes(): void {
  console.log(bold('Supported decoy types (40):'));
  console.log();
  for (const t of KNOWN_TYPES) {
    console.log(`  ${cyan(t.padEnd(24))}  ${dim(`default length ${defaultLengthForType(t)}`)}`);
  }
}

// ─── help ───────────────────────────────────────────────────────────────

function showHelp(): void {
  console.log(`
${bold('deny-sh tripwires')} — bulk-arm decoy tripwires

${bold('Subcommands:')}

  ${cyan('list')}                          List existing tripwires
  ${cyan('types')}                         List supported decoy types
  ${cyan('arm-bulk')}    --type T --count N [--label-prefix P] [--out CSV]
  ${cyan('arm-from-csv')} --type T --in CSV --id-col N [--label-template "row-{id}"] [--out CSV]
  ${cyan('test')} <id>                    Fire a synthetic trigger for an existing tripwire

${bold('Flags (any subcommand):')}

  --api-key cs_...           Override DENY_API_KEY env var
  --api-url https://...      Override DENY_API_URL env var (default: https://deny.sh/api)
  --kind plaintext|controldata  Default: plaintext
  --length N                 Override the default decoy length for the chosen type

${bold('Examples:')}

  ${dim('# Arm 100,000 stripe-live decoys, save the mapping CSV')}
  ${cyan('DENY_API_KEY=cs_... deny-sh tripwires arm-bulk --type stripe-live-key --count 100000 --out armed.csv')}

  ${dim('# Arm one decoy per row in your DB export')}
  ${cyan('DENY_API_KEY=cs_... deny-sh tripwires arm-from-csv --type aws-access-key --in real-rows.csv --id-col 0 --skip-header true --out armed.csv')}

  ${dim('# Test the webhook plumbing for tripwire #42891')}
  ${cyan('DENY_API_KEY=cs_... deny-sh tripwires test 42891')}

${bold('How to use the CSV write-back:')}

  ${dim('Each row has a generated decoy value + tripwire id. Store the decoy value')}
  ${dim('in your DB alongside the real row (in a separate column you control); keep')}
  ${dim('the real value offline / wherever it normally lives. If anyone reads the decoy')}
  ${dim('and tries to decrypt it against the deny.sh API, your tripwire fires.')}

${bold('Tiers and caps:')}

  pro                     10,000      ${dim('($199/mo or $1,910/yr — entry-level tripwire tier)')}
  agents-starter          100,000
  agents-infra            1,000,000   ${dim('($999/mo — bulk scale)')}
  enterprise              10,000,000
  inherit-institutional   10,000,000

  ${dim('Tripwires are NOT available on free or dev tiers. Upgrade at')} ${cyan('https://deny.sh/pricing')}
`);
}

// ─── dispatch ───────────────────────────────────────────────────────────

export async function cmdTripwires(subArgs: string[], flags: Record<string, string>): Promise<void> {
  const sub = subArgs[0] || 'help';
  const rest = subArgs.slice(1);
  switch (sub) {
    case 'list':         await cmdList(flags); break;
    case 'arm-bulk':     await cmdArmBulk(flags); break;
    case 'arm-from-csv': await cmdArmFromCsv(flags); break;
    case 'test':         await cmdTest(rest, flags); break;
    case 'types':        cmdTypes(); break;
    case 'help':
    case '--help':
    case '-h':           showHelp(); break;
    default:
      printErr(`Unknown subcommand: ${sub}`);
      showHelp();
      process.exit(1);
  }
}

// ─── tiny CSV line parser (RFC-4180 lite) ───────────────────────────────

function parseCsvLine(line: string): string[] {
  const out: string[] = [];
  let cur = '';
  let inQuotes = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (inQuotes) {
      if (ch === '"' && line[i + 1] === '"') { cur += '"'; i++; }
      else if (ch === '"') { inQuotes = false; }
      else { cur += ch; }
    } else {
      if (ch === '"') { inQuotes = true; }
      else if (ch === ',') { out.push(cur); cur = ''; }
      else { cur += ch; }
    }
  }
  out.push(cur);
  return out;
}
