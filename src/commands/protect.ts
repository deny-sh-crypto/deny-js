/**
 * protect.ts — deny-sh protect
 * Interactive seed phrase protection wizard.
 */

import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { createGzip } from 'node:zlib';
import { pipeline } from 'node:stream/promises';
import { createReadStream, createWriteStream, rmSync, existsSync } from 'node:fs';
import { Readable } from 'node:stream';

import { encrypt, generateControlData, generateDeniableControl } from '../index.js';
import {
  banner, success, warn, info, step, progressBar,
  bold, red, green, yellow, dim
} from '../utils/display.js';
import {
  hiddenInput, textInput, confirm, confirmedPassword
} from '../utils/prompts.js';

// BIP-39 valid word counts
const VALID_WORD_COUNTS = [12, 15, 18, 21, 24];

function validateWordCount(phrase: string): string | null {
  const words = phrase.trim().split(/\s+/).filter(Boolean);
  if (!VALID_WORD_COUNTS.includes(words.length)) {
    return `Expected 12, 15, 18, 21, or 24 words. Got ${words.length}.`;
  }
  return null;
}

/** Simulate Argon2id progress bar while the async KDF runs. */
async function animateProgress(label: string): Promise<void> {
  process.stdout.write('\n');
  const steps = [0, 10, 25, 40, 55, 70, 85, 95, 100];
  for (const pct of steps) {
    process.stdout.write(`\r  ${label} ${progressBar(pct)}   `);
    await new Promise(r => setTimeout(r, pct < 100 ? 80 : 0));
  }
  process.stdout.write('\n');
}

/** Create a simple .tar.gz archive containing given files (paths → names). */
async function createTarGz(outputPath: string, files: { path: string; name: string }[]): Promise<void> {
  // Simple tar format implementation using node built-ins
  const blocks: Buffer[] = [];

  for (const { path: filePath, name } of files) {
    const { readFileSync } = await import('node:fs');
    const data = readFileSync(filePath);
    const header = buildTarHeader(name, data.length);
    blocks.push(header);
    // Pad data to 512-byte block
    const padded = Buffer.alloc(Math.ceil(data.length / 512) * 512);
    data.copy(padded);
    blocks.push(padded);
  }

  // Two 512-byte zero blocks as EOF marker
  blocks.push(Buffer.alloc(1024));

  const combined = Buffer.concat(blocks);

  await new Promise<void>((res, rej) => {
    const gzip = createGzip();
    const out = createWriteStream(outputPath);
    const src = Readable.from(combined);
    gzip.pipe(out);
    src.pipe(gzip);
    out.on('finish', res);
    out.on('error', rej);
    gzip.on('error', rej);
  });
}

function buildTarHeader(name: string, size: number): Buffer {
  const header = Buffer.alloc(512);
  // name (0-99)
  header.write(name.slice(0, 99), 0, 'ascii');
  // mode (100-107)
  header.write('0000644\0', 100, 'ascii');
  // uid/gid (108-135)
  header.write('0000000\0', 108, 'ascii');
  header.write('0000000\0', 116, 'ascii');
  // size (124-135) — octal
  header.write(size.toString(8).padStart(11, '0') + '\0', 124, 'ascii');
  // mtime (136-147)
  header.write(Math.floor(Date.now() / 1000).toString(8).padStart(11, '0') + '\0', 136, 'ascii');
  // checksum placeholder
  header.write('        ', 148, 'ascii');
  // type flag (156): '0' = regular file
  header.write('0', 156, 'ascii');
  // magic (257)
  header.write('ustar  \0', 257, 'ascii');

  // Compute checksum
  let sum = 0;
  for (const b of header) sum += b;
  header.write(sum.toString(8).padStart(6, '0') + '\0 ', 148, 'ascii');
  return header;
}

export async function cmdProtect(_flags: Record<string, string>): Promise<void> {
  banner('Seed Phrase Protector');

  console.log('  This wizard encrypts your seed phrase with deniable encryption.');
  console.log('  You can create a decoy password that reveals a different message.');
  console.log();

  // --- Get seed phrase ---
  console.log(`  ${bold('Step 1:')} Enter your seed phrase`);
  let seedPhrase = '';
  while (true) {
    seedPhrase = await hiddenInput('  Seed phrase (hidden): ');
    const err = validateWordCount(seedPhrase);
    if (err) {
      console.log(`  ${red('✗')} ${err}`);
      continue;
    }
    const words = seedPhrase.trim().split(/\s+/).filter(Boolean);
    console.log(`  ${green('✓')} ${words.length} words detected`);
    break;
  }
  console.log();

  // --- Real passwords ---
  console.log(`  ${bold('Step 2:')} Set your real password`);
  console.log(`  ${dim('This password decrypts to your actual seed phrase.')}`);
  const realPw1 = await confirmedPassword('  Enter real password:    ', '  Confirm:               ');
  console.log(`  ${green('✓')} Real password set`);
  console.log();

  // --- Decoy? ---
  console.log(`  ${bold('Step 3:')} Add a decoy? ${dim('(optional — for plausible deniability)')}`);
  const addDecoy = await confirm('  Create decoy password?', true);
  let decoyPw1 = '';
  let decoyMessage = '';

  if (addDecoy) {
    console.log(`  ${dim('The decoy password reveals a different message when used.')}`);
    decoyPw1 = await confirmedPassword('  Enter decoy password:  ', '  Confirm:               ');
    decoyMessage = await textInput('  Decoy message: ', s => s.trim().length < 3 ? 'Enter at least 3 characters' : null);
    console.log(`  ${green('✓')} Decoy configured`);
  }
  console.log();

  // --- Output naming ---
  const outputBin     = _flags['o']  || 'encrypted.bin';
  const controlReal   = _flags['cr'] || 'control-real.dat';
  const controlDecoy  = _flags['cd'] || 'control-decoy.dat';

  // --- Encrypt ---
  console.log(`  ${bold('Step 4:')} Encrypting...`);

  await animateProgress('Deriving key');

  const plaintext = new TextEncoder().encode(seedPhrase.trim());
  const controlData = generateControlData(Math.max(plaintext.length + 4, 512));
  const { ciphertext } = await encrypt(plaintext, {
    password1: realPw1,
    password2: realPw1,
    controlData,
  });

  writeFileSync(resolve(outputBin), ciphertext);
  writeFileSync(resolve(controlReal), controlData);

  const files: { path: string; name: string }[] = [
    { path: resolve(outputBin),   name: outputBin },
    { path: resolve(controlReal), name: controlReal },
  ];

  if (addDecoy) {
    const decoyPlaintext = new TextEncoder().encode(decoyMessage.trim());
    // Use DECOY passwords for decoy control — so only decoyPw1 unlocks the decoy.
    // Using realPw1 here (the original bug) meant the decoy was readable with
    // the real password, defeating the two-password deniability model.
    const { controlData: decoyControl } = await generateDeniableControl(
      ciphertext, decoyPw1, decoyPw1, decoyPlaintext
    );
    writeFileSync(resolve(controlDecoy), decoyControl);
    files.push({ path: resolve(controlDecoy), name: controlDecoy });
  }

  console.log();
  success(`Created files:`);
  step(`${bold(outputBin)} (${ciphertext.length} bytes) — encrypted seed phrase`);
  step(`${bold(controlReal)} (${controlData.length} bytes) ${yellow('← reveals your seed phrase')}`);
  if (addDecoy) {
    step(`${bold(controlDecoy)} (${controlData.length} bytes) ${dim('← reveals: "' + decoyMessage + '"')}`);
  }
  console.log();

  warn('Store control files SEPARATELY from the encrypted file.');
  warn('If found together, deniability is weakened.');
  console.log();

  // --- ZIP? ---
  const makeZip = await confirm('  Download as .tar.gz archive?', true);
  if (makeZip) {
    const archiveName = 'seed-backup.tar.gz';
    await createTarGz(resolve(archiveName), files);
    success(`Archive created: ${bold(archiveName)}`);
    step('Contains: ' + files.map(f => f.name).join(', '));
    console.log();
    warn('Move the archive to a secure, offline location.');
    warn('Delete the individual files if storing only the archive.');
  }

  console.log();
  success('Seed phrase protection complete.');
  console.log();
  console.log('  To decrypt:');
  console.log(`    deny-sh decrypt -i ${outputBin} -p1 <pass> -p2 <pass> -c ${controlReal}`);
  console.log();
}
