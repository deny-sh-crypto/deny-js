#!/usr/bin/env node

/**
 * deny-sh CLI
 *
 * Usage:
 *   deny-sh encrypt  -m "message" -p1 "pass1" -p2 "pass2" [-c control.dat] [-o output.enc]
 *   deny-sh decrypt  -i input.enc -p1 "pass1" -p2 "pass2" -c control.dat
 *   deny-sh deny     -i input.enc -p1 "pass1" -p2 "pass2" -m "fake message" [-o fake-control.dat]
 *   deny-sh generate -s 1024 [-o control.dat]
 *   deny-sh text-encrypt -m "message" -p1 "pass1" -p2 "pass2" [-c control.dat]
 *   deny-sh text-decrypt -i "hex..." -p1 "pass1" -p2 "pass2" -c control.dat
 *   deny-sh demo
 *   deny-sh protect
 *   deny-sh init
 *   deny-sh env protect .env / env restore .env.deny
 *   deny-sh vault set|get|list|delete KEY [value]
 *   deny-sh verify
 *   deny-sh status
 */

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { resolve } from 'node:path';
import {
  encrypt,
  decrypt,
  generateDeniableControl,
  generateControlData,
  encryptText,
  decryptText,
} from './index.js';
import { bold, cyan, dim, green, red, yellow, banner, success, error as err, progressBar } from './utils/display.js';
import { hiddenInput, confirm, isStdinPiped, readStdin } from './utils/prompts.js';

// --- Argument Parsing ---

function parseArgs(args: string[]): { command: string; subArgs: string[]; flags: Record<string, string> } {
  const command = args[0] || 'help';
  const flags: Record<string, string> = {};
  const subArgs: string[] = [];
  let pastCommand = false;

  for (let i = 1; i < args.length; i++) {
    const arg = args[i]!;
    if (arg.startsWith('-')) {
      pastCommand = true;
      const key = arg.replace(/^-+/, '');
      const next = args[i + 1];
      const value = next && !next.startsWith('-') ? (i++, next) : 'true';
      flags[key] = value;
    } else if (!pastCommand) {
      subArgs.push(arg);
    } else {
      // positional after flags: collect as remaining subArgs
      subArgs.push(arg);
    }
  }

  return { command, subArgs, flags };
}

function requireFlag(flags: Record<string, string>, key: string, label: string): string {
  const value = flags[key];
  if (!value || value === 'true') {
    console.error(`Error: ${label} (-${key}) is required`);
    process.exit(1);
  }
  return value;
}

// --- Commands ---

async function cmdEncrypt(flags: Record<string, string>): Promise<void> {
  let message: string;

  if (flags['m']) {
    message = flags['m'];
  } else if (isStdinPiped()) {
    // Read from stdin when no -m flag provided
    message = await readStdin();
  } else if (flags['interactive'] === 'true' || flags['I'] === 'true') {
    message = await hiddenInput('  Message to encrypt: ');
    process.stdout.write('\n');
  } else {
    message = requireFlag(flags, 'm', 'Message');
  }

  let pw1: string, pw2: string;
  if (flags['interactive'] === 'true' || flags['I'] === 'true') {
    pw1 = await hiddenInput('  Password 1: '); process.stdout.write('\n');
    pw2 = await hiddenInput('  Password 2: '); process.stdout.write('\n');
  } else {
    pw1 = requireFlag(flags, 'p1', 'Password 1');
    pw2 = requireFlag(flags, 'p2', 'Password 2');
  }

  const controlPath = flags['c'];
  const outputPath = flags['o'] || 'encrypted.bin';
  const controlOutPath = flags['co'] || 'control.dat';

  const plaintext = new TextEncoder().encode(message);

  let controlData: Uint8Array;
  if (controlPath && existsSync(controlPath)) {
    controlData = new Uint8Array(readFileSync(resolve(controlPath)));
    if (controlData.length < plaintext.length) {
      console.error(`Error: Control file (${controlData.length} bytes) must be >= message (${plaintext.length} bytes)`);
      process.exit(1);
    }
  } else {
    controlData = generateControlData(Math.max(plaintext.length + 4, 256));
    writeFileSync(resolve(controlOutPath), controlData);
    console.log(`Generated control file: ${controlOutPath} (${controlData.length} bytes)`);
  }

  const { ciphertext } = encrypt(plaintext, { password1: pw1, password2: pw2, controlData });
  writeFileSync(resolve(outputPath), ciphertext);
  console.log(`Encrypted: ${outputPath} (${ciphertext.length} bytes)`);
}

async function cmdDecrypt(flags: Record<string, string>): Promise<void> {
  const inputPath = requireFlag(flags, 'i', 'Input file');

  let pw1: string, pw2: string;
  if (flags['interactive'] === 'true' || flags['I'] === 'true') {
    pw1 = await hiddenInput('  Password 1: '); process.stdout.write('\n');
    pw2 = await hiddenInput('  Password 2: '); process.stdout.write('\n');
  } else {
    pw1 = requireFlag(flags, 'p1', 'Password 1');
    pw2 = requireFlag(flags, 'p2', 'Password 2');
  }

  const controlPath = requireFlag(flags, 'c', 'Control file');

  const ciphertext = new Uint8Array(readFileSync(resolve(inputPath)));
  const controlData = new Uint8Array(readFileSync(resolve(controlPath)));

  const { plaintext } = decrypt(ciphertext, { password1: pw1, password2: pw2, controlData });
  const text = new TextDecoder().decode(plaintext);

  if (flags['o'] === '-' || flags['output'] === '-') {
    process.stdout.write(text);
  } else if (flags['o']) {
    writeFileSync(resolve(flags['o']), text, 'utf8');
    console.log(`Decrypted → ${flags['o']}`);
  } else {
    console.log(text);
  }
}

function cmdDeny(flags: Record<string, string>): void {
  const inputPath = requireFlag(flags, 'i', 'Input file');
  const pw1 = requireFlag(flags, 'p1', 'Password 1');
  const pw2 = requireFlag(flags, 'p2', 'Password 2');
  const fakeMessage = requireFlag(flags, 'm', 'Fake message');
  const outputPath = flags['o'] || 'deny-control.dat';

  const ciphertext = new Uint8Array(readFileSync(resolve(inputPath)));
  const desiredPlaintext = new TextEncoder().encode(fakeMessage);

  const { controlData } = generateDeniableControl(ciphertext, pw1, pw2, desiredPlaintext);
  writeFileSync(resolve(outputPath), controlData);
  console.log(`Deniable control file: ${outputPath} (${controlData.length} bytes)`);
  console.log(`\nDecrypting with this control file will produce:\n"${fakeMessage}"`);
}

function cmdGenerate(flags: Record<string, string>): void {
  const size = parseInt(flags['s'] || '1024', 10);
  const outputPath = flags['o'] || 'control.dat';

  const data = generateControlData(size);
  writeFileSync(resolve(outputPath), data);
  console.log(`Generated: ${outputPath} (${size} bytes, cryptographically random)`);
}

async function cmdTextEncrypt(flags: Record<string, string>): Promise<void> {
  let message: string;

  if (flags['m']) {
    message = flags['m'];
  } else if (isStdinPiped()) {
    message = await readStdin();
  } else {
    message = requireFlag(flags, 'm', 'Message');
  }

  const pw1 = requireFlag(flags, 'p1', 'Password 1');
  const pw2 = requireFlag(flags, 'p2', 'Password 2');
  const controlPath = flags['c'];
  const controlOutPath = flags['co'] || 'control.dat';

  let controlData: Uint8Array;
  const msgBytes = Buffer.byteLength(message, 'utf8');

  if (controlPath && existsSync(controlPath)) {
    controlData = new Uint8Array(readFileSync(resolve(controlPath)));
  } else {
    controlData = generateControlData(Math.max(msgBytes + 4, 256));
    writeFileSync(resolve(controlOutPath), controlData);
    console.error(`Generated control file: ${controlOutPath}`);
  }

  const hex = encryptText(message, pw1, pw2, controlData);
  console.log(hex);
}

function cmdTextDecrypt(flags: Record<string, string>): void {
  const hex = requireFlag(flags, 'i', 'Hex ciphertext');
  const pw1 = requireFlag(flags, 'p1', 'Password 1');
  const pw2 = requireFlag(flags, 'p2', 'Password 2');
  const controlPath = requireFlag(flags, 'c', 'Control file');

  const controlData = new Uint8Array(readFileSync(resolve(controlPath)));
  const message = decryptText(hex, pw1, pw2, controlData);
  console.log(message);
}

async function cmdDemo(): Promise<void> {
  const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

  banner('Deniable Encryption Demo');

  const realMessage = 'Launch the product on Monday at 9am';
  const fakeMessage = 'Team lunch moved to Thursday';
  const pw1 = 'correct-horse';
  const pw2 = 'battery-staple';

  console.log(`  ${dim('Real message:')}  ${green('"' + realMessage + '"')}`);
  console.log(`  ${dim('Fake message:')}  ${yellow('"' + fakeMessage + '"')}`);
  console.log(`  ${dim('Password 1:')}    "${pw1}"`);
  console.log(`  ${dim('Password 2:')}    "${pw2}"`);
  console.log();
  await sleep(500);

  // Step 1: Encrypt
  console.log(`  ${bold('Step 1:')} Generating control file and encrypting...`);
  for (const pct of [0, 20, 50, 80, 100]) {
    process.stdout.write(`\r  ${progressBar(pct)}   `);
    await sleep(120);
  }
  process.stdout.write('\n');

  const plaintext = new TextEncoder().encode(realMessage);
  const controlData = generateControlData(plaintext.length + 4);
  const { ciphertext } = encrypt(plaintext, { password1: pw1, password2: pw2, controlData });
  const hexSlice = Buffer.from(ciphertext).toString('hex').slice(0, 64);
  console.log(`\n  ${dim('Ciphertext:')} ${hexSlice}...`);
  console.log(`  ${dim('           ')} (${ciphertext.length} bytes total)\n`);
  await sleep(600);

  // Step 2: Normal decrypt
  console.log(`  ${bold('Step 2:')} Decrypt with real control file:`);
  const { plaintext: decrypted } = decrypt(ciphertext, { password1: pw1, password2: pw2, controlData });
  await sleep(400);
  console.log(`  ${green('→')} "${new TextDecoder().decode(decrypted)}"\n`);
  await sleep(600);

  // Step 3: Generate deniable control
  console.log(`  ${bold('Step 3:')} Generate deniable control file for fake message...`);
  const fakeBytes = new TextEncoder().encode(fakeMessage);
  const { controlData: fakeControl } = generateDeniableControl(ciphertext, pw1, pw2, fakeBytes);
  await sleep(400);
  console.log(`  ${dim('→')} New control file created (looks identical to real one)\n`);
  await sleep(400);

  // Step 4: Decrypt with fake control
  console.log(`  ${bold('Step 4:')} Decrypt same ciphertext with fake control file:`);
  const { plaintext: fakeDecrypted } = decrypt(ciphertext, { password1: pw1, password2: pw2, controlData: fakeControl });
  const fakeResult = new TextDecoder().decode(fakeDecrypted.slice(0, fakeBytes.length));
  await sleep(400);
  console.log(`  ${yellow('→')} "${fakeResult}"\n`);
  await sleep(500);

  // Step 5: Visual comparison
  const realHex = Buffer.from(controlData.slice(0, 16)).toString('hex');
  const fakeHex = Buffer.from(fakeControl.slice(0, 16)).toString('hex');
  console.log(`  ${bold('Step 5:')} Compare the two control files:`);
  console.log(`  ${dim('Real:')} ${realHex}...`);
  console.log(`  ${dim('Fake:')} ${fakeHex}...`);
  console.log();
  await sleep(400);

  console.log(`  ${green('✓')} ${bold('Both look like random data. No way to tell which is "real".')}`);
  console.log(`  ${dim('Same ciphertext. Same passwords. Different control file = different message.')}`);
  console.log();
}

function showHelp(): void {
  console.log(`
  ${bold(cyan('deny-sh'))} — Deniable encryption with plausible deniability

  ${bold('Core commands:')}
    encrypt        Encrypt a message or file
    decrypt        Decrypt a file
    deny           Generate a deniable control file
    generate       Generate a random control file
    text-encrypt   Encrypt text to hex string (for messaging)
    text-decrypt   Decrypt hex string back to text
    demo           Interactive demo with step-by-step walkthrough

  ${bold('Wizard commands:')}
    protect        Interactive seed phrase protection wizard
    init           Initialise .deny/ in current project
    env protect    Encrypt a .env file
    env restore    Restore an encrypted .env file
    vault          Encrypted key-value store

  ${bold('Integrations:')}
    1p             1Password integration (push/pull/list/status)
    bw             Bitwarden integration (push/pull/list/status)
    backup         Cloud backup (push/pull/list/config/auto)

  ${bold('Info commands:')}
    verify         Run encryption/deniability test suite
    status         Show .deny/ state and version info
    help           Show this help

  ${bold('Core options:')}
    -m   Message text
    -p1  Password 1
    -p2  Password 2
    -c   Control file path
    -co  Control file output path (default: control.dat)
    -i   Input file or hex string
    -o   Output file path (use - for stdout)
    -s   Size in bytes (for generate)
    -I, --interactive  Prompt for passwords interactively

  ${bold('Stdin support:')}
    cat secret.txt | deny-sh encrypt -p1 pw1 -p2 pw2
    cat msg.txt | deny-sh text-encrypt -p1 pw1 -p2 pw2

  ${bold('Examples:')}
    deny-sh encrypt -m "Secret" -p1 "pass1" -p2 "pass2"
    deny-sh decrypt -i encrypted.bin -p1 "pass1" -p2 "pass2" -c control.dat
    deny-sh deny -i encrypted.bin -p1 "p1" -p2 "p2" -m "Fake" -o fake.dat
    deny-sh protect
    deny-sh env protect .env
    deny-sh vault set AWS_KEY sk-abc123
    deny-sh verify
`);
}

// --- Main ---

const { command, subArgs, flags } = parseArgs(process.argv.slice(2));

(async () => {
  switch (command) {
    case 'encrypt':       await cmdEncrypt(flags); break;
    case 'decrypt':       await cmdDecrypt(flags); break;
    case 'deny':          cmdDeny(flags); break;
    case 'generate':      cmdGenerate(flags); break;
    case 'text-encrypt':  await cmdTextEncrypt(flags); break;
    case 'text-decrypt':  cmdTextDecrypt(flags); break;
    case 'demo':          await cmdDemo(); break;

    case 'protect': {
      const { cmdProtect } = await import('./commands/protect.js');
      await cmdProtect(flags);
      break;
    }
    case 'init': {
      const { cmdInit } = await import('./commands/init.js');
      await cmdInit(flags);
      break;
    }
    case 'env': {
      const { cmdEnv } = await import('./commands/env.js');
      await cmdEnv(subArgs, flags);
      break;
    }
    case 'vault': {
      const { cmdVault } = await import('./commands/vault.js');
      await cmdVault(subArgs, flags);
      break;
    }
    case 'verify': {
      const { cmdVerify } = await import('./commands/verify.js');
      await cmdVerify(flags);
      break;
    }
    case 'status': {
      const { cmdStatus } = await import('./commands/status.js');
      await cmdStatus(flags);
      break;
    }

    case '1p':
    case '1password':
    case 'onepassword': {
      const { cmd1Password } = await import('./commands/onepassword.js');
      await cmd1Password(subArgs, flags);
      break;
    }
    case 'bw':
    case 'bitwarden': {
      const { cmdBitwarden } = await import('./commands/bitwarden.js');
      await cmdBitwarden(subArgs, flags);
      break;
    }
    case 'backup': {
      const { cmdBackup } = await import('./commands/backup.js');
      await cmdBackup(subArgs, flags);
      break;
    }

    case 'help':
    case '--help':
    case '-h':            showHelp(); break;
    default:
      console.error(`Unknown command: ${command}`);
      showHelp();
      process.exit(1);
  }
})();
