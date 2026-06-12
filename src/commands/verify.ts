/**
 * verify.ts — deny-sh verify
 * Runs encryption/decryption round-trips and deniability tests.
 */

import {
  encrypt,
  decrypt,
  generateControlData,
  generateDeniableControl,
  encryptText,
  decryptText,
  bucketedPayloadLength,
} from '../index.js';
import { banner, bold, green, red, dim, success as passLog } from '../utils/display.js';

interface TestResult {
  name: string;
  pass: boolean;
  note?: string;
}

const results: TestResult[] = [];

async function test(name: string, fn: () => boolean | string | Promise<boolean | string>): Promise<void> {
  let pass = false;
  let note: string | undefined;
  try {
    const res = await fn();
    if (typeof res === 'string') {
      pass = false;
      note = res;
    } else {
      pass = res;
    }
  } catch (e: unknown) {
    pass = false;
    note = e instanceof Error ? e.message : String(e);
  }
  results.push({ name, pass, note });
  const icon = pass ? green('✓') : red('✗');
  const status = pass ? '' : (note ? `  ${dim(note)}` : '');
  console.log(`  ${icon} ${name}${status}`);
}

function bytesEntropy(data: Uint8Array): number {
  const freq = new Array<number>(256).fill(0);
  for (const b of data) freq[b]!++;
  let entropy = 0;
  for (const f of freq) {
    if (f > 0) {
      const p = f / data.length;
      entropy -= p * Math.log2(p);
    }
  }
  return entropy;
}

export async function cmdVerify(_flags: Record<string, string>): Promise<void> {
  banner('Verification Suite');

  // 1. Basic round-trip
  await test('Encrypt/decrypt round-trip', async () => {
    const msg = 'Hello, deny.sh!';
    const plaintext = new TextEncoder().encode(msg);
    const controlData = generateControlData(plaintext.length + 4);
    const { ciphertext } = await encrypt(plaintext, { password1: 'pw1', password2: 'pw2', controlData });
    const { plaintext: dec } = await decrypt(ciphertext, { password1: 'pw1', password2: 'pw2', controlData });
    const result = new TextDecoder().decode(dec);
    if (result !== msg) return `Expected "${msg}", got "${result}"`;
    return true;
  });

  // 2. Wrong password produces garbage (no exception)
  await test('Wrong password produces different output', async () => {
    const msg = 'Secret';
    const plaintext = new TextEncoder().encode(msg);
    const controlData = generateControlData(plaintext.length + 4);
    const { ciphertext } = await encrypt(plaintext, { password1: 'real', password2: 'real', controlData });
    const { plaintext: dec } = await decrypt(ciphertext, { password1: 'wrong', password2: 'wrong', controlData });
    const result = new TextDecoder().decode(dec);
    return result !== msg;
  });

  // 3. Deniable control file
  await test('Deniable control file reveals fake message', async () => {
    const real = 'Real message';
    const fake = 'Fake message';
    const plaintext = new TextEncoder().encode(real);
    const controlData = generateControlData(plaintext.length + 64);
    const { ciphertext } = await encrypt(plaintext, { password1: 'pw', password2: 'pw', controlData });
    const { controlData: fakeControl } = await generateDeniableControl(
      ciphertext, 'pw', 'pw', new TextEncoder().encode(fake)
    );
    // Real control → real message
    const { plaintext: dec1 } = await decrypt(ciphertext, { password1: 'pw', password2: 'pw', controlData });
    // Fake control → fake message
    const { plaintext: dec2 } = await decrypt(ciphertext, { password1: 'pw', password2: 'pw', controlData: fakeControl });
    const r1 = new TextDecoder().decode(dec1);
    const r2 = new TextDecoder().decode(dec2);
    if (r1 !== real) return `Real decrypt failed: got "${r1}"`;
    if (r2 !== fake) return `Fake decrypt failed: got "${r2}"`;
    return true;
  });

  // 4. Control files are indistinguishable
  await test('Real and fake control files have similar entropy', async () => {
    // Use a large enough payload for entropy to be meaningful (256+ bytes)
    const msg = new Uint8Array(256);
    for (let i = 0; i < msg.length; i++) msg[i] = i & 0xff;
    const controlData = generateControlData(msg.length + 4);
    const { ciphertext } = await encrypt(msg, { password1: 'p', password2: 'p', controlData });
    const { controlData: fakeControl } = await generateDeniableControl(
      ciphertext, 'p', 'p', new Uint8Array(128).fill(0x41)
    );
    const e1 = bytesEntropy(controlData);
    const e2 = bytesEntropy(fakeControl);
    // Both should be high entropy (> 7 bits/byte) with 256-byte random data
    if (e1 < 7) return `Real control entropy too low: ${e1.toFixed(2)}`;
    if (e2 < 7) return `Fake control entropy too low: ${e2.toFixed(2)}`;
    return true;
  });

  // 5. Ciphertext entropy
  await test('Ciphertext has high entropy (> 7.5 bits/byte)', async () => {
    // Use a large payload so entropy measurement is meaningful
    const msg = new Uint8Array(512);
    for (let i = 0; i < msg.length; i++) msg[i] = (i * 7 + 13) & 0xff;
    const controlData = generateControlData(msg.length + 4);
    const { ciphertext } = await encrypt(msg, { password1: 'pass1', password2: 'pass2', controlData });
    const entropy = bytesEntropy(ciphertext.slice(48)); // skip header
    if (entropy < 7.5) return `Entropy too low: ${entropy.toFixed(4)} bits/byte`;
    return true;
  });

  // 6. Different salts each time
  await test('Each encryption produces different ciphertext (random salt/IV)', async () => {
    const msg = new TextEncoder().encode('same message');
    const controlData = generateControlData(msg.length + 4);
    const { ciphertext: ct1 } = await encrypt(msg, { password1: 'p', password2: 'p', controlData });
    const { ciphertext: ct2 } = await encrypt(msg, { password1: 'p', password2: 'p', controlData });
    const hex1 = Buffer.from(ct1).toString('hex');
    const hex2 = Buffer.from(ct2).toString('hex');
    return hex1 !== hex2;
  });

  // 7. Text mode round-trip
  await test('Text encrypt/decrypt round-trip (hex)', async () => {
    const msg = 'Text mode test: emoji 🔐 works?';
    const controlData = generateControlData(bucketedPayloadLength(Buffer.byteLength(msg, 'utf8') + 4));
    const hex = await encryptText(msg, 'p1', 'p2', controlData);
    const result = await decryptText(hex, 'p1', 'p2', controlData);
    if (result !== msg) return `Got "${result}"`;
    return true;
  });

  // 8. Large payload
  await test('Large payload (10KB) round-trip', async () => {
    const msg = new Uint8Array(10240);
    for (let i = 0; i < msg.length; i++) msg[i] = i & 0xff;
    const controlData = generateControlData(msg.length + 4);
    const { ciphertext } = await encrypt(msg, { password1: 'p1', password2: 'p2', controlData });
    const { plaintext } = await decrypt(ciphertext, { password1: 'p1', password2: 'p2', controlData });
    return plaintext.every((b, i) => b === msg[i]);
  });

  // --- Summary ---
  const passed = results.filter(r => r.pass).length;
  const total  = results.length;
  console.log();
  const allPass = passed === total;
  if (allPass) {
    console.log(`  ${green('All ' + total + ' tests passed.')}`);
  } else {
    console.log(`  ${red(passed + '/' + total + ' tests passed.')} ${red((total - passed) + ' failed.')}`);
  }
  console.log();
  process.exit(allPass ? 0 : 1);
}
