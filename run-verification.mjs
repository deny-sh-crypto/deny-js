/**
 * deny.sh - Verification Suite Runner
 * Runs all tests with live progress output.
 */

import { randomBytes, createHash } from 'node:crypto';
import {
  encrypt,
  decrypt,
  generateDeniableControl,
  generateControlData,
  deriveKey,
  encryptText,
  decryptText,
  SALT_LENGTH,
  IV_LENGTH,
  HEADER_LENGTH,
} from './dist/src/index.js';

let passed = 0;
let failed = 0;
const results = [];

function log(msg) { process.stdout.write(msg + '\n'); }

function pass(name, detail) {
  passed++;
  results.push({ name, status: 'PASS', detail });
  log(`  ✓ ${name}${detail ? ' — ' + detail : ''}`);
}

function fail(name, reason) {
  failed++;
  results.push({ name, status: 'FAIL', reason });
  log(`  ✗ ${name} — ${reason}`);
}

// ─── Helpers ───

function entropy(data) {
  const freq = new Float64Array(256);
  for (let i = 0; i < data.length; i++) freq[data[i]]++;
  let h = 0;
  for (let i = 0; i < 256; i++) {
    if (freq[i] > 0) {
      const p = freq[i] / data.length;
      h -= p * Math.log2(p);
    }
  }
  return h;
}

function chiSquared(data) {
  const expected = data.length / 256;
  const freq = new Float64Array(256);
  for (let i = 0; i < data.length; i++) freq[data[i]]++;
  let chi2 = 0;
  for (let i = 0; i < 256; i++) {
    const diff = freq[i] - expected;
    chi2 += (diff * diff) / expected;
  }
  return chi2;
}

function ksStatistic(data) {
  const sorted = Array.from(data).sort((a, b) => a - b);
  const n = sorted.length;
  let maxD = 0;
  for (let i = 0; i < n; i++) {
    const empirical = (i + 1) / n;
    const theoretical = (sorted[i] + 1) / 256;
    maxD = Math.max(maxD, Math.abs(empirical - theoretical));
  }
  return maxD;
}

function serialCorrelation(data) {
  if (data.length < 2) return 0;
  let sum = 0;
  for (let i = 0; i < data.length; i++) sum += data[i];
  const mean = sum / data.length;
  let num = 0, den = 0;
  for (let i = 0; i < data.length - 1; i++) {
    num += (data[i] - mean) * (data[i + 1] - mean);
    den += (data[i] - mean) ** 2;
  }
  den += (data[data.length - 1] - mean) ** 2;
  return den === 0 ? 0 : num / den;
}

function deepEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

// ═══════════════════════════════════════════════════════════
log('');
log('╔══════════════════════════════════════════════╗');
log('║  deny.sh - Cryptographic Verification Suite  ║');
log('║  ' + new Date().toISOString().slice(0, 19) + ' UTC                  ║');
log('╚══════════════════════════════════════════════╝');
log('');

// ─── 1. Statistical Indistinguishability ───

log('━━━ 1. Statistical Indistinguishability ━━━');

{
  const SAMPLES = 1000;
  const realMessage = new TextEncoder().encode('The launch code is ALPHA-7749');
  const fakeMessage = new TextEncoder().encode('Dinner at 8pm');
  const pw1 = 'test-password-1';
  const pw2 = 'test-password-2';
  const controlData = generateControlData(256);
  const { ciphertext } = encrypt(realMessage, { password1: pw1, password2: pw2, controlData });

  log(`  Running ${SAMPLES} chi-squared samples...`);
  const t0 = Date.now();
  const chiValues = [];
  for (let i = 0; i < SAMPLES; i++) {
    const { controlData: fc } = generateDeniableControl(ciphertext, pw1, pw2, fakeMessage);
    chiValues.push(chiSquared(fc));
    if ((i + 1) % 200 === 0) process.stdout.write(`    ${i + 1}/${SAMPLES}...\n`);
  }
  const passing = chiValues.filter(v => v < 310).length;
  const passRate = passing / SAMPLES;
  const elapsed = ((Date.now() - t0) / 1000).toFixed(1);

  if (passRate >= 0.98) {
    pass(`Chi-squared: ${(passRate * 100).toFixed(1)}% pass rate (${elapsed}s)`, `${passing}/${SAMPLES} within critical value`);
  } else {
    fail(`Chi-squared: ${(passRate * 100).toFixed(1)}% pass rate`, `below 98% threshold`);
  }
}

{
  // Use 256-byte messages so control files are large enough for meaningful entropy measurement
  const realMessage = new Uint8Array(256); randomBytes(256).copy(Buffer.from(realMessage.buffer));
  const fakeMessage = new Uint8Array(200); randomBytes(200).copy(Buffer.from(fakeMessage.buffer));
  const pw1 = 'entropy-test-1';
  const pw2 = 'entropy-test-2';
  const controlData = generateControlData(512);
  const { ciphertext } = encrypt(realMessage, { password1: pw1, password2: pw2, controlData });

  const entropies = [];
  for (let i = 0; i < 500; i++) {
    const { controlData: fc } = generateDeniableControl(ciphertext, pw1, pw2, fakeMessage);
    entropies.push(entropy(fc));
  }
  const avgEntropy = entropies.reduce((a, b) => a + b, 0) / entropies.length;

  if (avgEntropy > 7.0) {
    pass(`Entropy: avg ${avgEntropy.toFixed(3)} bits/byte`, `max possible 8.0`);
  } else {
    fail(`Entropy: avg ${avgEntropy.toFixed(3)} bits/byte`, `below 7.0 threshold`);
  }
}

{
  const realMessage = new TextEncoder().encode('Wire $50K to account 4419');
  const fakeMessage = new TextEncoder().encode('Grocery: eggs milk');
  const pw1 = 'ks-test-1';
  const pw2 = 'ks-test-2';
  const controlData = generateControlData(512);
  const { ciphertext } = encrypt(realMessage, { password1: pw1, password2: pw2, controlData });

  const ksValues = [];
  for (let i = 0; i < 500; i++) {
    const { controlData: fc } = generateDeniableControl(ciphertext, pw1, pw2, fakeMessage);
    ksValues.push(ksStatistic(fc));
  }
  const avgKS = ksValues.reduce((a, b) => a + b, 0) / ksValues.length;

  if (avgKS < 0.25) {
    pass(`Kolmogorov-Smirnov: avg D=${avgKS.toFixed(4)}`, `uniform distribution confirmed`);
  } else {
    fail(`Kolmogorov-Smirnov: avg D=${avgKS.toFixed(4)}`, `exceeds 0.25 threshold`);
  }
}

{
  const pw1 = 'compare-1';
  const pw2 = 'compare-2';
  // Use 200-byte messages for meaningful statistical comparison
  const realMessage = new Uint8Array(200); for (let i = 0; i < 200; i++) realMessage[i] = i;
  const fakeMessage = new Uint8Array(150); for (let i = 0; i < 150; i++) fakeMessage[i] = 255 - i;

  const realEntropies = [];
  const fakeEntropies = [];
  const realChis = [];
  const fakeChis = [];

  for (let i = 0; i < 200; i++) {
    const realControl = generateControlData(256);
    realEntropies.push(entropy(realControl));
    realChis.push(chiSquared(realControl));

    const { ciphertext } = encrypt(realMessage, { password1: pw1, password2: pw2, controlData: realControl });
    const { controlData: fc } = generateDeniableControl(ciphertext, pw1, pw2, fakeMessage);
    fakeEntropies.push(entropy(fc));
    fakeChis.push(chiSquared(fc));
  }

  const avgRealEnt = realEntropies.reduce((a, b) => a + b, 0) / realEntropies.length;
  const avgFakeEnt = fakeEntropies.reduce((a, b) => a + b, 0) / fakeEntropies.length;
  const avgRealChi = realChis.reduce((a, b) => a + b, 0) / realChis.length;
  const avgFakeChi = fakeChis.reduce((a, b) => a + b, 0) / fakeChis.length;
  const entGap = Math.abs(avgRealEnt - avgFakeEnt);
  const chiRatio = avgFakeChi / avgRealChi;

  if (entGap < 0.5 && chiRatio > 0.8 && chiRatio < 1.2) {
    pass(`Real vs deniable comparison`, `entropy gap=${entGap.toFixed(4)}, chi ratio=${chiRatio.toFixed(3)}`);
  } else {
    fail(`Real vs deniable comparison`, `entropy gap=${entGap.toFixed(4)}, chi ratio=${chiRatio.toFixed(3)}`);
  }
}

{
  const pw1 = 'serial-1';
  const pw2 = 'serial-2';
  // Use 256-byte messages for meaningful serial correlation measurement
  const realMessage = new Uint8Array(256); randomBytes(256).copy(Buffer.from(realMessage.buffer));
  const fakeMessage = new Uint8Array(200); randomBytes(200).copy(Buffer.from(fakeMessage.buffer));
  const controlData = generateControlData(512);
  const { ciphertext } = encrypt(realMessage, { password1: pw1, password2: pw2, controlData });

  const correlations = [];
  for (let i = 0; i < 500; i++) {
    const { controlData: fc } = generateDeniableControl(ciphertext, pw1, pw2, fakeMessage);
    correlations.push(serialCorrelation(fc));
  }
  const avgCorr = correlations.reduce((a, b) => a + b, 0) / correlations.length;

  if (Math.abs(avgCorr) < 0.1) {
    pass(`Serial correlation: ${avgCorr.toFixed(6)}`, `no byte-to-byte patterns`);
  } else {
    fail(`Serial correlation: ${avgCorr.toFixed(6)}`, `exceeds 0.1 threshold`);
  }
}

// ─── 2. Ciphertext Invariance ───

log('');
log('━━━ 2. Ciphertext Invariance ━━━');

{
  const pw1 = 'invariance-1';
  const pw2 = 'invariance-2';
  const realMessage = new TextEncoder().encode('Real secret message here');
  const controlData = generateControlData(256);
  const { ciphertext } = encrypt(realMessage, { password1: pw1, password2: pw2, controlData });
  const ctHash = createHash('sha256').update(ciphertext).digest('hex');

  const fakeMessages = ['Short', 'Call mom', 'Weather', 'Notes', 'abc'];
  let allGood = true;
  for (const fm of fakeMessages) {
    const fb = new TextEncoder().encode(fm);
    const { controlData: fc } = generateDeniableControl(ciphertext, pw1, pw2, fb);
    const { plaintext } = decrypt(ciphertext, { password1: pw1, password2: pw2, controlData: fc });
    if (new TextDecoder().decode(plaintext) !== fm) { allGood = false; break; }
    if (createHash('sha256').update(ciphertext).digest('hex') !== ctHash) { allGood = false; break; }
  }

  const { plaintext: real } = decrypt(ciphertext, { password1: pw1, password2: pw2, controlData });
  if (new TextDecoder().decode(real) !== 'Real secret message here') allGood = false;

  if (allGood) pass(`Ciphertext unchanged across 5 deniable decryptions`);
  else fail(`Ciphertext changed during deniable operations`);
}

{
  const pw1 = 'bit-1';
  const pw2 = 'bit-2';
  const msg = new TextEncoder().encode('Bit analysis test message');
  const cd = generateControlData(256);
  const { ciphertext } = encrypt(msg, { password1: pw1, password2: pw2, controlData: cd });
  const hash = createHash('sha256').update(ciphertext).digest('hex');

  let mutated = false;
  for (let i = 0; i < 50; i++) {
    const fm = new TextEncoder().encode(`Fake ${i}`);
    generateDeniableControl(ciphertext, pw1, pw2, fm);
    if (createHash('sha256').update(ciphertext).digest('hex') !== hash) { mutated = true; break; }
  }

  if (!mutated) pass(`No ciphertext mutation across 50 deny operations`);
  else fail(`Ciphertext mutated during deny`);
}

// ─── 3. Length Independence ───

log('');
log('━━━ 3. Length Independence ━━━');

{
  const pw1 = 'len-1';
  const pw2 = 'len-2';
  const realMsg = new TextEncoder().encode('A longer secret message with plenty of room for fakes');
  const cd = generateControlData(256);
  const { ciphertext } = encrypt(realMsg, { password1: pw1, password2: pw2, controlData: cd });
  const ctLen = ciphertext.length;

  const short = new TextEncoder().encode('Hi');
  const med = new TextEncoder().encode('Medium length msg');
  const { controlData: sc } = generateDeniableControl(ciphertext, pw1, pw2, short);
  const { controlData: mc } = generateDeniableControl(ciphertext, pw1, pw2, med);

  const sr = decrypt(ciphertext, { password1: pw1, password2: pw2, controlData: sc });
  const mr = decrypt(ciphertext, { password1: pw1, password2: pw2, controlData: mc });

  if (new TextDecoder().decode(sr.plaintext) === 'Hi' &&
      new TextDecoder().decode(mr.plaintext) === 'Medium length msg' &&
      ciphertext.length === ctLen) {
    pass(`Different length messages from same ciphertext`);
  } else {
    fail(`Length independence failed`);
  }
}

{
  const pw1 = 'prefix-1';
  const pw2 = 'prefix-2';
  let allCorrect = true;
  for (const len of [1, 10, 50, 100, 200]) {
    const msg = new Uint8Array(len).fill(0x41);
    const cd = generateControlData(256);
    const { ciphertext } = encrypt(msg, { password1: pw1, password2: pw2, controlData: cd });
    if (ciphertext.length !== HEADER_LENGTH + len + 4) { allCorrect = false; break; }
  }

  if (allCorrect) pass(`Length prefix inside encrypted zone (5 sizes verified)`);
  else fail(`Unexpected ciphertext lengths`);
}

// ─── 4. Cross-implementation (hex mode) ───

log('');
log('━━━ 4. Cross-implementation (hex mode) ━━━');

{
  const cd = generateControlData(256);
  const messages = ['Hello world', 'Unicode: \u00e9\u00f1\u00fc', '.', 'x'.repeat(200)];
  let allGood = true;
  for (const m of messages) {
    const hex = encryptText(m, 'pw1', 'pw2', cd);
    const r = decryptText(hex, 'pw1', 'pw2', cd);
    if (r !== m) { allGood = false; break; }
    if (!/^[0-9a-f]+$/.test(hex) || hex.length % 2 !== 0) { allGood = false; break; }
  }

  if (allGood) pass(`encryptText/decryptText round-trip (4 variants including unicode)`);
  else fail(`Hex mode round-trip failed`);
}

// ─── 5. Known-Answer Tests ───

log('');
log('━━━ 5. Known-Answer Tests (KATs) ━━━');

{
  const salt = new Uint8Array(32).fill(0xAA);
  const k1 = deriveKey('password1', 'password2', salt);
  const k2 = deriveKey('password1', 'password2', salt);
  if (deepEqual(k1, k2)) pass(`Key derivation is deterministic`);
  else fail(`Same inputs produced different keys`);
}

{
  const salt = new Uint8Array(32).fill(0xBB);
  const k1 = deriveKey('alpha', 'bravo', salt);
  const k2 = deriveKey('alpha', 'charlie', salt);
  const k3 = deriveKey('delta', 'bravo', salt);
  if (!deepEqual(k1, k2) && !deepEqual(k1, k3) && !deepEqual(k2, k3)) {
    pass(`Different passwords produce different keys (3 variants)`);
  } else {
    fail(`Password variation failed`);
  }
}

{
  const s1 = new Uint8Array(32).fill(0x01);
  const s2 = new Uint8Array(32).fill(0x02);
  const k1 = deriveKey('same', 'passwords', s1);
  const k2 = deriveKey('same', 'passwords', s2);
  if (!deepEqual(k1, k2)) pass(`Different salts produce different keys`);
  else fail(`Salt variation failed`);
}

{
  const salt = new Uint8Array(32).fill(0xCC);
  const k1 = deriveKey('alpha', 'bravo', salt);
  const k2 = deriveKey('bravo', 'alpha', salt);
  if (!deepEqual(k1, k2)) pass(`Password order matters (pw1/pw2 not interchangeable)`);
  else fail(`Swapped passwords produced same key`);
}

// ─── 6. Fuzz Testing ───

log('');
log('━━━ 6. Fuzz Testing ━━━');

{
  const ROUNDS = 500;
  log(`  Running ${ROUNDS} rounds with random inputs...`);
  const t0 = Date.now();
  let failures = 0;

  for (let i = 0; i < ROUNDS; i++) {
    try {
      const msgLen = Math.floor(Math.random() * 200) + 1;
      const realMessage = randomBytes(msgLen);
      const fakeLen = Math.floor(Math.random() * msgLen) + 1;
      const fakeMessage = randomBytes(fakeLen);
      const pw1 = randomBytes(8).toString('hex');
      const pw2 = randomBytes(8).toString('hex');
      const cd = generateControlData(msgLen + 4);

      const { ciphertext } = encrypt(new Uint8Array(realMessage), { password1: pw1, password2: pw2, controlData: cd });
      const { plaintext: rr } = decrypt(ciphertext, { password1: pw1, password2: pw2, controlData: cd });
      if (!deepEqual(new Uint8Array(rr), new Uint8Array(realMessage))) { failures++; continue; }

      const { controlData: fc } = generateDeniableControl(ciphertext, pw1, pw2, new Uint8Array(fakeMessage));
      const { plaintext: fr } = decrypt(ciphertext, { password1: pw1, password2: pw2, controlData: fc });
      if (!deepEqual(new Uint8Array(fr), new Uint8Array(fakeMessage))) { failures++; continue; }
    } catch (e) {
      failures++;
    }
    if ((i + 1) % 100 === 0) process.stdout.write(`    ${i + 1}/${ROUNDS}...\n`);
  }

  const elapsed = ((Date.now() - t0) / 1000).toFixed(1);
  if (failures === 0) pass(`${ROUNDS} rounds, 0 failures (${elapsed}s)`);
  else fail(`${failures}/${ROUNDS} rounds failed`);
}

{
  let allGood = true;
  for (let b = 0; b < 256; b++) {
    const msg = new Uint8Array([b]);
    const fake = new Uint8Array([(b + 128) % 256]);
    const cd = generateControlData(8);
    const { ciphertext } = encrypt(msg, { password1: 'e1', password2: 'e2', controlData: cd });
    const { plaintext } = decrypt(ciphertext, { password1: 'e1', password2: 'e2', controlData: cd });
    if (plaintext[0] !== b) { allGood = false; break; }
    const { controlData: fc } = generateDeniableControl(ciphertext, 'e1', 'e2', fake);
    const { plaintext: fr } = decrypt(ciphertext, { password1: 'e1', password2: 'e2', controlData: fc });
    if (fr[0] !== (b + 128) % 256) { allGood = false; break; }
  }

  if (allGood) pass(`All 256 single-byte values encrypt/deny/decrypt correctly`);
  else fail(`Single-byte edge case failed`);
}

// ─── 7. Security Properties ───

log('');
log('━━━ 7. Security Properties ━━━');

{
  const msg = new TextEncoder().encode('Same message every time');
  const cd = generateControlData(256);
  const hashes = new Set();
  for (let i = 0; i < 100; i++) {
    const { ciphertext } = encrypt(msg, { password1: 'sp1', password2: 'sp2', controlData: cd });
    hashes.add(createHash('sha256').update(ciphertext).digest('hex'));
  }
  if (hashes.size === 100) pass(`100 encryptions = 100 unique ciphertexts (random salt works)`);
  else fail(`Only ${hashes.size}/100 unique (salt reuse)`);
}

{
  const msg = new TextEncoder().encode('Secret message');
  const cd = generateControlData(256);
  const { ciphertext } = encrypt(msg, { password1: 'right1', password2: 'right2', controlData: cd });
  const { plaintext } = decrypt(ciphertext, { password1: 'wrong1', password2: 'wrong2', controlData: cd });
  const result = new TextDecoder().decode(plaintext);
  if (result !== 'Secret message') pass(`Wrong password produces garbage (not error)`);
  else fail(`Wrong password decrypted correctly`);
}

{
  const msg = new TextEncoder().encode('Real secret');
  const cd = generateControlData(256);
  const wc = generateControlData(256);
  const { ciphertext } = encrypt(msg, { password1: 'pw1', password2: 'pw2', controlData: cd });
  const { plaintext } = decrypt(ciphertext, { password1: 'pw1', password2: 'pw2', controlData: wc });
  if (new TextDecoder().decode(plaintext) !== 'Real secret') pass(`Wrong control file produces different message`);
  else fail(`Wrong control file decrypted correctly`);
}

{
  const msg = new Uint8Array(500).fill(0x41);
  const cd = generateControlData(512);
  const { ciphertext } = encrypt(msg, { password1: 'e1', password2: 'e2', controlData: cd });
  const encPortion = ciphertext.slice(HEADER_LENGTH);
  const e = entropy(encPortion);
  if (e > 7.0) pass(`Ciphertext entropy: ${e.toFixed(3)} bits/byte (repetitive plaintext hidden)`);
  else fail(`Ciphertext entropy too low: ${e.toFixed(3)}`);
}

{
  // Use 256-byte messages so XOR of control files has enough bytes for entropy measurement
  const msg = new Uint8Array(256); randomBytes(256).copy(Buffer.from(msg.buffer));
  const cd = generateControlData(512);
  const { ciphertext } = encrypt(msg, { password1: 'c1', password2: 'c2', controlData: cd });
  const f1 = new Uint8Array(200); randomBytes(200).copy(Buffer.from(f1.buffer));
  const f2 = new Uint8Array(180); randomBytes(180).copy(Buffer.from(f2.buffer));
  const { controlData: fc1 } = generateDeniableControl(ciphertext, 'c1', 'c2', f1);
  const { controlData: fc2 } = generateDeniableControl(ciphertext, 'c1', 'c2', f2);
  const minLen = Math.min(fc1.length, fc2.length);
  const xored = new Uint8Array(minLen);
  for (let i = 0; i < minLen; i++) xored[i] = fc1[i] ^ fc2[i];
  const e = entropy(xored);
  if (e > 5.0) pass(`Control file XOR entropy: ${e.toFixed(3)} (no correlation)`);
  else fail(`Control files correlated: XOR entropy ${e.toFixed(3)}`);
}

// ─── 8. Multiple Deniable Messages ───

log('');
log('━━━ 8. Multiple Deniable Messages ━━━');

{
  const realMsg = new TextEncoder().encode('The real secret message that is long enough for many fakes');
  const cd = generateControlData(256);
  const { ciphertext } = encrypt(realMsg, { password1: 'm1', password2: 'm2', controlData: cd });

  let allGood = true;
  for (let i = 0; i < 100; i++) {
    const fm = new TextEncoder().encode(`F${i}`);
    const { controlData: fc } = generateDeniableControl(ciphertext, 'm1', 'm2', fm);
    const { plaintext } = decrypt(ciphertext, { password1: 'm1', password2: 'm2', controlData: fc });
    if (new TextDecoder().decode(plaintext) !== `F${i}`) { allGood = false; break; }
  }

  const { plaintext: orig } = decrypt(ciphertext, { password1: 'm1', password2: 'm2', controlData: cd });
  if (new TextDecoder().decode(orig) !== 'The real secret message that is long enough for many fakes') allGood = false;

  if (allGood) pass(`100 deniable messages from 1 ciphertext + original still works`);
  else fail(`Multiple deniable messages failed`);
}

// ─── Report ───

log('');
log('══════════════════════════════════════');
const total = passed + failed;
log(`  ${passed}/${total} tests passed${failed > 0 ? `, ${failed} FAILED` : ''}`);
log('══════════════════════════════════════');
log('');

process.exit(failed > 0 ? 1 : 0);
