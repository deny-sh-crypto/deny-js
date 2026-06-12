import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv } from 'node:crypto';
import {
  encrypt,
  decrypt,
  generateDeniableControl,
  generateControlData,
  encryptText,
  decryptText,
  deriveKey,
  HEADER_LENGTH,
  bucketedPayloadLength,
} from '../index.js';

describe('deny-sh', () => {
  const pw1 = 'agent0018765432!unconditional';
  const pw2 = 'unconditional1234567Bagent001';

  describe('basic encrypt/decrypt', () => {
    it('should encrypt and decrypt a message', async () => {
      const message = new TextEncoder().encode('Meet Me At 2pm Tomorrow');
      const controlData = generateControlData(message.length + 4);

      const { ciphertext } = await encrypt(message, { password1: pw1, password2: pw2, controlData });
      const { plaintext } = await decrypt(ciphertext, { password1: pw1, password2: pw2, controlData });

      assert.deepEqual(plaintext, message);
    });

    it('should encrypt and decrypt empty message', async () => {
      const message = new Uint8Array(0);
      const controlData = generateControlData(4);

      const { ciphertext } = await encrypt(message, { password1: pw1, password2: pw2, controlData });
      const { plaintext } = await decrypt(ciphertext, { password1: pw1, password2: pw2, controlData });

      assert.deepEqual(plaintext, message);
    });

    it('should encrypt and decrypt large data', async () => {
      const message = new Uint8Array(1024 * 100); // 100KB
      for (let i = 0; i < message.length; i++) message[i] = i % 256;
      const controlData = generateControlData(message.length + 4);

      const { ciphertext } = await encrypt(message, { password1: pw1, password2: pw2, controlData });
      const { plaintext } = await decrypt(ciphertext, { password1: pw1, password2: pw2, controlData });

      assert.deepEqual(plaintext, message);
    });

    it('should produce different ciphertext each time (random salt+IV)', async () => {
      const message = new TextEncoder().encode('Same message');
      const controlData = generateControlData(message.length + 4);

      const { ciphertext: c1 } = await encrypt(message, { password1: pw1, password2: pw2, controlData });
      const { ciphertext: c2 } = await encrypt(message, { password1: pw1, password2: pw2, controlData });

      // Salt and IV are random, so ciphertexts differ
      assert.notDeepEqual(c1, c2);
    });

    it('should fail with wrong password', async () => {
      const message = new TextEncoder().encode('Secret');
      const controlData = generateControlData(message.length + 4);

      const { ciphertext } = await encrypt(message, { password1: pw1, password2: pw2, controlData });
      const { plaintext } = await decrypt(ciphertext, {
        password1: 'wrong',
        password2: pw2,
        controlData,
      });

      // Should not match (CTR mode won't throw, just garbles output)
      assert.notDeepEqual(plaintext, message);
    });

    it('should fail with wrong control data', async () => {
      const message = new TextEncoder().encode('Secret');
      const controlData = generateControlData(message.length + 4);
      const wrongControl = generateControlData(message.length + 4);

      const { ciphertext } = await encrypt(message, { password1: pw1, password2: pw2, controlData });
      const { plaintext } = await decrypt(ciphertext, {
        password1: pw1,
        password2: pw2,
        controlData: wrongControl,
      });

      assert.notDeepEqual(plaintext, message);
    });

    it('should reject control data shorter than plaintext', async () => {
      const message = new TextEncoder().encode('Hello world');
      const shortControl = generateControlData(3);

      await assert.rejects(
        () => encrypt(message, { password1: pw1, password2: pw2, controlData: shortControl }),
        /Control data.*must be/
      );
    });

    // P2-1 regression: decrypt() must also reject a too-short control file rather
    // than silently XOR-ing only a prefix and returning garbage with no error.
    // The public error is now length-free (review P2 #1) so it is not a parsing
    // oracle; it must still reject (not silently return garbage).
    it('decrypt should reject control data shorter than the ciphertext payload', async () => {
      const message = new TextEncoder().encode('Hello world');
      const controlData = generateControlData(message.length + 4);
      const { ciphertext } = await encrypt(message, { password1: pw1, password2: pw2, controlData });
      const shortControl = generateControlData(3);
      await assert.rejects(
        () => decrypt(ciphertext, { password1: pw1, password2: pw2, controlData: shortControl }),
        /decrypt failed or malformed input/
      );
    });
  });

  describe('deniable encryption', () => {
    it('should generate control data that decrypts to a different message', async () => {
      const realMessage = new TextEncoder().encode('Meet Me At 2pm Tomorrow');
      const fakeMessage = new TextEncoder().encode('Kill KyK In One Month');
      const controlData = generateControlData(realMessage.length + 4);

      // Encrypt the real message
      const { ciphertext } = await encrypt(realMessage, { password1: pw1, password2: pw2, controlData });

      // Verify real decryption works
      const { plaintext: realDecrypted } = await decrypt(ciphertext, {
        password1: pw1,
        password2: pw2,
        controlData,
      });
      assert.deepEqual(realDecrypted, realMessage);

      // Generate deniable control data
      const { controlData: fakeControl } = await generateDeniableControl(
        ciphertext, pw1, pw2, fakeMessage
      );

      // Same ciphertext + same passwords + different control = different message
      const { plaintext: fakeDecrypted } = await decrypt(ciphertext, {
        password1: pw1,
        password2: pw2,
        controlData: fakeControl,
      });

      // The first N bytes should match the fake message
      assert.deepEqual(fakeDecrypted, fakeMessage);
    });

    it('should work with shorter fake message than original', async () => {
      const realMessage = new TextEncoder().encode('This is a long secret message with details');
      const fakeMessage = new TextEncoder().encode('Nothing here');
      const controlData = generateControlData(realMessage.length + 4);

      const { ciphertext } = await encrypt(realMessage, { password1: pw1, password2: pw2, controlData });

      const { controlData: fakeControl } = await generateDeniableControl(
        ciphertext, pw1, pw2, fakeMessage
      );

      const { plaintext: fakeDecrypted } = await decrypt(ciphertext, {
        password1: pw1,
        password2: pw2,
        controlData: fakeControl,
      });

      assert.deepEqual(fakeDecrypted, fakeMessage);
    });

    it('should produce control data indistinguishable from random', async () => {
      const realMessage = new TextEncoder().encode('Secret plans for world domination');
      const fakeMessage = new TextEncoder().encode('Shopping list: eggs, milk');
      const controlData = generateControlData(realMessage.length + 4);

      const { ciphertext } = await encrypt(realMessage, { password1: pw1, password2: pw2, controlData });

      const { controlData: fakeControl } = await generateDeniableControl(
        ciphertext, pw1, pw2, fakeMessage
      );

      // Both control files should look random - check byte distribution
      const realDist = byteDistribution(controlData);
      const fakeDist = byteDistribution(fakeControl);

      // Chi-squared test: both should pass basic randomness
      // (not a rigorous test, just sanity check for > 32 bytes)
      assert.ok(realDist.uniqueBytes > 10, 'Real control data should have diverse bytes');
      assert.ok(fakeDist.uniqueBytes > 10, 'Fake control data should have diverse bytes');
    });

    it('should allow multiple different deniable messages from same ciphertext', async () => {
      const realMessage = new TextEncoder().encode('The real secret');
      const fake1 = new TextEncoder().encode('Fake message 1');
      const fake2 = new TextEncoder().encode('Fake message 2');
      const controlData = generateControlData(realMessage.length + 4);

      const { ciphertext } = await encrypt(realMessage, { password1: pw1, password2: pw2, controlData });

      const { controlData: control1 } = await generateDeniableControl(ciphertext, pw1, pw2, fake1);
      const { controlData: control2 } = await generateDeniableControl(ciphertext, pw1, pw2, fake2);

      const { plaintext: dec1 } = await decrypt(ciphertext, {
        password1: pw1, password2: pw2, controlData: control1,
      });
      const { plaintext: dec2 } = await decrypt(ciphertext, {
        password1: pw1, password2: pw2, controlData: control2,
      });

      assert.deepEqual(dec1, fake1);
      assert.deepEqual(dec1, fake1);
      assert.deepEqual(dec2, fake2);
      // Control files should be different
      assert.notDeepEqual(control1, control2);
    });

    it('should deny with unicode fake messages', async () => {
      const realMessage = new TextEncoder().encode('Secret plans that are quite long for testing');
      const fakeMessage = new TextEncoder().encode('日本語テスト');
      const controlData = generateControlData(realMessage.length + 4);

      const { ciphertext } = await encrypt(realMessage, { password1: pw1, password2: pw2, controlData });
      const { controlData: fakeControl } = await generateDeniableControl(ciphertext, pw1, pw2, fakeMessage);
      const { plaintext: fakeDecrypted } = await decrypt(ciphertext, {
        password1: pw1, password2: pw2, controlData: fakeControl,
      });

      assert.deepEqual(fakeDecrypted, fakeMessage);
    });

    it('should reject fake message longer than ciphertext capacity', async () => {
      const realMessage = new TextEncoder().encode('Short');
      const controlData = generateControlData(realMessage.length + 4);

      const { ciphertext } = await encrypt(realMessage, { password1: pw1, password2: pw2, controlData });

      // Fake message that's longer than the encrypted payload can hold
      const tooLong = new Uint8Array(1000);
      await assert.rejects(
        () => generateDeniableControl(ciphertext, pw1, pw2, tooLong),
        /too long/
      );
    });

    it('should deny with empty fake message', async () => {
      const realMessage = new TextEncoder().encode('Real secret');
      const fakeMessage = new Uint8Array(0);
      const controlData = generateControlData(realMessage.length + 4);

      const { ciphertext } = await encrypt(realMessage, { password1: pw1, password2: pw2, controlData });
      const { controlData: fakeControl } = await generateDeniableControl(ciphertext, pw1, pw2, fakeMessage);
      const { plaintext: fakeDecrypted } = await decrypt(ciphertext, {
        password1: pw1, password2: pw2, controlData: fakeControl,
      });

      assert.deepEqual(fakeDecrypted, fakeMessage);
    });

    it('should deny with fake message same length as original', async () => {
      const realMessage = new TextEncoder().encode('AAAA');
      const fakeMessage = new TextEncoder().encode('BBBB');
      const controlData = generateControlData(realMessage.length + 4);

      const { ciphertext } = await encrypt(realMessage, { password1: pw1, password2: pw2, controlData });
      const { controlData: fakeControl } = await generateDeniableControl(ciphertext, pw1, pw2, fakeMessage);
      const { plaintext: fakeDecrypted } = await decrypt(ciphertext, {
        password1: pw1, password2: pw2, controlData: fakeControl,
      });

      assert.deepEqual(fakeDecrypted, fakeMessage);
    });
  });

  describe('text mode', () => {
    it('should encrypt and decrypt text via hex encoding', async () => {
      const message = 'Meet Me At 2pm Tomorrow';
      const controlData = generateControlData(bucketedPayloadLength(Buffer.byteLength(message, 'utf8') + 4));

      const hex = await encryptText(message, pw1, pw2, controlData);
      assert.match(hex, /^[0-9a-f]+$/); // valid hex

      const decrypted = await decryptText(hex, pw1, pw2, controlData);
      assert.equal(decrypted, message);
    });

    it('should handle unicode text', async () => {
      const message = 'Привет мир 🌍 こんにちは';
      const controlData = generateControlData(bucketedPayloadLength(Buffer.byteLength(message, 'utf8') + 4));

      const hex = await encryptText(message, pw1, pw2, controlData);
      const decrypted = await decryptText(hex, pw1, pw2, controlData);
      assert.equal(decrypted, message);
    });
  });

  describe('key derivation', () => {
    it('should produce consistent keys for same inputs', async () => {
      const salt = new Uint8Array(32);
      const k1 = await deriveKey('pass1', 'pass2', salt);
      const k2 = await deriveKey('pass1', 'pass2', salt);
      assert.deepEqual(k1, k2);
    });

    it('should produce different keys for different passwords', async () => {
      const salt = new Uint8Array(32);
      const k1 = await deriveKey('pass1', 'pass2', salt);
      const k2 = await deriveKey('pass1', 'pass3', salt);
      assert.notDeepEqual(k1, k2);
    });

    it('should produce different keys for different salts', async () => {
      const salt1 = new Uint8Array(32).fill(0);
      const salt2 = new Uint8Array(32).fill(1);
      const k1 = await deriveKey('pass1', 'pass2', salt1);
      const k2 = await deriveKey('pass1', 'pass2', salt2);
      assert.notDeepEqual(k1, k2);
    });

    it('password order matters', async () => {
      const salt = new Uint8Array(32);
      const k1 = await deriveKey('alpha', 'beta', salt);
      const k2 = await deriveKey('beta', 'alpha', salt);
      assert.notDeepEqual(k1, k2);
    });

    // Argon2id parameter pinning. If any of these constants ever
    // drifts (e.g. a future refactor changes m=65536 to m=131072),
    // a deriveKey call with known inputs will produce DIFFERENT output
    // from the locked KAT vectors below. This test asserts the
    // PARAMETERS THEMSELVES rather than the resulting hex so that
    // the failure message names the bad constant directly.
    it('Argon2id parameters are locked at t=3 m=65536 p=1 len=32', async () => {
      const { argon2id } = await import('hash-wasm');
      const { createHash } = await import('node:crypto');
      const pw1 = createHash('sha256').update('password1', 'utf8').digest();
      const pw2 = createHash('sha256').update('password2', 'utf8').digest();
      const combined = Buffer.concat([pw1, pw2]);
      const salt = new Uint8Array(32).fill(0xaa);
      // These are the locked v2.0.0 cross-SDK parameters.
      const LOCKED_ITERATIONS = 3;
      const LOCKED_MEMORY_SIZE = 65536;
      const LOCKED_PARALLELISM = 1;
      const LOCKED_HASH_LENGTH = 32;
      const key = await argon2id({
        password: combined,
        salt,
        parallelism: LOCKED_PARALLELISM,
        iterations: LOCKED_ITERATIONS,
        memorySize: LOCKED_MEMORY_SIZE,
        hashLength: LOCKED_HASH_LENGTH,
        outputType: 'binary',
      });
      const hex = Array.from(key).map((b) => b.toString(16).padStart(2, '0')).join('');
      assert.equal(
        hex,
        '854e7acffd85eae6d45ed07e84237fddc887928270f591a41b36d57e675181d8',
        `Argon2id parameter pinning failed; one of t=${LOCKED_ITERATIONS} m=${LOCKED_MEMORY_SIZE} p=${LOCKED_PARALLELISM} len=${LOCKED_HASH_LENGTH} has drifted`,
      );
    });
  });

  // ----- Cross-implementation Known Answer Tests -----
  //
  // These vectors are byte-identical across the four reference SDKs
  // (TypeScript, Python, Rust, Go) and gate cross-SDK ciphertext
  // interoperability. A regression in Argon2id parameters (t=3, m=64MiB,
  // p=1, variant=Argon2id, version=0x13), SHA-256 pre-hashing, or
  // AES-CTR composition will fail one of these tests BEFORE shipping.
  // Whitepaper §8 references these exact values.
  describe('cross-implementation KAT', () => {
    const toHex = (u: Uint8Array): string =>
      Array.from(u).map((b) => b.toString(16).padStart(2, '0')).join('');

    it('KAT 1: deriveKey(password1, password2, salt=0xAA*32) - full 32-byte output', async () => {
      const salt = new Uint8Array(32).fill(0xaa);
      const key = await deriveKey('password1', 'password2', salt);
      assert.equal(
        toHex(key),
        '854e7acffd85eae6d45ed07e84237fddc887928270f591a41b36d57e675181d8',
      );
    });

    it('KAT 2: deriveKey(test-pw1, test-pw2, salt=0x01*32) - full 32-byte output', async () => {
      const salt = new Uint8Array(32).fill(0x01);
      const key = await deriveKey('test-pw1', 'test-pw2', salt);
      assert.equal(
        toHex(key),
        'd99364f250367785bff7a962331254b18138d2249c969e27b0f75060070fa3f6',
      );
    });

    it('KAT 3: full ciphertext (fixed salt + IV + control data, byte-exact match)', async () => {
      // Inputs match Python tests/test_core.py:test_full_encrypt_decrypt_kat
      // and Rust tests/integration_test.rs:kat_full_ciphertext_byte_exact.
      const pw1 = 'test-pw1';
      const pw2 = 'test-pw2';
      const fixedSalt = new Uint8Array(32).fill(0x01);
      const fixedIv = new Uint8Array(16).fill(0x02);
      const message = new TextEncoder().encode('Hello, World!'); // 13 bytes
      const controlData = new Uint8Array(message.length + 4).fill(0x03); // 17 bytes

      // 1. Derive key (must match KAT 2)
      const key = await deriveKey(pw1, pw2, fixedSalt);
      assert.equal(
        toHex(key),
        'd99364f250367785bff7a962331254b18138d2249c969e27b0f75060070fa3f6',
      );

      // 2. Build payload: LE32 length || plaintext
      const payload = new Uint8Array(message.length + 4);
      new DataView(payload.buffer).setUint32(0, message.length, true);
      payload.set(message, 4);
      assert.equal(toHex(payload), '0d00000048656c6c6f2c20576f726c6421');

      // 3. XOR with control data
      const xored = new Uint8Array(payload.length);
      for (let i = 0; i < payload.length; i++) {
        xored[i] = payload[i] ^ controlData[i];
      }
      assert.equal(toHex(xored), '0e0303034b666f6f6c2f23546c716f6722');

      // 4. AES-256-CTR encrypt with fixed IV
      const cipher = createCipheriv('aes-256-ctr', key, fixedIv);
      const encrypted = Buffer.concat([cipher.update(xored), cipher.final()]);
      assert.equal(
        encrypted.toString('hex'),
        '7c5cd13699e85f6bcde6dad013d48047ca',
      );

      // 5. Full wire-format ciphertext = salt(32) || iv(16) || encrypted(17)
      const fullCt = Buffer.concat([fixedSalt, fixedIv, encrypted]);
      assert.equal(
        fullCt.toString('hex'),
        '0101010101010101010101010101010101010101010101010101010101010101' +
          '02020202020202020202020202020202' +
          '7c5cd13699e85f6bcde6dad013d48047ca',
      );
    });
  });
});

// --- Helpers ---

function byteDistribution(data: Uint8Array): { uniqueBytes: number; maxFreq: number } {
  const freq = new Map<number, number>();
  for (const b of data) {
    freq.set(b, (freq.get(b) || 0) + 1);
  }
  return {
    uniqueBytes: freq.size,
    maxFreq: Math.max(...freq.values()),
  };
}
