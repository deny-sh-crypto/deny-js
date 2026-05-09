import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  encrypt,
  decrypt,
  generateDeniableControl,
  generateControlData,
  encryptText,
  decryptText,
  deriveKey,
  HEADER_LENGTH,
} from '../index.js';

describe('deny-sh', () => {
  const pw1 = 'agent0018765432!unconditional';
  const pw2 = 'unconditional1234567Bagent001';

  describe('basic encrypt/decrypt', () => {
    it('should encrypt and decrypt a message', () => {
      const message = new TextEncoder().encode('Meet Me At 2pm Tomorrow');
      const controlData = generateControlData(message.length + 4);

      const { ciphertext } = encrypt(message, { password1: pw1, password2: pw2, controlData });
      const { plaintext } = decrypt(ciphertext, { password1: pw1, password2: pw2, controlData });

      assert.deepEqual(plaintext, message);
    });

    it('should encrypt and decrypt empty message', () => {
      const message = new Uint8Array(0);
      const controlData = generateControlData(4);

      const { ciphertext } = encrypt(message, { password1: pw1, password2: pw2, controlData });
      const { plaintext } = decrypt(ciphertext, { password1: pw1, password2: pw2, controlData });

      assert.deepEqual(plaintext, message);
    });

    it('should encrypt and decrypt large data', () => {
      const message = new Uint8Array(1024 * 100); // 100KB
      for (let i = 0; i < message.length; i++) message[i] = i % 256;
      const controlData = generateControlData(message.length + 4);

      const { ciphertext } = encrypt(message, { password1: pw1, password2: pw2, controlData });
      const { plaintext } = decrypt(ciphertext, { password1: pw1, password2: pw2, controlData });

      assert.deepEqual(plaintext, message);
    });

    it('should produce different ciphertext each time (random salt+IV)', () => {
      const message = new TextEncoder().encode('Same message');
      const controlData = generateControlData(message.length + 4);

      const { ciphertext: c1 } = encrypt(message, { password1: pw1, password2: pw2, controlData });
      const { ciphertext: c2 } = encrypt(message, { password1: pw1, password2: pw2, controlData });

      // Salt and IV are random, so ciphertexts differ
      assert.notDeepEqual(c1, c2);
    });

    it('should fail with wrong password', () => {
      const message = new TextEncoder().encode('Secret');
      const controlData = generateControlData(message.length + 4);

      const { ciphertext } = encrypt(message, { password1: pw1, password2: pw2, controlData });
      const { plaintext } = decrypt(ciphertext, {
        password1: 'wrong',
        password2: pw2,
        controlData,
      });

      // Should not match (CTR mode won't throw, just garbles output)
      assert.notDeepEqual(plaintext, message);
    });

    it('should fail with wrong control data', () => {
      const message = new TextEncoder().encode('Secret');
      const controlData = generateControlData(message.length + 4);
      const wrongControl = generateControlData(message.length + 4);

      const { ciphertext } = encrypt(message, { password1: pw1, password2: pw2, controlData });
      const { plaintext } = decrypt(ciphertext, {
        password1: pw1,
        password2: pw2,
        controlData: wrongControl,
      });

      assert.notDeepEqual(plaintext, message);
    });

    it('should reject control data shorter than plaintext', () => {
      const message = new TextEncoder().encode('Hello world');
      const shortControl = generateControlData(3);

      assert.throws(
        () => encrypt(message, { password1: pw1, password2: pw2, controlData: shortControl }),
        /Control data.*must be/
      );
    });
  });

  describe('deniable encryption', () => {
    it('should generate control data that decrypts to a different message', () => {
      const realMessage = new TextEncoder().encode('Meet Me At 2pm Tomorrow');
      const fakeMessage = new TextEncoder().encode('Kill KyK In One Month');
      const controlData = generateControlData(realMessage.length + 4);

      // Encrypt the real message
      const { ciphertext } = encrypt(realMessage, { password1: pw1, password2: pw2, controlData });

      // Verify real decryption works
      const { plaintext: realDecrypted } = decrypt(ciphertext, {
        password1: pw1,
        password2: pw2,
        controlData,
      });
      assert.deepEqual(realDecrypted, realMessage);

      // Generate deniable control data
      const { controlData: fakeControl } = generateDeniableControl(
        ciphertext, pw1, pw2, fakeMessage
      );

      // Same ciphertext + same passwords + different control = different message
      const { plaintext: fakeDecrypted } = decrypt(ciphertext, {
        password1: pw1,
        password2: pw2,
        controlData: fakeControl,
      });

      // The first N bytes should match the fake message
      assert.deepEqual(fakeDecrypted, fakeMessage);
    });

    it('should work with shorter fake message than original', () => {
      const realMessage = new TextEncoder().encode('This is a long secret message with details');
      const fakeMessage = new TextEncoder().encode('Nothing here');
      const controlData = generateControlData(realMessage.length + 4);

      const { ciphertext } = encrypt(realMessage, { password1: pw1, password2: pw2, controlData });

      const { controlData: fakeControl } = generateDeniableControl(
        ciphertext, pw1, pw2, fakeMessage
      );

      const { plaintext: fakeDecrypted } = decrypt(ciphertext, {
        password1: pw1,
        password2: pw2,
        controlData: fakeControl,
      });

      assert.deepEqual(fakeDecrypted, fakeMessage);
    });

    it('should produce control data indistinguishable from random', () => {
      const realMessage = new TextEncoder().encode('Secret plans for world domination');
      const fakeMessage = new TextEncoder().encode('Shopping list: eggs, milk');
      const controlData = generateControlData(realMessage.length + 4);

      const { ciphertext } = encrypt(realMessage, { password1: pw1, password2: pw2, controlData });

      const { controlData: fakeControl } = generateDeniableControl(
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

    it('should allow multiple different deniable messages from same ciphertext', () => {
      const realMessage = new TextEncoder().encode('The real secret');
      const fake1 = new TextEncoder().encode('Fake message 1');
      const fake2 = new TextEncoder().encode('Fake message 2');
      const controlData = generateControlData(realMessage.length + 4);

      const { ciphertext } = encrypt(realMessage, { password1: pw1, password2: pw2, controlData });

      const { controlData: control1 } = generateDeniableControl(ciphertext, pw1, pw2, fake1);
      const { controlData: control2 } = generateDeniableControl(ciphertext, pw1, pw2, fake2);

      const { plaintext: dec1 } = decrypt(ciphertext, {
        password1: pw1, password2: pw2, controlData: control1,
      });
      const { plaintext: dec2 } = decrypt(ciphertext, {
        password1: pw1, password2: pw2, controlData: control2,
      });

      assert.deepEqual(dec1, fake1);
      assert.deepEqual(dec1, fake1);
      assert.deepEqual(dec2, fake2);
      // Control files should be different
      assert.notDeepEqual(control1, control2);
    });

    it('should deny with unicode fake messages', () => {
      const realMessage = new TextEncoder().encode('Secret plans that are quite long for testing');
      const fakeMessage = new TextEncoder().encode('日本語テスト');
      const controlData = generateControlData(realMessage.length + 4);

      const { ciphertext } = encrypt(realMessage, { password1: pw1, password2: pw2, controlData });
      const { controlData: fakeControl } = generateDeniableControl(ciphertext, pw1, pw2, fakeMessage);
      const { plaintext: fakeDecrypted } = decrypt(ciphertext, {
        password1: pw1, password2: pw2, controlData: fakeControl,
      });

      assert.deepEqual(fakeDecrypted, fakeMessage);
    });

    it('should reject fake message longer than ciphertext capacity', () => {
      const realMessage = new TextEncoder().encode('Short');
      const controlData = generateControlData(realMessage.length + 4);

      const { ciphertext } = encrypt(realMessage, { password1: pw1, password2: pw2, controlData });

      // Fake message that's longer than the encrypted payload can hold
      const tooLong = new Uint8Array(1000);
      assert.throws(
        () => generateDeniableControl(ciphertext, pw1, pw2, tooLong),
        /too long/
      );
    });

    it('should deny with empty fake message', () => {
      const realMessage = new TextEncoder().encode('Real secret');
      const fakeMessage = new Uint8Array(0);
      const controlData = generateControlData(realMessage.length + 4);

      const { ciphertext } = encrypt(realMessage, { password1: pw1, password2: pw2, controlData });
      const { controlData: fakeControl } = generateDeniableControl(ciphertext, pw1, pw2, fakeMessage);
      const { plaintext: fakeDecrypted } = decrypt(ciphertext, {
        password1: pw1, password2: pw2, controlData: fakeControl,
      });

      assert.deepEqual(fakeDecrypted, fakeMessage);
    });

    it('should deny with fake message same length as original', () => {
      const realMessage = new TextEncoder().encode('AAAA');
      const fakeMessage = new TextEncoder().encode('BBBB');
      const controlData = generateControlData(realMessage.length + 4);

      const { ciphertext } = encrypt(realMessage, { password1: pw1, password2: pw2, controlData });
      const { controlData: fakeControl } = generateDeniableControl(ciphertext, pw1, pw2, fakeMessage);
      const { plaintext: fakeDecrypted } = decrypt(ciphertext, {
        password1: pw1, password2: pw2, controlData: fakeControl,
      });

      assert.deepEqual(fakeDecrypted, fakeMessage);
    });
  });

  describe('text mode', () => {
    it('should encrypt and decrypt text via hex encoding', () => {
      const message = 'Meet Me At 2pm Tomorrow';
      const controlData = generateControlData(Buffer.byteLength(message, 'utf8') + 4);

      const hex = encryptText(message, pw1, pw2, controlData);
      assert.match(hex, /^[0-9a-f]+$/); // valid hex

      const decrypted = decryptText(hex, pw1, pw2, controlData);
      assert.equal(decrypted, message);
    });

    it('should handle unicode text', () => {
      const message = 'Привет мир 🌍 こんにちは';
      const controlData = generateControlData(Buffer.byteLength(message, 'utf8') + 4);

      const hex = encryptText(message, pw1, pw2, controlData);
      const decrypted = decryptText(hex, pw1, pw2, controlData);
      assert.equal(decrypted, message);
    });
  });

  describe('key derivation', () => {
    it('should produce consistent keys for same inputs', () => {
      const salt = new Uint8Array(32);
      const k1 = deriveKey('pass1', 'pass2', salt);
      const k2 = deriveKey('pass1', 'pass2', salt);
      assert.deepEqual(k1, k2);
    });

    it('should produce different keys for different passwords', () => {
      const salt = new Uint8Array(32);
      const k1 = deriveKey('pass1', 'pass2', salt);
      const k2 = deriveKey('pass1', 'pass3', salt);
      assert.notDeepEqual(k1, k2);
    });

    it('should produce different keys for different salts', () => {
      const salt1 = new Uint8Array(32).fill(0);
      const salt2 = new Uint8Array(32).fill(1);
      const k1 = deriveKey('pass1', 'pass2', salt1);
      const k2 = deriveKey('pass1', 'pass2', salt2);
      assert.notDeepEqual(k1, k2);
    });

    it('password order matters', () => {
      const salt = new Uint8Array(32);
      const k1 = deriveKey('alpha', 'beta', salt);
      const k2 = deriveKey('beta', 'alpha', salt);
      assert.notDeepEqual(k1, k2);
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
