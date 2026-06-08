import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  decryptRecord,
  encodeRecordFrame,
  encryptRecord,
  generateLocalDecoy,
} from '../record.js';
import { matchesShape } from '../decoy-engine/classifier.js';

describe('record helper', () => {
  const passwords = { p1: 'agent0018765432!unconditional', p2: 'unconditional1234567Bagent001' };

  it('round-trips real and generated decoy records', async () => {
    const result = await encryptRecord({
      real: { name: 'Alex', email: 'alex@example.com' },
      passwords,
    });

    assert.deepEqual(await decryptRecord(result.ciphertext, result.realCtrl, passwords), {
      name: 'Alex',
      email: 'alex@example.com',
    });
    assert.deepEqual(await decryptRecord(result.ciphertext, result.decoyCtrl, passwords), result.decoy);
    assert.equal(Object.keys(result.decoy).join(','), 'name,email');
  });

  it('uses explicit decoys exactly when shapes and budgets pass', async () => {
    const explicit = {
      stripe_key: 'sk_live_123456789012345678901234',
      note: 'cover',
    };
    const result = await encryptRecord({
      real: {
        stripe_key: 'sk_live_abcdefghijklmnopqrstuvwxyz123456',
        note: 'secret',
      },
      decoys: explicit,
      passwords,
    });

    assert.deepEqual(result.decoy, explicit);
    assert.deepEqual(await decryptRecord(result.ciphertext, result.decoyCtrl, passwords), explicit);
  });

  it('generates Stripe live key decoys matching the classifier shape', async () => {
    const result = await encryptRecord({
      real: { stripe_key: 'sk_live_abcdefghijklmnopqrstuvwxyz123456' },
      passwords,
    });

    assert.equal(result.detectedTypes.stripe_key, 'stripe-live-key');
    assert.equal(matchesShape(result.decoy.stripe_key!, 'stripe-live-key'), true);
    assert.ok(result.decoy.stripe_key!.length <= 'sk_live_abcdefghijklmnopqrstuvwxyz123456'.length);
  });

  it('generates BIP-39 decoys with matching word count', async () => {
    const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    const result = await encryptRecord({
      real: { seed: phrase },
      passwords,
    });

    assert.equal(result.detectedTypes.seed, 'bip39-phrase');
    assert.equal(result.decoy.seed!.trim().split(/\s+/).length, 12);
  });

  it('falls back to a generic decoy (does NOT throw) when no typed decoy fits the budget', async () => {
    // A 1-char value explicitly typed as stripe-live-key cannot fit any valid
    // stripe-shaped decoy. The old behaviour threw an uncaught error; the fix
    // gracefully falls back to a generic decoy of the same length so a single
    // short field can't crash the whole encryptRecord call.
    const result = await encryptRecord({
      real: { tiny: 'x' },
      explicitTypes: { tiny: 'stripe-live-key' },
      passwords,
    });
    // Decoy must fit the byte budget; real + decoy paths both round-trip.
    assert.ok(result.decoy.tiny!.length <= 'x'.length);
    assert.deepEqual(await decryptRecord(result.ciphertext, result.realCtrl, passwords), { tiny: 'x' });
    assert.deepEqual(
      await decryptRecord(result.ciphertext, result.decoyCtrl, passwords),
      { tiny: result.decoy.tiny! },
    );
  });

  it('does not crash encryptRecord on a short checksummed value (postgres-uri)', async () => {
    // Regression for P1-1: `postgres://localhost` is a valid short DB URI that
    // classifies as a checksummed/structured type too short to fit a typed decoy.
    const result = await encryptRecord({
      real: { db: 'postgres://localhost' },
      passwords,
    });
    assert.ok(result.decoy.db!.length <= 'postgres://localhost'.length);
    assert.deepEqual(await decryptRecord(result.ciphertext, result.realCtrl, passwords), {
      db: 'postgres://localhost',
    });
  });

  it('preserves shape contracts for representative local generators', () => {
    const samples = [
      ['sk_live_abcdefghijklmnopqrstuvwxyz123456', 'stripe-live-key'],
      ['ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ', 'github-pat-classic'],
      ['AKIAABCDEFGHIJKLMNOP', 'aws-access-key'],
      ['+447700900123', 'phone-e164'],
      ['AB123456C', 'uk-ni-number'],
    ] as const;

    for (const [value, type] of samples) {
      const decoy = generateLocalDecoy(value, type);
      assert.equal(matchesShape(decoy, type), true, `${type} shape`);
      assert.ok(decoy.length <= value.length, `${type} length`);
    }
  });

  it('frame magic, field count, and length prefixes round-trip varied fields', async () => {
    const record = { a: 'x', medium: 'hello world', long: 'z'.repeat(128) };
    const frame = encodeRecordFrame(record);
    assert.equal(Buffer.from(frame.slice(0, 4)).toString('utf8'), 'DRC1');
    assert.equal(new DataView(frame.buffer, frame.byteOffset, frame.byteLength).getUint32(4, true), 3);

    const result = await encryptRecord({ real: record, passwords });
    assert.deepEqual(await decryptRecord(result.ciphertext, result.realCtrl, passwords), record);
  });

  // P2-3 regression: a pathologically large field must be rejected by the frame
  // size cap rather than driving an unbounded allocation.
  it('rejects a record frame larger than the 16 MiB cap', () => {
    const huge = { blob: 'a'.repeat(17 * 1024 * 1024) };
    assert.throws(() => encodeRecordFrame(huge), /exceeds maximum size/);
  });
});
