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

  it('rejects generated decoys that cannot fit the real frame budget', async () => {
    await assert.rejects(
      () =>
        encryptRecord({
          real: { tiny: 'x' },
          explicitTypes: { tiny: 'stripe-live-key' },
          passwords,
        }),
      /exceeds real value length|could not generate decoy/
    );
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
});
