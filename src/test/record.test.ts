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

  it('fails closed when no typed decoy fits the budget', async () => {
    // A 1-char value explicitly typed as stripe-live-key cannot fit any valid
    // stripe-shaped decoy. Do not silently downgrade to a generic printable
    // value, because that makes the typed field fail its own classifier.
    await assert.rejects(
      () => encryptRecord({
        real: { tiny: 'x' },
        explicitTypes: { tiny: 'stripe-live-key' },
        passwords,
      }),
      /could not generate valid stripe-live-key decoy/,
    );
  });

  it('fails closed on a short typed URI when no valid typed decoy fits', async () => {
    await assert.rejects(
      () => encryptRecord({
        real: { db: 'postgres://localhost' },
        passwords,
      }),
      /could not generate valid postgres-uri decoy/,
    );
  });

  it('normalizes public record decrypt decode failures', async () => {
    const result = await encryptRecord({
      real: { name: 'Alex', note: 'secret' },
      passwords,
    });

    const wrongKey = await decryptRecord(result.ciphertext, result.realCtrl, { p1: 'wrong', p2: 'wrong' })
      .then(() => null, (err: Error) => err);
    const truncated = await decryptRecord(result.ciphertext.slice(0, 60), result.realCtrl, passwords)
      .then(() => null, (err: Error) => err);

    assert.equal(wrongKey?.message, 'record decrypt failed');
    assert.equal(truncated?.message, 'record decrypt failed');
    assert.equal(wrongKey?.constructor, truncated?.constructor);
  });

  it('generates GCP service account decoys with independent identifiers', () => {
    const real = JSON.stringify({
      type: 'service_account',
      project_id: 'real-project-123',
      private_key_id: '0'.repeat(40),
      private_key: '-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n',
      client_email: 'prod-admin@real-project-123.iam.gserviceaccount.com',
      client_id: '123456789012345678901',
      auth_uri: 'https://accounts.google.com/o/oauth2/auth',
      token_uri: 'https://oauth2.googleapis.com/token',
      auth_provider_x509_cert_url: 'https://www.googleapis.com/oauth2/v1/certs',
      client_x509_cert_url: 'https://www.googleapis.com/robot/v1/metadata/x509/prod-admin%40real-project-123.iam.gserviceaccount.com',
      universe_domain: 'googleapis.com',
    }, null, 2);
    const decoy = JSON.parse(generateLocalDecoy(real, 'gcp-service-account-key'));
    assert.notEqual(decoy.project_id, 'real-project-123');
    assert.notEqual(String(decoy.client_email).split('@')[0], 'prod-admin');
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
