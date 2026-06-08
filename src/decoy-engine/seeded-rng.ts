/**
 * deny-sh - Seeded deterministic RNG for Honey Mode
 *
 * Honey Mode requires that a *wrong* password decrypt to a stable, plausible,
 * type-correct fake (a "honey" value) instead of random nonsense. "Stable"
 * is the critical word: the SAME wrong password must always produce the SAME
 * fake. A fake that changes between retries is an instant honeypot tell.
 *
 * This module provides a deterministic CSPRNG-style byte source that the decoy
 * generators can draw from instead of node:crypto randomBytes. It is a simple
 * counter-mode hash DRBG:
 *
 *     block_i = SHA-256( seed || be32(i) )      for i = 0, 1, 2, ...
 *     keystream = block_0 || block_1 || ...
 *
 * Properties that matter:
 *   - Deterministic: same seed => same byte stream, on every platform and in
 *     every SDK (TS / Rust / Python / Go) as long as they implement this exact
 *     construction. SHA-256 + big-endian counter is the cross-language contract.
 *   - Forward-only: blocks are consumed in order; the generator never seeks back.
 *   - Seed hygiene: the seed is derived OUTSIDE this module (see core.ts honey
 *     path) from the wrong-password decrypt bytes + public salt + a type tag.
 *     It MUST NOT contain any real-plaintext or real-control-data bytes. This
 *     module makes no assumptions about seed contents beyond "opaque bytes".
 *
 * SECURITY NOTE: this is NOT a general-purpose CSPRNG for key material. It is a
 * deterministic expansion function whose only job is to drive shape generation
 * for honey decoys reproducibly. Real cryptographic randomness (salts, IVs,
 * curated-decoy material) continues to come from node:crypto randomBytes.
 */

import { createHash } from 'node:crypto';

/**
 * A byte source: hand it a count, get that many bytes. The curated-decoy flow
 * uses a randomBytes-backed source; the honey flow uses SeededByteSource.
 */
export interface ByteSource {
  /** Return exactly `n` bytes. */
  bytes(n: number): Uint8Array;
}

/**
 * Deterministic byte source seeded from arbitrary opaque bytes.
 *
 * Construction (cross-SDK contract — do not change without bumping a version):
 *   block_i = SHA-256( seed || be32(i) ),  bytes consumed left-to-right.
 */
export class SeededByteSource implements ByteSource {
  private readonly seed: Uint8Array;
  private counter = 0;
  private buffer: Uint8Array = new Uint8Array(0);
  private bufPos = 0;

  constructor(seed: Uint8Array) {
    // Copy defensively so external mutation can't change the stream mid-draw.
    this.seed = Uint8Array.from(seed);
  }

  private refill(): void {
    const ctr = new Uint8Array(4);
    // big-endian counter — the cross-language contract
    ctr[0] = (this.counter >>> 24) & 0xff;
    ctr[1] = (this.counter >>> 16) & 0xff;
    ctr[2] = (this.counter >>> 8) & 0xff;
    ctr[3] = this.counter & 0xff;
    const h = createHash('sha256');
    h.update(this.seed);
    h.update(ctr);
    this.buffer = new Uint8Array(h.digest());
    this.bufPos = 0;
    this.counter = (this.counter + 1) >>> 0;
  }

  bytes(n: number): Uint8Array {
    if (n <= 0) return new Uint8Array(0);
    const out = new Uint8Array(n);
    let written = 0;
    while (written < n) {
      if (this.bufPos >= this.buffer.length) this.refill();
      const take = Math.min(n - written, this.buffer.length - this.bufPos);
      out.set(this.buffer.subarray(this.bufPos, this.bufPos + take), written);
      this.bufPos += take;
      written += take;
    }
    return out;
  }
}

/** randomBytes-backed source for the existing (non-honey) curated-decoy flow. */
export class RandomByteSource implements ByteSource {
  // Lazy import keeps this file usable in environments that polyfill crypto.
  bytes(n: number): Uint8Array {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { randomBytes } = require('node:crypto') as typeof import('node:crypto');
    return new Uint8Array(randomBytes(n));
  }
}

/**
 * Uniform integer in [0, max) drawn from a ByteSource via rejection sampling.
 *
 * This MUST match the legacy randInt() rejection rule exactly (4-byte LE read,
 * reject above the largest multiple of `max`) so that, for any given byte
 * stream, seeded and legacy paths agree. Cross-SDK ports must replicate this.
 */
export function sourcedInt(src: ByteSource, max: number): number {
  if (max <= 0) return 0;
  const limit = Math.floor(0x100000000 / max) * max;
  // Pull 4 bytes at a time, LE, until within limit.
  // Bounded loop guard: rejection probability < 0.5 per draw, so 128 draws is
  // astronomically safe; throwing past that flags a broken source rather than
  // hanging forever.
  for (let attempt = 0; attempt < 128; attempt++) {
    const b = src.bytes(4);
    const v = (b[0]! | (b[1]! << 8) | (b[2]! << 16) | (b[3]! << 24)) >>> 0;
    if (v < limit) return v % max;
  }
  throw new Error('sourcedInt: rejection sampling exceeded bound (broken byte source?)');
}

/**
 * Derive a honey seed from the decrypt bytes + public salt + a type tag.
 *
 * seed = SHA-256( "deny-sh/honey/v1" || 0x00 || decryptBytes || 0x00 || salt || 0x00 || typeTag )
 *
 * The domain-separation prefix + 0x00 separators prevent any cross-context
 * collision. decryptBytes is the AES-CTR output XOR controlData for the WRONG
 * password (i.e. the would-be nonsense payload). It deterministically depends
 * on the wrong password + ciphertext + salt, and is independent of the real
 * plaintext, so the same wrong password always lands the same honey value while
 * leaking nothing about the real secret.
 *
 * Cross-SDK contract: this exact byte layout must be replicated in every port.
 */
const HONEY_DOMAIN = 'deny-sh/honey/v1';

export function deriveHoneySeed(
  decryptBytes: Uint8Array,
  salt: Uint8Array,
  typeTag: string
): Uint8Array {
  const h = createHash('sha256');
  h.update(HONEY_DOMAIN, 'utf8');
  h.update(new Uint8Array([0x00]));
  h.update(decryptBytes);
  h.update(new Uint8Array([0x00]));
  h.update(salt);
  h.update(new Uint8Array([0x00]));
  h.update(typeTag, 'utf8');
  return new Uint8Array(h.digest());
}
