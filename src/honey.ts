/**
 * deny-sh - Honey Mode (Phase 1b: decrypt-path integration)
 *
 * Honey Mode turns the "wrong password returns nonsense" branch into "wrong
 * password returns a deterministic, plausible, type-correct fake" — but ONLY
 * for structured secret types our generators can fully back, and ONLY when the
 * caller opts in per record. See vault honey-mode-per-type-plan.md.
 *
 * Integration approach: APPROACH A ("honey is the only fallback"), confirmed by
 * Alex 2026-05-31. The record stores no per-slot authenticator. On decrypt we
 * compute the recovered inner payload (core.decryptToPayload) and inspect its
 * 4-byte length prefix:
 *
 *   - band-consistent well-formed frame  -> a real or decoy slot the user set
 *     up; return that plaintext (unchanged from classic behaviour).
 *   - NOT band-consistent (the random-prefix "wall" a wrong key produces) AND
 *     honeyMode on -> derive a deterministic typed fake from the wrong-password
 *     decrypt bytes and return THAT instead of the nonsense.
 *
 * Deniability properties preserved:
 *   - No stored slot list, no MAC tags, nothing extra on the wire => no
 *     distinguisher for how many real/decoy doors exist (the reason we rejected
 *     Approach B).
 *   - The honey fake is emitted on the SAME code path and has the SAME output
 *     shape (a typed string) as a legit decrypt => no format/length tell.
 *   - The seed for the fake comes ONLY from {wrong-password decrypt bytes,
 *     public salt, type tag} (deriveHoneySeed) => the fake is stable per wrong
 *     password (no honeypot "answer changes on retry" tell) and leaks nothing
 *     about the real secret.
 *
 * Scope: honey is refused for unstructured types (generic / freeform-secret).
 * Those stay on the classic real+decoy+noise model.
 *
 * Cross-SDK note: this TS path is the reference. The Rust/Python/Go ports must
 * replicate deriveHoneySeed layout + SeededByteSource DRBG + sourcedInt
 * rejection + each generator's draw order byte-for-byte, or honey output
 * diverges across languages. That spec work is Phase 2 (ARCHITECTURE.md first).
 */

import {
  encrypt,
  decryptToPayload,
  generateControlData,
  bucketedPayloadLength,
} from './core.js';
import type { DecoyType } from './decoy-engine/types.js';
import { isHoneyEligible, generateHoneyDecoy, defaultLengthForType } from './record-decoy-generators.js';

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const LENGTH_PREFIX = 4;

/** Parameters for a honey-enabled single-secret encrypt. */
export interface EncryptHoneyParams {
  /** The real secret value (a single structured token, e.g. a Stripe key). */
  secret: string;
  /** Dual passwords for the deniability layer. */
  passwords: { p1: string; p2: string };
  /**
   * Declared structured type of the secret. MUST be honey-eligible
   * (isHoneyEligible). Wrong passwords on the resulting record will decrypt to
   * a fresh, type-correct fake of THIS type.
   */
  honeyType: DecoyType;
}

export interface EncryptHoneyResult {
  /** Combined ciphertext (bucketed for length privacy). */
  ciphertext: Uint8Array;
  /** Control file that decrypts (with the real passwords) to the real secret. */
  realCtrl: Uint8Array;
  /** The bucket band the payload was padded to (stored in record metadata). */
  band: number;
  /** Echoes the honey type so callers can persist it in record metadata. */
  honeyType: DecoyType;
}

/*
 * SECURITY BOUNDARY — Honey Mode metadata leak (review P2 #2, documented as
 * intentional). decryptHoney requires two pieces of metadata that callers MUST
 * persist alongside the ciphertext: `band` and `honeyType`. These are NOT inside
 * the encrypted envelope, and that is structural, not an oversight:
 *
 *   - `band` selects the decrypt-side band-consistency window
 *     (isWellFormedFrame). It is the input that DECIDES real-vs-honey; it cannot
 *     live inside the thing it gates without a chicken-and-egg dependency.
 *   - `honeyType` selects which deterministic generator produces the wrong-
 *     password fake. The decrypt path needs it BEFORE it has any plaintext.
 *
 * Consequence an attacker who seizes the stored record learns: (a) the record is
 * honey-protected, and (b) the broad class of secret it holds (e.g.
 * "stripe-live-key"), and (c) its coarse length band. They do NOT learn the
 * real value, the real length (length privacy holds), or whether any given
 * decrypt attempt hit the real slot vs a honey fake (uniform output shape +
 * timing). Honey Mode is opt-in and aimed at the agents/infra tier where the
 * record schema is already known to the operator; the type/band disclosure is an
 * accepted trade for a deterministic, cross-SDK, no-stored-authenticator design.
 *
 * If a future deployment needs to hide (a)/(b)/(c), the mitigation is to wrap the
 * whole honey record (ciphertext + band + honeyType) in an OUTER classic
 * deny.sh envelope, so the honey metadata only appears after a successful outer
 * decrypt. That is a packaging choice for the caller, not a change to this
 * primitive.
 */

/** Ergonomic options bag for the public honey encrypt wrapper. */
export interface EncryptWithHoneyOptions {
  /** Explicit opt-in. Honey Mode is never inferred or defaulted. */
  honeyMode: true;
  /** Structured secret type to synthesise on wrong-password decrypt. */
  honeyType: DecoyType;
  /** Dual passwords for the deniability layer. */
  passwords: { p1: string; p2: string };
}

/** Ergonomic options bag for the public honey decrypt wrapper. */
export interface DecryptWithHoneyOptions {
  /** Control file to try against the ciphertext. */
  controlData: Uint8Array;
  /** Dual passwords being tried. */
  passwords: { p1: string; p2: string };
  /** Structured secret type persisted with the record metadata. */
  honeyType: DecoyType;
  /** Bucket band persisted with the record metadata. */
  band: number;
}

/**
 * Outcome of a honey-aware decrypt (PUBLIC).
 *
 * P2 (gpt55 audit 2026-06-07): this deliberately exposes ONLY `value`. The
 * branch taken ('real' vs 'honey') is a perfect real-vs-honey oracle and MUST
 * NOT be surfaced to SDK consumers — a caller who logs or returns the struct
 * would hand an attacker exactly the distinguisher honey mode exists to deny.
 * The branch is available only via the internal `*WithBranch` functions used
 * by tests/telemetry (not re-exported from the package index).
 */
export interface DecryptHoneyResult {
  /** The recovered value: real secret, or a deterministic typed honey fake. */
  value: string;
}

/**
 * Internal-only decrypt outcome carrying the branch telemetry. NOT exported
 * from the package index; for tests and internal telemetry only.
 */
export interface DecryptHoneyInternalResult {
  value: string;
  /**
   * Branch taken. `'real'` = a band-consistent well-formed frame was recovered
   * (real or decoy slot). `'honey'` = the wall branch fired and a typed fake was
   * synthesised. The two branches are designed to be externally
   * indistinguishable; never surface this past the SDK boundary.
   */
  branch: 'real' | 'honey';
}

/**
 * Encrypt a single structured secret with Honey Mode enabled.
 *
 * The record is always bucketed (padToBucket) so its ciphertext byte-count
 * reveals only a coarse band, and so the decrypt-side band-consistency check has
 * a known band to test against.
 *
 * Throws if `honeyType` is not honey-eligible.
 */
export async function encryptHoney(params: EncryptHoneyParams): Promise<EncryptHoneyResult> {
  const { secret, passwords, honeyType } = params;
  if (!isHoneyEligible(honeyType)) {
    throw new Error(
      `Honey Mode is not supported for unstructured type "${honeyType}". ` +
        `Use classic encrypt() for generic / freeform secrets.`
    );
  }

  const plaintext = textEncoder.encode(secret);
  // Inner payload length = 4-byte prefix + secret; band is the smallest bucket
  // that fits it. Control data must cover the padded payload.
  const band = bucketedPayloadLength(plaintext.length + 4);
  const controlData = generateControlData(band);

  const result = await encrypt(plaintext, {
    password1: passwords.p1,
    password2: passwords.p2,
    controlData,
    padToBucket: true,
  });

  return {
    ciphertext: result.ciphertext,
    realCtrl: controlData,
    band,
    honeyType,
  };
}

/**
 * Ergonomic Honey Mode encrypt wrapper for SDK callers.
 *
 * Mirrors the public mental model:
 * `encryptWithHoney(secret, { honeyMode: true, honeyType, passwords })`.
 *
 * This is intentionally thin and delegates to `encryptHoney`; crypto stays in
 * the existing primitive.
 */
export async function encryptWithHoney(
  secret: string,
  options: EncryptWithHoneyOptions
): Promise<EncryptHoneyResult> {
  if (options.honeyMode !== true) {
    throw new Error('Honey Mode requires honeyMode: true.');
  }
  return encryptHoney({
    secret,
    passwords: options.passwords,
    honeyType: options.honeyType,
  });
}

/**
 * Decrypt a Honey-Mode record.
 *
 * @param ciphertext  The honey ciphertext.
 * @param controlData The control file to try (real, a decoy, or an attacker's
 *                    wrong guess derived from a wrong password).
 * @param passwords   The dual passwords being tried.
 * @param honeyType   The declared structured type (from record metadata).
 * @param band        The bucket band (from record metadata) for the
 *                    band-consistency check.
 *
 * Returns the real secret when a band-consistent frame is recovered, otherwise a
 * deterministic typed honey fake. Same output shape on both branches.
 */
export async function decryptHoneyWithBranch(
  ciphertext: Uint8Array,
  controlData: Uint8Array,
  passwords: { p1: string; p2: string },
  honeyType: DecoyType,
  band: number
): Promise<DecryptHoneyInternalResult> {
  // Eligibility is enforced authoritatively at SETUP (encryptHoney / encryptWithHoney
  // and the server's parseHoneyMeta), so a genuine honey record's type is always
  // eligible by construction. This decrypt-surface guard is therefore purely
  // defensive (caller passing a hand-built ineligible type). Per review P2 #3 it
  // must NOT throw a honey-capability-distinguishing error at the
  // (potentially attacker-facing) decrypt boundary: it fails with the same
  // opaque message any malformed/wrong-credential decode uses, so the decrypt
  // surface has one uniform failure mode regardless of type eligibility.
  if (!isHoneyEligible(honeyType)) {
    throw new Error('decrypt failed or malformed input');
  }

  const { payload, salt, wellFormed, plaintext } = await decryptToPayload(
    ciphertext,
    {
      password1: passwords.p1,
      password2: passwords.p2,
      controlData,
    },
    band
  );

  // Always do both branch workloads before selecting output. This keeps the
  // real/decoy-slot path and wrong-password honey path timing shape aligned
  // without changing the generator's seed material or draw order.
  const defaultLengthHint = defaultLengthForType(honeyType);
  const realLengthHint = bucketedPayloadLength(defaultLengthHint + LENGTH_PREFIX) === payload.length
    ? defaultLengthHint
    : Math.max(0, payload.length - LENGTH_PREFIX);
  const fake = generateHoneyDecoy({
    type: honeyType,
    decryptBytes: payload,
    salt,
    realLengthHint,
  });
  const decoded = textDecoder.decode(plaintext);
  return wellFormed
    ? { value: decoded, branch: 'real' }
    : { value: fake, branch: 'honey' };
}

/**
 * Decrypt a Honey-Mode record (PUBLIC). Returns only the recovered value; the
 * real-vs-honey branch is intentionally NOT exposed (see DecryptHoneyResult).
 * Use `decryptHoneyWithBranch` internally if the branch is needed for tests.
 */
export async function decryptHoney(
  ciphertext: Uint8Array,
  controlData: Uint8Array,
  passwords: { p1: string; p2: string },
  honeyType: DecoyType,
  band: number
): Promise<DecryptHoneyResult> {
  const { value } = await decryptHoneyWithBranch(
    ciphertext,
    controlData,
    passwords,
    honeyType,
    band
  );
  return { value };
}

/**
 * Internal ergonomic Honey Mode decrypt wrapper that retains branch telemetry.
 * NOT re-exported from the package index. For tests/internal telemetry only.
 */
export async function decryptWithHoneyWithBranch(
  ciphertext: Uint8Array,
  options: DecryptWithHoneyOptions
): Promise<DecryptHoneyInternalResult> {
  return decryptHoneyWithBranch(
    ciphertext,
    options.controlData,
    options.passwords,
    options.honeyType,
    options.band
  );
}

/**
 * Ergonomic Honey Mode decrypt wrapper for SDK callers (PUBLIC). Returns only
 * the recovered value; the branch is intentionally stripped.
 */
export async function decryptWithHoney(
  ciphertext: Uint8Array,
  options: DecryptWithHoneyOptions
): Promise<DecryptHoneyResult> {
  const { value } = await decryptWithHoneyWithBranch(ciphertext, options);
  return { value };
}
