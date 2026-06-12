/**
 * deny-sh - Core encryption engine
 *
 * Algorithm:
 *
 * ENCRYPT:
 *   1. Derive AES-256 key from password1 + password2 via Argon2id
 *   2. Prepend 4-byte plaintext length to plaintext (inside encrypted zone)
 *   3. XOR (length + plaintext) with control data
 *   4. AES-256-CTR encrypt the result
 *   5. Prepend: salt (32 bytes) + IV (16 bytes) as unencrypted header
 *
 * DECRYPT:
 *   1. Extract salt + IV from header
 *   2. Re-derive AES-256 key from passwords + salt
 *   3. AES-256-CTR decrypt payload
 *   4. XOR with control data
 *   5. Read 4-byte length prefix, trim plaintext to that length
 *
 * DENIABLE DECRYPTION:
 *   Given ciphertext + passwords + desired fake plaintext:
 *   1. AES decrypt to get intermediate (= length+plaintext XOR controlData)
 *   2. Construct fake payload = 4-byte-length(fake) + fake plaintext + random padding
 *   3. New control data = intermediate XOR fake payload
 *   4. Now decrypting with new control file produces the fake plaintext
 *
 * LENGTH PRIVACY:
 *   The 4-byte length prefix lives INSIDE the encrypted+XOR zone, so the *decrypt
 *   output* never reveals the real length: a 2-byte decoy and a 64-byte real
 *   message can share one ciphertext, and which one you get is chosen entirely by
 *   the control file. However, the *ciphertext byte-count itself* is fixed at
 *   encrypt time. Without padding it equals real.length + 4, so an adversary who
 *   only ever sees the ciphertext can read the real plaintext length off the wire.
 *
 *   To close that channel, pass `padToBucket: true` (or a fixed `bucketSize`).
 *   The inner payload is then padded with random bytes up to a coarse size band
 *   (see BUCKET_BANDS) before encryption, so the ciphertext size reveals only
 *   which band the message falls into, not its exact length. The padding sits
 *   after the real plaintext inside the XOR zone and is transparent to decrypt
 *   (decrypt trims to the length prefix), so it is lossless. Bucketing is OPT-IN
 *   to preserve exact byte-for-byte wire compatibility with the rust/python/go
 *   ports by default; the CLI surfaces (protect wizard, record helper) opt in.
 */

import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'node:crypto';
import { argon2id } from 'hash-wasm';

// --- Types ---

export interface EncryptionParams {
  /** First password/passphrase */
  password1: string;
  /** Second password/passphrase */
  password2: string;
  /** Control file data - must be >= plaintext length + 4 bytes */
  controlData: Uint8Array;
  /**
   * Length privacy. When true, the inner payload is padded with random bytes up
   * to the next size band in BUCKET_BANDS before encryption, so the resulting
   * ciphertext size reveals only a coarse band rather than the exact plaintext
   * length. Lossless (decrypt trims to the length prefix). Opt-in: defaults to
   * false so wire output stays byte-identical to the non-padded ports.
   *
   * Note: controlData must be at least as long as the padded payload when this
   * is set. The CLI helpers size their control data accordingly.
   */
  padToBucket?: boolean;
  /**
   * Explicit target payload length (length-prefix + plaintext + padding) in
   * bytes. Overrides padToBucket band selection. Must be >= plaintext.length + 4.
   * Use when a caller wants every artefact of a given class to be exactly one
   * fixed size regardless of content.
   */
  bucketSize?: number;
}

export interface EncryptResult {
  /** Encrypted data (salt + iv + ciphertext) */
  ciphertext: Uint8Array;
  /** Salt used for key derivation (also embedded in ciphertext header) */
  salt: Uint8Array;
  /** Number of control bytes consumed by this ciphertext payload. */
  controlBytes: number;
}

export interface DecryptResult {
  /** Decrypted plaintext */
  plaintext: Uint8Array;
}

export interface DeniableControlResult {
  /** New control data that makes ciphertext decrypt to desiredPlaintext */
  controlData: Uint8Array;
}

export interface EncryptTextOptions {
  /**
   * Compatibility escape hatch. When true, text mode uses the raw low-level
   * wire shape (plaintext + 4 bytes) instead of length bucketing.
   */
  unsafeUnpadded?: boolean;
}

// --- Constants ---

const SALT_LENGTH = 32;
const IV_LENGTH = 16;
const KEY_LENGTH = 32; // AES-256
const ALGORITHM = 'aes-256-ctr';
const ARGON2_T_COST = 3;
const ARGON2_M_COST = 65536; // KiB (64 MiB)
const ARGON2_P = 1;
const LENGTH_PREFIX = 4; // 4-byte length prefix inside encrypted zone
const HEADER_LENGTH = SALT_LENGTH + IV_LENGTH; // 48 bytes (unencrypted header)

/**
 * Public, length-free error message for any malformed-artifact / wrong-credential
 * decode failure on the decrypt surface (review P2 #1). Distinct error strings
 * that embed exact byte lengths let an attacker who can observe errors/logs tell
 * a malformed artifact apart from a wrong credential (a parsing oracle). The
 * public surface returns this single opaque message; precise lengths are
 * available only when DENY_DEBUG_ERRORS is set (operator-side debugging), never
 * by default.
 */
const MALFORMED_INPUT_MESSAGE = 'decrypt failed or malformed input';

function malformedInputError(detail: string): Error {
  // eslint-disable-next-line n/no-process-env
  if (typeof process !== 'undefined' && process.env && process.env['DENY_DEBUG_ERRORS']) {
    return new Error(`${MALFORMED_INPUT_MESSAGE} (${detail})`);
  }
  return new Error(MALFORMED_INPUT_MESSAGE);
}

/**
 * Coarse size bands for length bucketing (inner-payload byte counts, i.e.
 * including the 4-byte length prefix). A payload is padded up to the smallest
 * band that fits it. Bands grow geometrically so the relative length leak is
 * bounded (a message in the 257..1024 band could be anywhere in a 4x range),
 * while keeping ciphertext bloat modest for the common small-secret case
 * (seed phrases, API keys, card numbers all land in <=256). Payloads larger
 * than the top band are rounded up to the next 16 KiB multiple.
 */
const BUCKET_BANDS = [64, 256, 1024, 4096, 16384] as const;
const BUCKET_STEP_ABOVE_TOP = 16384;
// Hard ceiling for an explicit bucketSize. Prevents a fat-fingered or hostile
// caller-supplied value (e.g. 2**32) from triggering a multi-GB randomBytes()
// allocation that crashes the process. 64 MiB is orders of magnitude above any
// legitimate single-secret payload.
const MAX_BUCKET_SIZE = 64 * 1024 * 1024;

/**
 * Return the bucketed payload length for a raw inner-payload length.
 * Exported for tests + the CLI helpers that must size control data to match.
 */
export function bucketedPayloadLength(rawPayloadLength: number): number {
  for (const band of BUCKET_BANDS) {
    if (rawPayloadLength <= band) return band;
  }
  return Math.ceil(rawPayloadLength / BUCKET_STEP_ABOVE_TOP) * BUCKET_STEP_ABOVE_TOP;
}

// --- Key Derivation ---

/**
 * Derive AES-256 key from two passwords using Argon2id.
 * Combines both passwords via SHA-256 hashing to avoid length ambiguities.
 */
export async function deriveKey(password1: string, password2: string, salt: Uint8Array): Promise<Uint8Array> {
  const pw1Hash = createHash('sha256').update(password1, 'utf8').digest();
  const pw2Hash = createHash('sha256').update(password2, 'utf8').digest();
  const combined = Buffer.concat([pw1Hash, pw2Hash]);

  const key = await argon2id({
    password: combined,
    salt,
    parallelism: ARGON2_P,
    iterations: ARGON2_T_COST,
    memorySize: ARGON2_M_COST,
    hashLength: KEY_LENGTH,
    outputType: 'binary',
  });

  return key;
}

// --- Control File Operations ---

/**
 * Generate cryptographically secure random control data.
 */
export function generateControlData(length: number): Uint8Array {
  return new Uint8Array(randomBytes(length));
}

/**
 * XOR two byte arrays. Returns a new array.
 */
function xorBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
  const len = Math.min(a.length, b.length);
  const result = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    result[i] = a[i]! ^ b[i]!;
  }
  return result;
}

/**
 * Build the inner payload: 4-byte LE length + plaintext data
 */
function buildPayload(data: Uint8Array): Uint8Array {
  const payload = new Uint8Array(LENGTH_PREFIX + data.length);
  new DataView(payload.buffer).setUint32(0, data.length, true);
  payload.set(data, LENGTH_PREFIX);
  return payload;
}

/**
 * Extract plaintext from inner payload (4-byte LE length + data).
 *
 * WARNING: Because this encryption scheme is intentionally unauthenticated
 * (to enable deniability), there is no reliable way to detect a wrong password
 * or control file. If the decoded length prefix exceeds available data, this
 * returns the raw payload bytes (garbage) rather than throwing. Callers MUST
 * handle the possibility of garbage output gracefully.
 */
function extractPayload(payload: Uint8Array): Uint8Array {
  if (payload.length < LENGTH_PREFIX) {
    throw new Error('Payload too short');
  }
  const length = new DataView(payload.buffer, payload.byteOffset, LENGTH_PREFIX).getUint32(0, true);
  if (length > payload.length - LENGTH_PREFIX) {
    // Length exceeds available data - likely wrong password or control file
    return payload.slice(LENGTH_PREFIX);
  }
  return payload.slice(LENGTH_PREFIX, LENGTH_PREFIX + length);
}

// --- Core Encryption ---

/**
 * Encrypt plaintext using dual passwords and a control file.
 */
export async function encrypt(plaintext: Uint8Array, params: EncryptionParams): Promise<EncryptResult> {
  const { password1, password2, controlData } = params;

  // Build inner payload with length prefix
  const rawPayload = buildPayload(plaintext);

  // Length privacy (opt-in): pad the inner payload up to a coarse size band (or
  // an explicit bucketSize) with random bytes so the ciphertext byte-count only
  // reveals which band the message falls in, not its exact length. The padding
  // sits after the real plaintext inside the XOR+encrypt zone and is trimmed on
  // decrypt via the length prefix, so it is lossless.
  let payload = rawPayload;
  if (params.bucketSize !== undefined || params.padToBucket) {
    const target = params.bucketSize !== undefined
      ? params.bucketSize
      : bucketedPayloadLength(rawPayload.length);
    if (!Number.isSafeInteger(target) || target < 0) {
      throw new Error(
        `bucketSize must be a non-negative safe integer, got ${target}`
      );
    }
    if (target < rawPayload.length) {
      throw new Error(
        `bucketSize (${target} bytes) must be >= plaintext + 4 bytes (${rawPayload.length} bytes)`
      );
    }
    // Upper bound: refuse absurd bucket sizes that would make randomBytes()
    // attempt a multi-GB allocation and crash the process with a native
    // RangeError. 64 MiB is far above any legitimate single-secret payload.
    if (target > MAX_BUCKET_SIZE) {
      throw new Error(
        `bucketSize (${target} bytes) exceeds maximum allowed (${MAX_BUCKET_SIZE} bytes)`
      );
    }
    if (target > rawPayload.length) {
      const padded = new Uint8Array(target);
      padded.set(rawPayload, 0);
      padded.set(new Uint8Array(randomBytes(target - rawPayload.length)), rawPayload.length);
      payload = padded;
    }
  }

  if (controlData.length < payload.length) {
    throw new Error(
      `Control data (${controlData.length} bytes) must be >= padded payload (${payload.length} bytes)`
    );
  }

  // Generate random salt and IV
  const salt = new Uint8Array(randomBytes(SALT_LENGTH));
  const iv = new Uint8Array(randomBytes(IV_LENGTH));

  // Derive key
  const key = await deriveKey(password1, password2, salt);

  // XOR payload with control data (the deniability layer)
  const controlSlice = controlData.slice(0, payload.length);
  const xored = xorBytes(payload, controlSlice);

  // AES-256-CTR encrypt
  const cipher = createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(xored), cipher.final()]);

  // Pack: salt || iv || encrypted(length + plaintext XOR controlData)
  const result = new Uint8Array(HEADER_LENGTH + encrypted.length);
  result.set(salt, 0);
  result.set(iv, SALT_LENGTH);
  result.set(new Uint8Array(encrypted), HEADER_LENGTH);

  return { ciphertext: result, salt, controlBytes: payload.length };
}

/**
 * Decrypt ciphertext using dual passwords and the original control file.
 */
export function decrypt(
  ciphertext: Uint8Array,
  params: EncryptionParams
): Promise<DecryptResult> {
  return decryptAsync(ciphertext, params);
}

async function decryptAsync(
  ciphertext: Uint8Array,
  params: EncryptionParams
): Promise<DecryptResult> {
  const { password1, password2, controlData } = params;

  if (ciphertext.length < HEADER_LENGTH) {
    throw malformedInputError(`ciphertext ${ciphertext.length} < header ${HEADER_LENGTH}`);
  }

  // Extract header
  const salt = ciphertext.slice(0, SALT_LENGTH);
  const iv = ciphertext.slice(SALT_LENGTH, HEADER_LENGTH);
  const encryptedData = ciphertext.slice(HEADER_LENGTH);

  // Derive key
  const key = await deriveKey(password1, password2, salt);

  // AES-256-CTR decrypt
  const decipher = createDecipheriv(ALGORITHM, key, iv);
  const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);

  // XOR with control data to recover payload. The control file MUST be at least
  // as long as the ciphertext payload; a short control file would silently XOR
  // only a prefix and return garbage with no error. Fail loudly instead. Public
  // message is length-free (review P2 #1); exact lengths gated behind
  // DENY_DEBUG_ERRORS so error text is not a parsing oracle.
  if (controlData.length < decrypted.length) {
    throw malformedInputError(
      `control ${controlData.length} < payload ${decrypted.length}`
    );
  }
  const controlSlice = controlData.slice(0, decrypted.length);
  const payload = xorBytes(new Uint8Array(decrypted), controlSlice);

  // Extract plaintext from payload (reads length prefix, trims)
  const plaintext = extractPayload(payload);

  return { plaintext };
}

/**
 * Honey Mode hook (Phase 1b).
 *
 * Runs the decrypt pipeline up to (but not through) extractPayload and returns
 * BOTH the recovered inner payload AND a verdict on whether its 4-byte length
 * prefix decodes to a well-formed frame. This is the exact branch point Honey
 * Mode needs: a real/decoy slot yields a well-formed frame (return the
 * plaintext); a genuinely-wrong (password, control) yields a uniform-random
 * prefix that is almost never band-consistent (fall back to a typed honey fake).
 *
 * The scheme stays unauthenticated: this introduces NO stored authenticator and
 * NO new oracle. `wellFormed` is computed purely from the in-band length-prefix
 * check, identically for every input, and the caller emits the same output shape
 * (a string) on both branches.
 *
 * `expectedBand` (when provided) tightens the check: a well-formed frame must
 * have a length prefix that fits inside the known bucket band, not merely inside
 * the raw payload. Honey records are always bucketed, so the band is known and
 * the accidental-well-formed-frame probability collapses to ~band / 2^32.
 */
export async function decryptToPayload(
  ciphertext: Uint8Array,
  params: EncryptionParams,
  expectedBand?: number
): Promise<{ payload: Uint8Array; salt: Uint8Array; wellFormed: boolean; plaintext: Uint8Array }> {
  const { password1, password2, controlData } = params;

  if (ciphertext.length < HEADER_LENGTH) {
    throw malformedInputError(`ciphertext ${ciphertext.length} < header ${HEADER_LENGTH}`);
  }

  const salt = ciphertext.slice(0, SALT_LENGTH);
  const iv = ciphertext.slice(SALT_LENGTH, HEADER_LENGTH);
  const encryptedData = ciphertext.slice(HEADER_LENGTH);

  const key = await deriveKey(password1, password2, salt);
  const decipher = createDecipheriv(ALGORITHM, key, iv);
  const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);

  if (controlData.length < decrypted.length) {
    throw malformedInputError(
      `control ${controlData.length} < payload ${decrypted.length}`
    );
  }
  const controlSlice = controlData.slice(0, decrypted.length);
  const payload = xorBytes(new Uint8Array(decrypted), controlSlice);

  const wellFormed = isWellFormedFrame(payload, expectedBand);
  const plaintext = extractPayload(payload);

  return { payload, salt, wellFormed, plaintext };
}

/**
 * Band-consistent well-formedness check for the inner payload's 4-byte LE length
 * prefix. A frame is well-formed iff the decoded length fits inside the payload
 * (always required) AND, when `expectedBand` is given, the length is consistent
 * with that bucket band (i.e. the slot was written under the same band).
 *
 * Constant-shape: always reads exactly 4 bytes, runs the same comparisons for
 * every input. No early-out that depends on secret-derived branch timing.
 */
export function isWellFormedFrame(payload: Uint8Array, expectedBand?: number): boolean {
  if (payload.length < LENGTH_PREFIX) return false;
  const length = new DataView(payload.buffer, payload.byteOffset, LENGTH_PREFIX).getUint32(0, true);
  const fitsPayload = length <= payload.length - LENGTH_PREFIX;
  if (expectedBand === undefined) return fitsPayload;
  // Bucketed slot: the real/decoy payload was padded to `expectedBand`, so a
  // legit frame's declared length is <= expectedBand - LENGTH_PREFIX. A random
  // prefix from a wrong key lands in this window with probability
  // ~(expectedBand - 3) / 2^32 (sub-1-in-60M for the 64-byte band).
  const fitsBand = length <= expectedBand - LENGTH_PREFIX;
  return fitsPayload && fitsBand;
}

// --- Deniable Encryption (The Key Feature) ---

/**
 * Generate a new control file that makes existing ciphertext decrypt
 * to a completely different plaintext.
 *
 * Given:
 *   - Original ciphertext (encrypted with password1 + password2 + originalControlData)
 *   - The same passwords
 *   - A desired fake plaintext
 *
 * Returns:
 *   - New control data such that decrypt(ciphertext, passwords, newControlData) = desiredPlaintext
 */
export function generateDeniableControl(
  ciphertext: Uint8Array,
  password1: string,
  password2: string,
  desiredPlaintext: Uint8Array
): Promise<DeniableControlResult> {
  return generateDeniableControlAsync(ciphertext, password1, password2, desiredPlaintext);
}

async function generateDeniableControlAsync(
  ciphertext: Uint8Array,
  password1: string,
  password2: string,
  desiredPlaintext: Uint8Array
): Promise<DeniableControlResult> {
  if (ciphertext.length < HEADER_LENGTH) {
    throw new Error('Ciphertext too short - missing header');
  }

  // Extract header
  const salt = ciphertext.slice(0, SALT_LENGTH);
  const iv = ciphertext.slice(SALT_LENGTH, HEADER_LENGTH);
  const encryptedData = ciphertext.slice(HEADER_LENGTH);

  // Build fake payload with length prefix
  const fakePayload = buildPayload(desiredPlaintext);

  if (fakePayload.length > encryptedData.length) {
    throw new Error(
      `Desired plaintext (${desiredPlaintext.length} bytes) is too long for this ciphertext`
    );
  }

  // Derive key (same as used for encryption)
  const key = await deriveKey(password1, password2, salt);

  // AES decrypt to get intermediate (= original payload XOR originalControlData)
  const decipher = createDecipheriv(ALGORITHM, key, iv);
  const intermediate = Buffer.concat([decipher.update(encryptedData), decipher.final()]);

  // Pad fake payload to match intermediate length with random bytes
  let paddedFake: Uint8Array;
  if (fakePayload.length < intermediate.length) {
    paddedFake = new Uint8Array(intermediate.length);
    paddedFake.set(fakePayload, 0);
    const padding = randomBytes(intermediate.length - fakePayload.length);
    paddedFake.set(new Uint8Array(padding), fakePayload.length);
  } else {
    paddedFake = fakePayload;
  }

  // New control data = intermediate XOR fakePayload
  const newControlData = xorBytes(new Uint8Array(intermediate), paddedFake);

  return { controlData: newControlData };
}

// --- Text Mode (hex-encoded, for messaging) ---

/**
 * Encrypt a text string, output as hex string (for copy-paste into messages).
 */
export function encryptText(
  message: string,
  password1: string,
  password2: string,
  controlData: Uint8Array,
  opts?: EncryptTextOptions
): Promise<string> {
  return encryptTextAsync(message, password1, password2, controlData, opts);
}

async function encryptTextAsync(
  message: string,
  password1: string,
  password2: string,
  controlData: Uint8Array,
  opts?: EncryptTextOptions
): Promise<string> {
  const plaintext = new TextEncoder().encode(message);
  const rawPayloadLength = plaintext.length + LENGTH_PREFIX;
  const padToBucket = opts?.unsafeUnpadded !== true;
  if (padToBucket) {
    const bucketLength = bucketedPayloadLength(rawPayloadLength);
    if (controlData.length < bucketLength) {
      throw new Error(
        `Control data (${controlData.length} bytes) must be >= bucketed payload (${bucketLength} bytes); ` +
        'size controlData with bucketedPayloadLength(message bytes + 4), or pass { unsafeUnpadded: true }'
      );
    }
  }
  const { ciphertext } = await encrypt(plaintext, {
    password1,
    password2,
    controlData,
    ...(padToBucket ? { padToBucket: true } : {}),
  });
  return Buffer.from(ciphertext).toString('hex');
}

/**
 * Decrypt a hex-encoded ciphertext back to text.
 */
export function decryptText(
  hexCiphertext: string,
  password1: string,
  password2: string,
  controlData: Uint8Array
): Promise<string> {
  return decryptTextAsync(hexCiphertext, password1, password2, controlData);
}

async function decryptTextAsync(
  hexCiphertext: string,
  password1: string,
  password2: string,
  controlData: Uint8Array
): Promise<string> {
  const ciphertext = new Uint8Array(Buffer.from(hexCiphertext, 'hex'));
  const { plaintext } = await decrypt(ciphertext, { password1, password2, controlData });
  return new TextDecoder().decode(plaintext);
}

// --- Utilities ---

export { SALT_LENGTH, IV_LENGTH, KEY_LENGTH, HEADER_LENGTH, ALGORITHM, BUCKET_BANDS };
