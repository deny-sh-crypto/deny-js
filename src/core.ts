/**
 * deny-sh - Core encryption engine
 *
 * Algorithm:
 *
 * ENCRYPT:
 *   1. Derive AES-256 key from password1 + password2 via scrypt
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
 * The length prefix is INSIDE the encrypted+XOR zone, so different control
 * files produce different lengths - no metadata leaks the real message size.
 */

import { createCipheriv, createDecipheriv, randomBytes, scryptSync, createHash } from 'node:crypto';

// --- Types ---

export interface EncryptionParams {
  /** First password/passphrase */
  password1: string;
  /** Second password/passphrase */
  password2: string;
  /** Control file data - must be >= plaintext length + 4 bytes */
  controlData: Uint8Array;
}

export interface EncryptResult {
  /** Encrypted data (salt + iv + ciphertext) */
  ciphertext: Uint8Array;
  /** Salt used for key derivation (also embedded in ciphertext header) */
  salt: Uint8Array;
}

export interface DecryptResult {
  /** Decrypted plaintext */
  plaintext: Uint8Array;
}

export interface DeniableControlResult {
  /** New control data that makes ciphertext decrypt to desiredPlaintext */
  controlData: Uint8Array;
}

// --- Constants ---

const SALT_LENGTH = 32;
const IV_LENGTH = 16;
const KEY_LENGTH = 32; // AES-256
const ALGORITHM = 'aes-256-ctr';
const SCRYPT_N = 2 ** 14; // 16K - fits in constrained environments, still strong KDF
const SCRYPT_R = 8;
const SCRYPT_P = 1;
const SCRYPT_KEYLEN = KEY_LENGTH;
const LENGTH_PREFIX = 4; // 4-byte length prefix inside encrypted zone
const HEADER_LENGTH = SALT_LENGTH + IV_LENGTH; // 48 bytes (unencrypted header)

// --- Key Derivation ---

/**
 * Derive AES-256 key from two passwords using scrypt.
 * Combines both passwords via SHA-256 hashing to avoid length ambiguities.
 */
export function deriveKey(password1: string, password2: string, salt: Uint8Array): Uint8Array {
  const pw1Hash = createHash('sha256').update(password1, 'utf8').digest();
  const pw2Hash = createHash('sha256').update(password2, 'utf8').digest();
  const combined = Buffer.concat([pw1Hash, pw2Hash]);

  const key = scryptSync(combined, salt, SCRYPT_KEYLEN, {
    N: SCRYPT_N,
    r: SCRYPT_R,
    p: SCRYPT_P,
  });

  return new Uint8Array(key);
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
export function encrypt(plaintext: Uint8Array, params: EncryptionParams): EncryptResult {
  const { password1, password2, controlData } = params;

  // Build inner payload with length prefix
  const payload = buildPayload(plaintext);

  if (controlData.length < payload.length) {
    throw new Error(
      `Control data (${controlData.length} bytes) must be >= plaintext + 4 bytes (${payload.length} bytes)`
    );
  }

  // Generate random salt and IV
  const salt = new Uint8Array(randomBytes(SALT_LENGTH));
  const iv = new Uint8Array(randomBytes(IV_LENGTH));

  // Derive key
  const key = deriveKey(password1, password2, salt);

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

  return { ciphertext: result, salt };
}

/**
 * Decrypt ciphertext using dual passwords and the original control file.
 */
export function decrypt(
  ciphertext: Uint8Array,
  params: EncryptionParams
): DecryptResult {
  const { password1, password2, controlData } = params;

  if (ciphertext.length < HEADER_LENGTH) {
    throw new Error('Ciphertext too short - missing header');
  }

  // Extract header
  const salt = ciphertext.slice(0, SALT_LENGTH);
  const iv = ciphertext.slice(SALT_LENGTH, HEADER_LENGTH);
  const encryptedData = ciphertext.slice(HEADER_LENGTH);

  // Derive key
  const key = deriveKey(password1, password2, salt);

  // AES-256-CTR decrypt
  const decipher = createDecipheriv(ALGORITHM, key, iv);
  const decrypted = Buffer.concat([decipher.update(encryptedData), decipher.final()]);

  // XOR with control data to recover payload
  const controlSlice = controlData.slice(0, decrypted.length);
  const payload = xorBytes(new Uint8Array(decrypted), controlSlice);

  // Extract plaintext from payload (reads length prefix, trims)
  const plaintext = extractPayload(payload);

  return { plaintext };
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
): DeniableControlResult {
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
  const key = deriveKey(password1, password2, salt);

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
  controlData: Uint8Array
): string {
  const plaintext = new TextEncoder().encode(message);
  const { ciphertext } = encrypt(plaintext, { password1, password2, controlData });
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
): string {
  const ciphertext = new Uint8Array(Buffer.from(hexCiphertext, 'hex'));
  const { plaintext } = decrypt(ciphertext, { password1, password2, controlData });
  return new TextDecoder().decode(plaintext);
}

// --- Utilities ---

export { SALT_LENGTH, IV_LENGTH, KEY_LENGTH, HEADER_LENGTH, ALGORITHM };
