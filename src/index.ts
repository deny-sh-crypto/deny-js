/**
 * deny-sh - Deniable encryption with plausible deniability
 *
 * Built on AES-256-CTR with a control-file XOR layer that enables
 * true deniable encryption: the same ciphertext can be made to decrypt
 * to any arbitrary plaintext by providing a different control file.
 *
 * @example
 * ```ts
 * import { encrypt, decrypt, generateDeniableControl, generateControlData } from 'deny-sh';
 *
 * // Generate a control file
 * const controlData = generateControlData(1024);
 *
 * // Encrypt
 * const message = new TextEncoder().encode('Launch the new product on Monday');
 * const { ciphertext } = await encrypt(message, {
 *   password1: 'correct-horse',
 *   password2: 'battery-staple',
 *   controlData,
 * });
 *
 * // Normal decrypt - returns the real message
 * const { plaintext } = await decrypt(ciphertext, {
 *   password1: 'correct-horse',
 *   password2: 'battery-staple',
 *   controlData,
 * });
 * // plaintext = 'Launch the new product on Monday'
 *
 * // Generate deniable control data - makes it decrypt to something else
 * const fakeMessage = new TextEncoder().encode('Meeting moved to Wednesday');
 * const { controlData: fakeControl } = await generateDeniableControl(
 *   ciphertext, 'correct-horse', 'battery-staple', fakeMessage
 * );
 *
 * // Same ciphertext + same passwords + different control file = different message
 * const { plaintext: fakePlaintext } = await decrypt(ciphertext, {
 *   password1: 'correct-horse',
 *   password2: 'battery-staple',
 *   controlData: fakeControl,
 * });
 * // fakePlaintext = 'Meeting moved to Wednesday'
 * ```
 */

export {
  encrypt,
  decrypt,
  generateDeniableControl,
  generateControlData,
  deriveKey,
  encryptText,
  decryptText,
  bucketedPayloadLength,
  SALT_LENGTH,
  IV_LENGTH,
  KEY_LENGTH,
  HEADER_LENGTH,
  ALGORITHM,
  BUCKET_BANDS,
} from './core.js';

export {
  encryptRecord,
  decryptRecord,
  classifyFieldValue,
  generateLocalDecoy,
  generateDecoyWithHash,
} from './record.js';

// Honey Mode (Phase 1b) - per-type opt-in: wrong password yields a deterministic
// typed fake instead of nonsense, for structured secret types only.
export {
  encryptHoney,
  decryptHoney,
  encryptWithHoney,
  decryptWithHoney,
} from './honey.js';

export {
  isHoneyEligible,
  generateHoneyDecoy,
} from './record-decoy-generators.js';

export type {
  EncryptionParams,
  EncryptResult,
  DecryptResult,
  DeniableControlResult,
  EncryptTextOptions,
} from './core.js';

export type {
  EncryptRecordParams,
  EncryptRecordResult,
  DecoyType,
  DecoyWithHash,
  GenerateDecoyWithHashOptions,
} from './record.js';

export type {
  EncryptHoneyParams,
  EncryptHoneyResult,
  EncryptWithHoneyOptions,
  DecryptWithHoneyOptions,
  DecryptHoneyResult,
} from './honey.js';

export type {
  HoneyDecoyParams,
} from './record-decoy-generators.js';
