import { randomBytes } from 'node:crypto';
import { classifyByRegex, matchesShape } from './decoy-engine/classifier.js';
import { passesDeepValidity } from './decoy-engine/validators.js';
import type { DecoyType } from './decoy-engine/types.js';
import { KNOWN_TYPES } from './decoy-engine/types.js';
import { decrypt, encrypt, generateControlData, generateDeniableControl, bucketedPayloadLength } from './core.js';
import { generateLocalDecoy } from './record-decoy-generators.js';

export type { DecoyType } from './decoy-engine/types.js';
export { generateLocalDecoy, generateDecoyWithHash } from './record-decoy-generators.js';
export type { DecoyWithHash, GenerateDecoyWithHashOptions } from './record-decoy-generators.js';

export interface EncryptRecordParams {
  /** Real record: field name -> field value (both strings). */
  real: Record<string, string>;
  /** Dual passwords for the deniability layer. */
  passwords: { p1: string; p2: string };
  /**
   * Optional per-field decoy override. Use when caller wants to supply their own
   * decoy values instead of letting the helper generate them (e.g. story-coherent
   * decoys curated by hand, or upgraded via the server /v1/decoy/suggest endpoint).
   * Keys must match `real` exactly. Missing keys are auto-generated locally.
   */
  decoys?: Record<string, string>;
  /**
   * Optional explicit type hint per field, used to bypass auto-classification.
   * Same key set as `real`. Type names match the DecoyType union exported from
   * src/decoy-engine/types.ts (re-exported in this file).
   */
  explicitTypes?: Record<string, DecoyType>;
}

export interface EncryptRecordResult {
  /** Combined ciphertext: a single buffer containing all field ciphertexts framed. */
  ciphertext: Uint8Array;
  /** Control file that decrypts to `real`. */
  realCtrl: Uint8Array;
  /** Control file that decrypts to the generated/supplied decoy record. */
  decoyCtrl: Uint8Array;
  /** Decoy record actually used (so callers can inspect what the helper picked). */
  decoy: Record<string, string>;
  /** Per-field type that was used (auto-detected or explicit). */
  detectedTypes: Record<string, DecoyType>;
}

const MAGIC = new Uint8Array([0x44, 0x52, 0x43, 0x31]); // DRC1
const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();
const OPAQUE_RECORD_DECRYPT_ERROR = 'record decrypt failed';

export function classifyFieldValue(value: string): DecoyType {
  return classifyByRegex(value) ?? 'generic';
}

function assertKnownType(type: DecoyType): void {
  if (!(KNOWN_TYPES as readonly string[]).includes(type)) {
    throw new Error(`unknown decoy type: ${type}`);
  }
}

function byteLen(value: string): number {
  return textEncoder.encode(value).length;
}

function padTo(input: Uint8Array, length: number): Uint8Array {
  if (input.length === length) return input;
  if (input.length > length) throw new Error('cannot pad to shorter length');
  const out = new Uint8Array(length);
  out.set(input, 0);
  out.set(randomBytes(length - input.length), input.length);
  return out;
}

function assertUint16(n: number, label: string): void {
  if (n > 0xffff) throw new Error(`${label} too long`);
}

function assertUint32(n: number, label: string): void {
  if (n > 0xffffffff) throw new Error(`${label} too long`);
}

// P2-3: hard cap on the encoded record frame. A record is a handful of small
// secrets (api keys, seed phrases, db URIs), never megabytes. Cap the total so a
// pathological input can't drive an unbounded allocation. 16 MiB is orders of
// magnitude above any legitimate credential record.
const MAX_FRAME_BYTES = 16 * 1024 * 1024;

export function encodeRecordFrame(record: Record<string, string>, fieldOrder = Object.keys(record)): Uint8Array {
  // P2-2: guard the field count up front (before building anything) so the
  // uint32 field-count writer can never silently wrap.
  assertUint32(fieldOrder.length, 'field count');
  const chunks: Uint8Array[] = [];
  let total = MAGIC.length + 4;
  for (const name of fieldOrder) {
    if (!Object.prototype.hasOwnProperty.call(record, name)) throw new Error(`missing field: ${name}`);
    const nameBytes = textEncoder.encode(name);
    const valueBytes = textEncoder.encode(record[name]!);
    assertUint16(nameBytes.length, 'field name');
    assertUint32(valueBytes.length, 'field value');
    const header = new Uint8Array(2 + nameBytes.length + 4);
    const view = new DataView(header.buffer);
    view.setUint16(0, nameBytes.length, true);
    header.set(nameBytes, 2);
    view.setUint32(2 + nameBytes.length, valueBytes.length, true);
    chunks.push(header, valueBytes);
    total += header.length + valueBytes.length;
    if (total > MAX_FRAME_BYTES) {
      throw new Error(`record frame exceeds maximum size (${MAX_FRAME_BYTES} bytes)`);
    }
  }
  const out = new Uint8Array(total);
  out.set(MAGIC, 0);
  const view = new DataView(out.buffer);
  view.setUint32(4, fieldOrder.length, true);
  let offset = 8;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

export function decodeRecordFrame(frame: Uint8Array): Record<string, string> {
  if (frame.length < 8) throw new Error('invalid frame magic');
  for (let i = 0; i < MAGIC.length; i++) {
    if (frame[i] !== MAGIC[i]) throw new Error('invalid frame magic');
  }
  const view = new DataView(frame.buffer, frame.byteOffset, frame.byteLength);
  const fieldCount = view.getUint32(4, true);
  let offset = 8;
  const out: Record<string, string> = {};
  for (let i = 0; i < fieldCount; i++) {
    if (offset + 2 > frame.length) throw new Error('truncated frame');
    const nameLen = view.getUint16(offset, true);
    offset += 2;
    if (offset + nameLen + 4 > frame.length) throw new Error('truncated frame');
    const name = textDecoder.decode(frame.slice(offset, offset + nameLen));
    offset += nameLen;
    const valueLen = view.getUint32(offset, true);
    offset += 4;
    if (offset + valueLen > frame.length) throw new Error('truncated frame');
    out[name] = textDecoder.decode(frame.slice(offset, offset + valueLen));
    offset += valueLen;
  }
  return out;
}

function chooseDecoy(realValue: string, type: DecoyType, supplied?: string): string {
  // A plausible decoy must satisfy BOTH the regex shape AND the type's
  // deep-validity check (Luhn / mod-97 / BIP-39 checksum / Base58Check / ...).
  // Shape alone is not enough: a real value passes its checksum, so a decoy that
  // fails the checksum would be a real-vs-decoy distinguisher for any adversary
  // who runs the check. passesDeepValidity returns true for types with no
  // meaningful integrity check, so those keep shape-only behaviour.
  const plausible = (value: string): boolean => {
    if (value.length === 0 && (type === 'generic' || type === 'freeform-secret')) return true;
    return matchesShape(value, type) && passesDeepValidity(value, type);
  };

  if (supplied !== undefined && byteLen(supplied) <= byteLen(realValue) && plausible(supplied)) {
    return supplied;
  }

  // Generators for checksummed types emit valid values directly, so this loop
  // normally terminates on the first iteration; the extra attempts cover the
  // rare case where length budget + checksum constraints collide.
  for (let i = 0; i < 50; i++) {
    let generated: string;
    try {
      generated = generateLocalDecoy(realValue, type);
    } catch {
      continue;
    }
    if (byteLen(generated) <= byteLen(realValue) && plausible(generated)) return generated;
  }

  if (type !== 'generic' && type !== 'freeform-secret') {
    throw new Error(
      `could not generate valid ${type} decoy within real value budget; ` +
      'provide an explicit valid decoy or use a longer real value'
    );
  }

  const fallback = generateLocalDecoy(realValue, 'generic');
  if (byteLen(fallback) <= byteLen(realValue)) return fallback;

  throw new Error(`could not generate valid decoy within real value budget for type ${type}`);
}

/**
 * Encrypt a structured key-value record with a deniable decoy record.
 *
 * Provides value-deniability: the decoy frame has realistic-looking field
 * values generated per the type classification of each real value.
 *
 * Security note: encryptRecord provides value-deniability, NOT
 * schema-deniability. The decoy frame uses the same field names and type
 * classes as the real frame, because realistic decoys require structural
 * similarity. An attacker who coerces a successful decoy decrypt learns
 * the field names and type classes of the real record (but not the values).
 * For full schema-deniability, encrypt the entire record as a freeform
 * blob using encrypt() instead.
 */
export async function encryptRecord(params: EncryptRecordParams): Promise<EncryptRecordResult> {
  const real = params.real;
  const fieldOrder = Object.keys(real);
  const detectedTypes: Record<string, DecoyType> = {};
  const decoy: Record<string, string> = {};

  for (const key of fieldOrder) {
    const explicit = params.explicitTypes?.[key];
    const type = explicit ?? classifyFieldValue(real[key]!);
    assertKnownType(type);
    detectedTypes[key] = type;
    decoy[key] = chooseDecoy(real[key]!, type, params.decoys?.[key]);
  }

  const frameReal = encodeRecordFrame(real, fieldOrder);
  const frameDecoyRaw = encodeRecordFrame(decoy, fieldOrder);
  if (frameDecoyRaw.length > frameReal.length) {
    throw new Error('generated decoy frame exceeds real frame budget');
  }
  const frameDecoy = padTo(frameDecoyRaw, frameReal.length);
  // Length privacy: bucket the ciphertext size so the encrypted record's
  // byte-count reveals only a coarse band, not the exact real-record length.
  // Control data must cover the padded payload.
  const targetPayloadLen = bucketedPayloadLength(frameReal.length + 4);
  const controlData = generateControlData(targetPayloadLen);
  const result = await encrypt(frameReal, {
    password1: params.passwords.p1,
    password2: params.passwords.p2,
    controlData,
    padToBucket: true,
  });
  const { controlData: decoyCtrl } = await generateDeniableControl(
    result.ciphertext,
    params.passwords.p1,
    params.passwords.p2,
    frameDecoy
  );
  return {
    ciphertext: result.ciphertext,
    realCtrl: controlData,
    decoyCtrl,
    decoy,
    detectedTypes,
  };
}

export async function decryptRecord(
  ciphertext: Uint8Array,
  controlData: Uint8Array,
  passwords: { p1: string; p2: string }
): Promise<Record<string, string>> {
  try {
    const { plaintext } = await decrypt(ciphertext, {
      password1: passwords.p1,
      password2: passwords.p2,
      controlData,
    });
    return decodeRecordFrame(plaintext);
  } catch {
    throw new Error(OPAQUE_RECORD_DECRYPT_ERROR);
  }
}
