import { randomBytes } from 'node:crypto';
import { classifyByRegex, matchesShape } from './decoy-engine/classifier.js';
import type { DecoyType } from './decoy-engine/types.js';
import { KNOWN_TYPES } from './decoy-engine/types.js';
import { decrypt, encrypt, generateControlData, generateDeniableControl } from './core.js';
import { generateLocalDecoy } from './record-decoy-generators.js';

export type { DecoyType } from './decoy-engine/types.js';
export { generateLocalDecoy } from './record-decoy-generators.js';

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

export function encodeRecordFrame(record: Record<string, string>, fieldOrder = Object.keys(record)): Uint8Array {
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
  }
  assertUint32(fieldOrder.length, 'field count');
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
  const shapeOk = (value: string): boolean =>
    (value.length === 0 && (type === 'generic' || type === 'freeform-secret')) || matchesShape(value, type);

  if (supplied !== undefined && byteLen(supplied) <= byteLen(realValue) && shapeOk(supplied)) {
    return supplied;
  }

  for (let i = 0; i < 20; i++) {
    const generated = generateLocalDecoy(realValue, type);
    if (byteLen(generated) <= byteLen(realValue) && shapeOk(generated)) return generated;
  }

  throw new Error(`could not generate decoy within real value budget for type ${type}`);
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
  const controlData = generateControlData(frameReal.length + 4);
  const result = await encrypt(frameReal, {
    password1: params.passwords.p1,
    password2: params.passwords.p2,
    controlData,
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
  const { plaintext } = await decrypt(ciphertext, {
    password1: passwords.p1,
    password2: passwords.p2,
    controlData,
  });
  return decodeRecordFrame(plaintext);
}
