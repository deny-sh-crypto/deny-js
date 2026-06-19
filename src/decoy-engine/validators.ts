/**
 * Deep-validity validators for decoy types.
 *
 * The regex layer in classifier.ts (`matchesShape`) answers "does this LOOK like
 * a <type>?". This file answers the harder question "would this PASS the same
 * structural integrity check a real <type> passes?" — Luhn for cards, mod-97 for
 * IBANs, the BIP-39 checksum for seed phrases, Base58Check for Bitcoin WIF keys,
 * and so on.
 *
 * Why this matters for deniability
 * --------------------------------
 * A real secret, by construction, passes its type's deep-validity check (a real
 * credit-card number satisfies Luhn; a real 24-word seed phrase has a valid
 * BIP-39 checksum). If our decoys only matched the *regex shape* but failed the
 * *checksum*, then validity itself would be a distinguisher: an adversary handed
 * two candidate plaintexts could run the checksum and keep the one that passes,
 * defeating deniability for every checksummed type.
 *
 * `chooseDecoy` in record.ts therefore rejects any generated decoy that fails
 * `passesDeepValidity` for its type and regenerates, so a coerced decoy decrypt
 * yields a value that is indistinguishable from a real one on BOTH shape and
 * integrity grounds.
 *
 * Types without a meaningful integrity check (opaque API tokens, random hex
 * keys, freeform secrets) return `true` — there is nothing for an adversary to
 * verify, so shape-correctness is already full deniability for them.
 */

import { createHash } from 'node:crypto';
import type { DecoyType } from './types.js';
import { BIP39_WORDS } from './bip39-wordlist.js';
import { matchesShape } from './classifier.js';

// ─── Luhn (credit cards) ──────────────────────────────────────────────────

/**
 * Luhn mod-10 checksum. Accepts a digit string (spaces/dashes are stripped).
 * Returns true iff the number passes the Luhn check that real PANs satisfy.
 */
export function luhnValid(value: string): boolean {
  const digits = value.replace(/[\s-]/g, '');
  if (!/^[0-9]{12,19}$/.test(digits)) return false;
  let sum = 0;
  let alternate = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48; // '0' === 48
    if (alternate) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

/** Compute the single Luhn check digit for a body of digits (no check digit). */
export function luhnCheckDigit(bodyDigits: string): number {
  // The check digit is appended at the end; positions alternate starting from
  // the check-digit position. With the check digit absent, the rightmost body
  // digit is in the "doubled" position.
  let sum = 0;
  let alternate = true; // body's last digit will be doubled
  for (let i = bodyDigits.length - 1; i >= 0; i--) {
    let d = bodyDigits.charCodeAt(i) - 48;
    if (alternate) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    alternate = !alternate;
  }
  return (10 - (sum % 10)) % 10;
}

// ─── mod-97 (IBAN, ISO 7064) ──────────────────────────────────────────────

/** Convert IBAN letters to the two-digit numbers ISO 13616 / 7064 requires. */
function ibanToNumeric(rearranged: string): string {
  let out = '';
  for (const ch of rearranged) {
    if (ch >= '0' && ch <= '9') {
      out += ch;
    } else if (ch >= 'A' && ch <= 'Z') {
      out += String(ch.charCodeAt(0) - 55); // A=10 ... Z=35
    } else {
      return ''; // invalid character
    }
  }
  return out;
}

/** Big-integer mod 97 over a decimal string (streamed, no BigInt needed). */
function mod97(numeric: string): number {
  let remainder = 0;
  for (let i = 0; i < numeric.length; i++) {
    remainder = (remainder * 10 + (numeric.charCodeAt(i) - 48)) % 97;
  }
  return remainder;
}

/**
 * IBAN mod-97 check (ISO 7064). Move the first 4 chars to the end, convert
 * letters to numbers, and verify the whole thing is ≡ 1 (mod 97).
 */
export function ibanMod97Valid(value: string): boolean {
  const iban = value.replace(/\s+/g, '').toUpperCase();
  if (!/^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$/.test(iban)) return false;
  const rearranged = iban.slice(4) + iban.slice(0, 4);
  const numeric = ibanToNumeric(rearranged);
  if (numeric === '') return false;
  return mod97(numeric) === 1;
}

/** Compute the two check digits for a country code + BBAN so mod-97 passes. */
export function ibanCheckDigits(countryCode: string, bban: string): string {
  const rearranged = bban.toUpperCase() + countryCode.toUpperCase() + '00';
  const numeric = ibanToNumeric(rearranged);
  const remainder = mod97(numeric);
  const check = 98 - remainder;
  return check < 10 ? `0${check}` : String(check);
}

// ─── Business / securities identifiers ───────────────────────────────────

function luhnValidNumeric(digits: string): boolean {
  if (!/^[0-9]+$/.test(digits)) return false;
  let sum = 0;
  let alternate = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (alternate) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

function alphaNumToNumeric(value: string): string {
  let out = '';
  for (const ch of value.toUpperCase()) {
    if (ch >= '0' && ch <= '9') out += ch;
    else if (ch >= 'A' && ch <= 'Z') out += String(ch.charCodeAt(0) - 55);
    else return '';
  }
  return out;
}

/** LEI ISO 17442 / ISO 7064 mod-97 check. */
export function leiValid(value: string): boolean {
  const lei = value.toUpperCase();
  if (!/^[A-Z0-9]{18}[0-9]{2}$/.test(lei)) return false;
  const numeric = alphaNumToNumeric(lei);
  return numeric !== '' && mod97(numeric) === 1;
}

/** Compute LEI check digits for an 18-char alphanumeric body. */
export function leiCheckDigits(body18: string): string {
  const body = body18.toUpperCase();
  if (!/^[A-Z0-9]{18}$/.test(body)) throw new Error('LEI body must be 18 uppercase alphanumeric chars');
  const remainder = mod97(alphaNumToNumeric(`${body}00`));
  const check = 98 - remainder;
  return String(check).padStart(2, '0');
}

/** ISIN checksum: alpha expansion A=10..Z=35, then Luhn over expanded digits. */
export function isinValid(value: string): boolean {
  const isin = value.toUpperCase();
  if (!/^[A-Z]{2}[A-Z0-9]{9}[0-9]$/.test(isin)) return false;
  const numeric = alphaNumToNumeric(isin);
  return numeric !== '' && luhnValidNumeric(numeric);
}

/** Compute the ISIN Luhn check digit for the first 11 ISIN characters. */
export function isinCheckDigit(body11: string): number {
  const body = body11.toUpperCase();
  if (!/^[A-Z]{2}[A-Z0-9]{9}$/.test(body)) throw new Error('ISIN body must be 2 letters + 9 alphanumeric chars');
  return luhnCheckDigit(alphaNumToNumeric(body));
}

function cusipCharValue(ch: string): number {
  if (ch >= '0' && ch <= '9') return ch.charCodeAt(0) - 48;
  if (ch >= 'A' && ch <= 'Z') return ch.charCodeAt(0) - 55;
  if (ch === '*') return 36;
  if (ch === '@') return 37;
  if (ch === '#') return 38;
  return -1;
}

/** CUSIP mod-10 check digit, alternating weights 1/2 from the left. */
export function cusipCheckDigit(body8: string): number {
  const body = body8.toUpperCase();
  if (!/^[A-Z0-9*@#]{8}$/.test(body)) throw new Error('CUSIP body must be 8 CUSIP chars');
  let sum = 0;
  for (let i = 0; i < body.length; i++) {
    const raw = cusipCharValue(body[i]!);
    const weighted = raw * (i % 2 === 0 ? 1 : 2);
    sum += Math.floor(weighted / 10) + (weighted % 10);
  }
  return (10 - (sum % 10)) % 10;
}

export function cusipValid(value: string): boolean {
  const cusip = value.toUpperCase();
  if (!/^[A-Z0-9*@#]{8}[0-9]$/.test(cusip)) return false;
  return cusipCheckDigit(cusip.slice(0, 8)) === cusip.charCodeAt(8) - 48;
}

const EIN_PREFIXES = new Set([
  '01', '02', '03', '04', '05', '06', '10', '11', '12', '13', '14', '15', '16',
  '20', '21', '22', '23', '24', '25', '26', '27', '30', '31', '32', '33', '34',
  '35', '36', '37', '38', '39', '40', '41', '42', '43', '44', '45', '46', '47',
  '48', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '60', '61',
  '62', '63', '64', '65', '66', '67', '68', '71', '72', '73', '74', '75', '76',
  '77', '80', '81', '82', '83', '84', '85', '86', '87', '88', '90', '91', '92',
  '93', '94', '95', '98', '99',
]);

export function einValid(value: string): boolean {
  if (!/^[0-9]{2}-[0-9]{7}$/.test(value)) return false;
  return EIN_PREFIXES.has(value.slice(0, 2));
}

// ─── Banking / payment identifiers ───────────────────────────────────────

/** ABA routing number checksum: weights 3,7,1 repeated over all 9 digits. */
export function abaRoutingNumberValid(value: string): boolean {
  if (!/^[0-9]{9}$/.test(value)) return false;
  const weights = [3, 7, 1];
  let sum = 0;
  for (let i = 0; i < value.length; i++) {
    sum += (value.charCodeAt(i) - 48) * weights[i % 3]!;
  }
  return sum % 10 === 0;
}

/** Compute the final ABA check digit for the first 8 routing-number digits. */
export function abaRoutingCheckDigit(body8: string): number {
  if (!/^[0-9]{8}$/.test(body8)) throw new Error('ABA routing body must be 8 digits');
  const weights = [3, 7, 1, 3, 7, 1, 3, 7];
  let sum = 0;
  for (let i = 0; i < body8.length; i++) {
    sum += (body8.charCodeAt(i) - 48) * weights[i]!;
  }
  return (10 - (sum % 10)) % 10;
}

// ─── BIP-39 checksum (seed phrases) ───────────────────────────────────────

const BIP39_INDEX: Map<string, number> = new Map(BIP39_WORDS.map((w, i) => [w, i]));

/**
 * BIP-39 mnemonic checksum check.
 *
 * A mnemonic encodes ENT bits of entropy + CS checksum bits, where the words map
 * to 11-bit indices, total bits = ENT + CS, CS = ENT / 32, and CS = the first CS
 * bits of SHA-256(entropy). We rebuild the entropy from the word indices and
 * verify the trailing checksum bits match SHA-256(entropy).
 */
export function bip39ChecksumPasses(phrase: string): boolean {
  const words = phrase.trim().split(/\s+/).map((w) => w.toLowerCase());
  if (![12, 15, 18, 21, 24].includes(words.length)) return false;

  // Build the bit string from 11-bit word indices.
  let bits = '';
  for (const w of words) {
    const idx = BIP39_INDEX.get(w);
    if (idx === undefined) return false;
    bits += idx.toString(2).padStart(11, '0');
  }

  const totalBits = words.length * 11;
  const csBits = totalBits / 33; // CS = ENT/32 and ENT = totalBits*32/33
  const entBits = totalBits - csBits;
  if (entBits % 8 !== 0) return false;

  const entropy = new Uint8Array(entBits / 8);
  for (let i = 0; i < entropy.length; i++) {
    entropy[i] = parseInt(bits.slice(i * 8, i * 8 + 8), 2);
  }

  const hash = createHash('sha256').update(entropy).digest();
  const hashBits = Array.from(hash)
    .map((b) => b.toString(2).padStart(8, '0'))
    .join('');
  const expectedChecksum = hashBits.slice(0, csBits);
  const actualChecksum = bits.slice(entBits);
  return expectedChecksum === actualChecksum;
}

/**
 * Build a checksum-valid BIP-39 mnemonic of `wordCount` words from a source of
 * entropy bytes. Used by the decoy generator so generated seed phrases pass
 * `bip39ChecksumPasses` (and are therefore indistinguishable from a real one on
 * checksum grounds).
 */
export function bip39FromEntropy(entropy: Uint8Array, wordCount: 12 | 15 | 18 | 21 | 24): string {
  const entBits = entropy.length * 8;
  const csBits = entBits / 32;
  if ((entBits + csBits) / 11 !== wordCount) {
    throw new Error(`entropy length ${entropy.length} does not match ${wordCount} words`);
  }
  const hash = createHash('sha256').update(entropy).digest();
  let bits = Array.from(entropy)
    .map((b) => b.toString(2).padStart(8, '0'))
    .join('');
  const hashBits = Array.from(hash)
    .map((b) => b.toString(2).padStart(8, '0'))
    .join('');
  bits += hashBits.slice(0, csBits);

  const words: string[] = [];
  for (let i = 0; i < wordCount; i++) {
    const idx = parseInt(bits.slice(i * 11, i * 11 + 11), 2);
    words.push(BIP39_WORDS[idx]!);
  }
  return words.join(' ');
}

// ─── Base58Check (Bitcoin WIF) ────────────────────────────────────────────

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const BASE58_INDEX: Map<string, number> = new Map(
  BASE58_ALPHABET.split('').map((c, i) => [c, i])
);

/** Decode a Base58 string to bytes, or null on invalid alphabet. */
export function base58Decode(input: string): Uint8Array | null {
  if (input.length === 0) return new Uint8Array(0);
  const bytes: number[] = [0];
  for (const ch of input) {
    const val = BASE58_INDEX.get(ch);
    if (val === undefined) return null;
    let carry = val;
    for (let j = 0; j < bytes.length; j++) {
      carry += bytes[j]! * 58;
      bytes[j] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  // Leading '1's in Base58 are leading zero bytes.
  for (let k = 0; k < input.length && input[k] === '1'; k++) bytes.push(0);
  return new Uint8Array(bytes.reverse());
}

/** Encode bytes to Base58. */
export function base58Encode(bytes: Uint8Array): string {
  if (bytes.length === 0) return '';
  const digits: number[] = [0];
  for (const byte of bytes) {
    let carry = byte;
    for (let j = 0; j < digits.length; j++) {
      carry += digits[j]! << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = (carry / 58) | 0;
    }
  }
  let out = '';
  for (let k = 0; k < bytes.length && bytes[k] === 0; k++) out += '1';
  for (let q = digits.length - 1; q >= 0; q--) out += BASE58_ALPHABET[digits[q]!];
  return out;
}

/** Double-SHA-256, the Base58Check checksum primitive. */
function doubleSha256(data: Uint8Array): Uint8Array {
  const first = createHash('sha256').update(data).digest();
  return new Uint8Array(createHash('sha256').update(first).digest());
}

/**
 * Base58Check validity: decode, split off the 4-byte trailing checksum, and
 * verify it equals the first 4 bytes of double-SHA-256(payload). This is exactly
 * the check a real Bitcoin WIF private key satisfies.
 */
export function base58CheckValid(value: string): boolean {
  const decoded = base58Decode(value);
  if (decoded === null || decoded.length < 5) return false;
  const payload = decoded.slice(0, decoded.length - 4);
  const checksum = decoded.slice(decoded.length - 4);
  const expected = doubleSha256(payload).slice(0, 4);
  for (let i = 0; i < 4; i++) {
    if (checksum[i] !== expected[i]) return false;
  }
  return true;
}

/** Encode payload bytes as a Base58Check string (payload + 4-byte checksum). */
export function base58CheckEncode(payload: Uint8Array): string {
  const checksum = doubleSha256(payload).slice(0, 4);
  const full = new Uint8Array(payload.length + 4);
  full.set(payload, 0);
  full.set(checksum, payload.length);
  return base58Encode(full);
}

/**
 * Bitcoin WIF validity: a Base58Check string whose payload is 0x80 + 32-byte key
 * (uncompressed) or 0x80 + 32-byte key + 0x01 (compressed).
 */
export function bitcoinWifValid(value: string): boolean {
  if (!base58CheckValid(value)) return false;
  const decoded = base58Decode(value);
  if (decoded === null) return false;
  const payload = decoded.slice(0, decoded.length - 4);
  if (payload[0] !== 0x80) return false;
  return payload.length === 33 || (payload.length === 34 && payload[33] === 0x01);
}

// ─── Solana key (raw 64-byte Base58) ──────────────────────────────────────

/** Solana secret keys are 64 raw bytes, Base58-encoded (no checksum). */
export function solanaKeyValid(value: string): boolean {
  const decoded = base58Decode(value);
  return decoded !== null && decoded.length === 64;
}

// ─── Ethereum key (raw 32-byte hex) ───────────────────────────────────────

/** Ethereum private keys are 32 raw bytes, hex-encoded (optional 0x prefix). */
export function ethereumKeyValid(value: string): boolean {
  const hex = value.startsWith('0x') ? value.slice(2) : value;
  return /^[0-9a-fA-F]{64}$/.test(hex);
}

// ─── UK NHS number (mod-11) ───────────────────────────────────────────────

/**
 * UK NHS number checksum (mod-11). 10 digits; weights 10..2 over the first 9,
 * remainder from 11 must equal the 10th digit (11→0; 10 is invalid).
 */
export function nhsMod11Valid(value: string): boolean {
  const digits = value.replace(/\s+/g, '');
  if (!/^[0-9]{10}$/.test(digits)) return false;
  let sum = 0;
  for (let i = 0; i < 9; i++) {
    sum += (digits.charCodeAt(i) - 48) * (10 - i);
  }
  let check = 11 - (sum % 11);
  if (check === 11) check = 0;
  if (check === 10) return false;
  return check === digits.charCodeAt(9) - 48;
}

/** Compute the NHS mod-11 check digit for a 9-digit body, or null if invalid. */
export function nhsCheckDigit(body9: string): number | null {
  if (!/^[0-9]{9}$/.test(body9)) return null;
  let sum = 0;
  for (let i = 0; i < 9; i++) sum += (body9.charCodeAt(i) - 48) * (10 - i);
  let check = 11 - (sum % 11);
  if (check === 11) check = 0;
  if (check === 10) return null;
  return check;
}

// --- US medical identifiers ------------------------------------------------

export function npiValid(value: string): boolean {
  const digits = value.replace(/\s+/g, '');
  return /^[0-9]{10}$/.test(digits) && luhnValid(`80840${digits}`);
}

export function deaCheckDigit(body6: string): number {
  if (!/^[0-9]{6}$/.test(body6)) throw new Error('DEA body must be 6 digits');
  const d = Array.from(body6, (ch) => ch.charCodeAt(0) - 48);
  return (d[0]! + d[2]! + d[4]! + 2 * (d[1]! + d[3]! + d[5]!)) % 10;
}

export function deaNumberValid(value: string): boolean {
  if (!/^[A-Z]{2}[0-9]{7}$/.test(value)) return false;
  const body = value.slice(2, 8);
  return deaCheckDigit(body) === value.charCodeAt(8) - 48;
}

// --- Legal / government / identity identifiers ----------------------------

export function itinValid(value: string): boolean {
  if (!/^9[0-9]{2}-[0-9]{2}-[0-9]{4}$/.test(value)) return false;
  const group = Number(value.slice(4, 6));
  return (group >= 50 && group <= 65)
    || (group >= 70 && group <= 88)
    || (group >= 90 && group <= 92)
    || (group >= 94 && group <= 99);
}

function mrzCharValue(ch: string): number {
  if (ch >= '0' && ch <= '9') return ch.charCodeAt(0) - 48;
  if (ch >= 'A' && ch <= 'Z') return ch.charCodeAt(0) - 55;
  if (ch === '<') return 0;
  return -1;
}

/**
 * ICAO Doc 9303 MRZ check digit. Characters map 0-9/A-Z/< to 0-9/10-35/0 and
 * use repeated 7,3,1 weights across the checked field.
 */
export function mrzCheckDigit(field: string): number {
  const weights = [7, 3, 1];
  let sum = 0;
  for (let i = 0; i < field.length; i++) {
    const value = mrzCharValue(field[i]!);
    if (value < 0) throw new Error('MRZ field contains invalid character');
    sum += value * weights[i % 3]!;
  }
  return sum % 10;
}

export function passportMrzValid(value: string): boolean {
  if (!/^[A-Z0-9<]{44}\n[A-Z0-9<]{44}$/.test(value)) return false;
  const [, line2] = value.split('\n');
  if (line2 === undefined) return false;
  if (mrzCheckDigit(line2.slice(0, 9)) !== line2.charCodeAt(9) - 48) return false;
  if (mrzCheckDigit(line2.slice(13, 19)) !== line2.charCodeAt(19) - 48) return false;
  if (mrzCheckDigit(line2.slice(21, 27)) !== line2.charCodeAt(27) - 48) return false;
  if (mrzCheckDigit(line2.slice(28, 42)) !== line2.charCodeAt(42) - 48) return false;
  const composite = `${line2.slice(0, 10)}${line2.slice(13, 20)}${line2.slice(21, 43)}`;
  return mrzCheckDigit(composite) === line2.charCodeAt(43) - 48;
}

const VERHOEFF_D = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
] as const;
const VERHOEFF_P = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
] as const;
const VERHOEFF_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9] as const;

/**
 * Verhoeff decimal checksum (dihedral-group tables d/p/inv). Aadhaar uses the
 * final digit as a Verhoeff check digit over the preceding 11 digits.
 */
export function verhoeffCheckDigit(body: string): number {
  if (!/^[0-9]+$/.test(body)) throw new Error('Verhoeff body must be digits');
  let c = 0;
  for (let i = 0; i < body.length; i++) {
    const digit = body.charCodeAt(body.length - 1 - i) - 48;
    c = VERHOEFF_D[c]![VERHOEFF_P[(i + 1) % 8]![digit]!]!;
  }
  return VERHOEFF_INV[c]!;
}

export function aadhaarValid(value: string): boolean {
  if (!/^[2-9][0-9]{11}$/.test(value)) return false;
  let c = 0;
  for (let i = 0; i < value.length; i++) {
    const digit = value.charCodeAt(value.length - 1 - i) - 48;
    c = VERHOEFF_D[c]![VERHOEFF_P[i % 8]![digit]!]!;
  }
  return c === 0;
}

export function eidasIdValid(value: string): boolean {
  return /^[A-Z]{2}\/[A-Z]{2}\/[A-Z0-9]{1,20}$/.test(value);
}

// --- Universal / tech / comms identifiers ---------------------------------

export function emailAddressValid(value: string): boolean {
  if (value.length > 254) return false;
  const parts = value.split('@');
  if (parts.length !== 2) return false;
  const [local, domain] = parts;
  if (!local || !domain || local.length > 64) return false;
  if (!/^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$/.test(local)) return false;
  const labels = domain.split('.');
  if (labels.length < 2) return false;
  if (!/^[A-Za-z]{2,24}$/.test(labels[labels.length - 1]!)) return false;
  return labels.every((label) => /^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$/.test(label));
}

export function ipv4AddressValid(value: string): boolean {
  const parts = value.split('.');
  return parts.length === 4
    && parts.every((part) => /^[0-9]{1,3}$/.test(part) && Number(part) <= 255);
}

export function ipv6AddressValid(value: string): boolean {
  return /^[0-9A-Fa-f]{4}:[0-9A-Fa-f]{4}:[0-9A-Fa-f]{4}:[0-9A-Fa-f]{4}:[0-9A-Fa-f]{4}:[0-9A-Fa-f]{4}:[0-9A-Fa-f]{4}:[0-9A-Fa-f]{4}$/.test(value);
}

export function macAddressValid(value: string): boolean {
  if (!/^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}$/.test(value)) return false;
  return (parseInt(value.slice(0, 2), 16) & 0x02) === 0x02;
}

export function imeiValid(value: string): boolean {
  return /^[0-9]{15}$/.test(value) && luhnValid(value);
}

function vinTranslit(ch: string): number {
  if (ch >= '0' && ch <= '9') return ch.charCodeAt(0) - 48;
  const map: Record<string, number> = {
    A: 1, B: 2, C: 3, D: 4, E: 5, F: 6, G: 7, H: 8,
    J: 1, K: 2, L: 3, M: 4, N: 5, P: 7, R: 9,
    S: 2, T: 3, U: 4, V: 5, W: 6, X: 7, Y: 8, Z: 9,
  };
  return map[ch] ?? -1;
}

export function vinCheckDigit(vin17: string): string {
  const vin = vin17.toUpperCase();
  if (!/^[A-HJ-NPR-Z0-9]{17}$/.test(vin)) throw new Error('VIN must be 17 chars excluding I/O/Q');
  const weights = [8, 7, 6, 5, 4, 3, 2, 10, 0, 9, 8, 7, 6, 5, 4, 3, 2];
  let sum = 0;
  for (let i = 0; i < vin.length; i++) {
    const value = vinTranslit(vin[i]!);
    if (value < 0) throw new Error('VIN contains invalid character');
    sum += value * weights[i]!;
  }
  const rem = sum % 11;
  return rem === 10 ? 'X' : String(rem);
}

export function vinValid(value: string): boolean {
  const vin = value.toUpperCase();
  return /^[A-HJ-NPR-Z0-9]{17}$/.test(vin) && vin[8] === vinCheckDigit(vin);
}

export function uuidValid(value: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value);
}

// ─── Dispatcher ───────────────────────────────────────────────────────────

/**
 * Deep-validity check for a value of a given type.
 *
 * Returns true if `value` would pass the integrity check a REAL value of `type`
 * satisfies. Types with no meaningful integrity check (opaque tokens, random
 * keys, freeform) return true — there is nothing to verify, so matching the
 * shape is already indistinguishable from a real value.
 *
 * This is the predicate `chooseDecoy` uses to reject would-be decoys that a
 * coercing adversary could disprove by checksum.
 */
export function passesDeepValidity(value: string, type: DecoyType): boolean {
  switch (type) {
    case 'credit-card':
      return luhnValid(value);
    case 'iban':
      return ibanMod97Valid(value);
    case 'bip39-phrase':
      return bip39ChecksumPasses(value);
    case 'bitcoin-wif':
      return bitcoinWifValid(value);
    case 'solana-private-key':
      return solanaKeyValid(value);
    case 'ethereum-private-key':
      return ethereumKeyValid(value);
    case 'uk-nhs-number':
      return nhsMod11Valid(value);
    case 'us-npi':
      return npiValid(value);
    case 'us-dea-number':
      return deaNumberValid(value);
    case 'lei':
      return leiValid(value);
    case 'isin':
      return isinValid(value);
    case 'cusip':
      return cusipValid(value);
    case 'us-ein':
      return einValid(value);
    case 'duns':
      return matchesShape(value, type);
    case 'us-routing-number':
      return abaRoutingNumberValid(value);
    case 'us-bank-account':
    case 'bic-swift':
      return matchesShape(value, type);
    case 'us-medicare-mbi':
    case 'us-ndc':
      return matchesShape(value, type);
    case 'us-itin':
      return itinValid(value);
    case 'passport-mrz':
      return passportMrzValid(value);
    case 'aadhaar':
      return aadhaarValid(value);
    case 'eidas-id':
      return eidasIdValid(value);
    case 'email-address':
      return emailAddressValid(value);
    case 'ipv4-address':
      return ipv4AddressValid(value);
    case 'ipv6-address':
      return ipv6AddressValid(value);
    case 'mac-address':
      return macAddressValid(value);
    case 'imei':
      return imeiValid(value);
    case 'vin':
      return vinValid(value);
    case 'uuid':
      return uuidValid(value);
    case 'us-passport':
    case 'uscis-number':
      return matchesShape(value, type);
    // Types whose integrity is purely structural (opaque random bodies, key
    // prefixes, URIs, PEM framing, JWT JSON header) have no additional checksum
    // a real value would pass that a shape-correct decoy would fail. The regex
    // shape check is the full plausibility bar for these.
    default:
      return true;
  }
}

/**
 * Combined gate: a value is a fully-plausible decoy for `type` iff it matches
 * the regex shape AND passes deep validity. This is the exact bar `chooseDecoy`
 * enforces before accepting a generated (or caller-supplied) decoy.
 */
export function isPlausibleDecoy(value: string, type: DecoyType): boolean {
  return matchesShape(value, type) && passesDeepValidity(value, type);
}
