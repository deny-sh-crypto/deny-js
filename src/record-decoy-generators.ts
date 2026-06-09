import { createHash, randomBytes } from 'node:crypto';
import { BIP39_WORDS } from './decoy-engine/bip39-wordlist.js';
import {
  luhnCheckDigit,
  ibanCheckDigits,
  bip39FromEntropy,
  base58CheckEncode,
  base58Encode,
} from './decoy-engine/validators.js';
import type { DecoyType } from './decoy-engine/types.js';
import { type ByteSource, SeededByteSource, sourcedInt, deriveHoneySeed } from './decoy-engine/seeded-rng.js';

/**
 * Ambient byte source for shape generation. Defaults to a randomBytes-backed
 * source (the existing curated-decoy behaviour, byte-for-byte unchanged). When
 * Honey Mode generates a fake from a wrong password, it temporarily swaps in a
 * deterministic SeededByteSource via withSeededSource() for the duration of one
 * synchronous generateLocalDecoy() call. Generation is fully synchronous (no
 * awaits), so a module-level ambient source is safe and re-entrant within a
 * single call stack.
 */
let AMBIENT_SOURCE: ByteSource | null = null;

function sourceBytes(n: number): Uint8Array {
  if (AMBIENT_SOURCE) return AMBIENT_SOURCE.bytes(n);
  return new Uint8Array(randomBytes(n));
}

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const ALNUM_UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const ALPHA_LOWER = 'abcdefghijklmnopqrstuvwxyz';
const ALNUM_LOWER = 'abcdefghijklmnopqrstuvwxyz0123456789';
const BASE64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';
const BASE64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
const HEX = '0123456789abcdef';
const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const NI_FIRST = 'ABCEGHJKLMNOPRSTWXYZ';
const NI_SECOND = 'ABCEGHJKLMNPRSTWXYZ';

function randInt(max: number): number {
  if (max <= 0) return 0;
  if (AMBIENT_SOURCE) return sourcedInt(AMBIENT_SOURCE, max);
  const limit = Math.floor(0x100000000 / max) * max;
  while (true) {
    const b = randomBytes(4).readUInt32LE(0);
    if (b < limit) return b % max;
  }
}

function chars(alphabet: string, len: number): string {
  let out = '';
  for (let i = 0; i < len; i++) out += alphabet[randInt(alphabet.length)];
  return out;
}

function digits(len: number): string {
  return chars('0123456789', len);
}

function boundedLen(realLen: number, prefixLen: number, minBody: number, fixedBody?: number): number {
  if (fixedBody !== undefined) {
    if (prefixLen + fixedBody > realLen) throw new Error('generated decoy exceeds real value length');
    return fixedBody;
  }
  const bodyLen = Math.max(minBody, realLen - prefixLen);
  if (prefixLen + bodyLen > realLen) throw new Error('generated decoy exceeds real value length');
  return bodyLen;
}

function token(prefix: string, realLen: number, alphabet = ALNUM, minBody = 1, fixedBody?: number): string {
  return prefix + chars(alphabet, boundedLen(realLen, prefix.length, minBody, fixedBody));
}

function segment(len: number, alphabet = BASE64URL): string {
  return chars(alphabet, Math.max(1, len));
}

function splitLengths(real: string, parts: number): number[] {
  const segs = real.split('.');
  if (segs.length === parts) return segs.map((s) => Math.max(1, s.length));
  const base = Math.max(1, Math.floor(real.length / parts));
  return Array.from({ length: parts }, (_, i) => (i === parts - 1 ? Math.max(1, real.length - base * (parts - 1)) : base));
}

// --- Human-like freeform decoy generation ---------------------------------
//
// A real freeform secret is overwhelmingly a human-chosen password or
// passphrase: dictionary words, capitalisation at the front, digits at the
// end, a small set of symbols, and a LOW symbol rate. The old generator
// (randomPrintableSameLength) drew uniformly from 95 printable ASCII, giving a
// ~50% symbol rate that a one-feature classifier separates from real secrets
// with ~100% accuracy (red-team AUC 0.999). The fix is to PROFILE the real
// value and emit a decoy with the same length, same character-class layout,
// same case pattern, and word-shaped alphabetic runs, so no shape statistic
// (symbol rate, digit rate, case rate, vowel rate, entropy) separates the two.

const SYMBOL_POOL = '!@#$%^&*()_-+=.?';
const VOWELS = 'aeiou';
const CONSONANTS = 'bcdfghjklmnpqrstvwxyz';

let BIP39_BY_LEN: Map<number, string[]> | null = null;
function wordsByLen(len: number): string[] {
  if (!BIP39_BY_LEN) {
    BIP39_BY_LEN = new Map();
    for (const w of BIP39_WORDS) {
      const arr = BIP39_BY_LEN.get(w.length) ?? [];
      arr.push(w);
      BIP39_BY_LEN.set(w.length, arr);
    }
  }
  return BIP39_BY_LEN.get(len) ?? [];
}

/** A pronounceable pseudo-word of exactly `len` lowercase letters. English is
 *  ~38% vowels; strict alternation over-produces them (~50%) and becomes a
 *  vowel-rate tell, so we bias toward consonants and allow consonant clusters. */
function pseudoWord(len: number): string {
  let out = '';
  let prevVowel: boolean = false;
  for (let i = 0; i < len; i++) {
    // After a vowel, almost always a consonant; after a consonant, ~45% vowel.
    const useVowel: boolean = prevVowel ? randInt(100) < 12 : randInt(100) < 45;
    out += useVowel ? VOWELS[randInt(VOWELS.length)] : CONSONANTS[randInt(CONSONANTS.length)];
    prevVowel = useVowel;
  }
  return out;
}

/** Lowercase letters of exactly `len`, word-shaped: real word if one exists,
 *  else concatenated words truncated to length, else a pseudo-word. */
function lettersOfLen(len: number): string {
  if (len <= 0) return '';
  if (len <= 2) return pseudoWord(len);
  const exact = wordsByLen(len);
  if (exact.length > 0) return exact[randInt(exact.length)]!;
  // Build from whole words then truncate to length (keeps English n-gram feel).
  let built = '';
  let guard = 0;
  while (built.length < len && guard++ < 12) built += BIP39_WORDS[randInt(BIP39_WORDS.length)]!;
  if (built.length >= len) return built.slice(0, len);
  return pseudoWord(len);
}

/** Letters of exactly `len` whose vowel count approximates `template`'s, so the
 *  decoy's vowel rate tracks the real run instead of English average (a residual
 *  freeform distinguisher). Starts from a word-shaped base, then swaps a bounded
 *  number of positions vowel<->consonant to hit the target vowel count. */
function lettersMatchingVowelRate(len: number, template: string): string {
  const base = Array.from(lettersOfLen(len));
  const isV = (c: string) => VOWELS.includes(c.toLowerCase());
  const tmplVowels = Array.from(template).filter((c) => /[A-Za-z]/.test(c) && isV(c)).length;
  let curVowels = base.filter(isV).length;
  let guard = 0;
  while (curVowels < tmplVowels && guard++ < len * 2) {
    const idx = base.findIndex((c) => !isV(c));
    if (idx < 0) break;
    base[idx] = VOWELS[randInt(VOWELS.length)]!;
    curVowels++;
  }
  guard = 0;
  while (curVowels > tmplVowels && guard++ < len * 2) {
    const idx = base.findIndex((c) => isV(c));
    if (idx < 0) break;
    base[idx] = CONSONANTS[randInt(CONSONANTS.length)]!;
    curVowels--;
  }
  return base.join('');
}

/** Apply the per-character case pattern of `template` onto `letters`. */
function applyCasePattern(letters: string, template: string): string {
  let out = '';
  for (let i = 0; i < letters.length; i++) {
    const t = template[i] ?? template[template.length - 1] ?? 'a';
    out += t >= 'A' && t <= 'Z' ? letters[i]!.toUpperCase() : letters[i]!.toLowerCase();
  }
  return out;
}

function classOf(c: string): 'alpha' | 'digit' | 'space' | 'symbol' {
  if (/[A-Za-z]/.test(c)) return 'alpha';
  if (/[0-9]/.test(c)) return 'digit';
  if (c === ' ') return 'space';
  return 'symbol';
}

/**
 * Human-like freeform/generic decoy. Same length as `real`; same character-
 * class layout, case pattern, and word structure, so shape statistics match.
 * Content is independent of `real` (no information leak).
 */
function randomHumanLike(real: string): string {
  if (real.length === 0) return '';
  let out = '';
  let i = 0;
  while (i < real.length) {
    const cls = classOf(real[i]!);
    let j = i;
    while (j < real.length && classOf(real[j]!) === cls) j++;
    const runLen = j - i;
    const runTemplate = real.slice(i, j);
    if (cls === 'alpha') {
      // Match the real run's vowel rate as well as its length/case, so vowel%
      // (a residual freeform tell) tracks the real value rather than English
      // average. lettersOfLen draws real words / pseudo-words; we then nudge
      // the vowel count toward the template's by swapping a few positions.
      out += applyCasePattern(lettersMatchingVowelRate(runLen, runTemplate), runTemplate);
    } else if (cls === 'digit') {
      out += digits(runLen);
    } else if (cls === 'space') {
      out += ' '.repeat(runLen);
    } else {
      out += chars(SYMBOL_POOL, runLen);
    }
    i = j;
  }
  // Length is preserved exactly by construction, but guard the invariant.
  return out.length <= real.length ? out : out.slice(0, real.length);
}

/**
 * Generate a CHECKSUM-VALID BIP-39 mnemonic of `count` words.
 *
 * Critical for deniability: a real seed phrase has a valid BIP-39 checksum, so a
 * decoy with an invalid checksum would be a real-vs-decoy distinguisher. We pick
 * random entropy of the right length for the word count and derive the mnemonic
 * (entropy + SHA-256 checksum bits) so the result passes bip39ChecksumPasses.
 *
 * The `budget` guards the length invariant: BIP-39 mnemonics for a given word
 * count vary in character length because words differ in length. We regenerate
 * (with fresh entropy) until the result fits the real value's character budget.
 * Average BIP-39 word is ~6 chars, and a real phrase of the same word count has
 * the same distribution, so this converges quickly.
 */
function randomWords(count: number, budget: number): string {
  if (![12, 15, 18, 21, 24].includes(count)) {
    // Non-standard word count cannot carry a valid BIP-39 checksum; fall back to
    // a shape-only phrase within budget (the validator returns false for these,
    // but classifier only treats standard counts as bip39 anyway).
    const maxWordLen = Math.floor((budget - Math.max(0, count - 1)) / Math.max(1, count));
    const pool = BIP39_WORDS.filter((w) => w.length <= maxWordLen);
    if (pool.length === 0) throw new Error('generated decoy exceeds real value length');
    const words: string[] = [];
    for (let i = 0; i < count; i++) words.push(pool[randInt(pool.length)]!);
    return words.join(' ');
  }
  const entBytes = (count * 11 - (count * 11) / 33) / 8; // ENT bits / 8
  // The decoy must fit `budget` (== the real phrase's char length). Naive
  // `<= budget` rejection biases decoys SHORTER than the real value (the real
  // is an unconditioned draw; the decoy is conditioned on length <= that draw),
  // which a length/transition-rate classifier exploits. Instead, prefer a
  // phrase whose length EXACTLY equals the budget so the decoy length
  // distribution matches the real distribution (and transrate, dominated by the
  // fixed word-count spaces over a matched length, matches too).
  let bestFit = '';
  for (let attempt = 0; attempt < 256; attempt++) {
    const entropy = sourceBytes(entBytes);
    const phrase = bip39FromEntropy(entropy, count as 12 | 15 | 18 | 21 | 24);
    if (phrase.length === budget) return phrase;
    if (phrase.length <= budget && phrase.length > bestFit.length) bestFit = phrase;
  }
  if (bestFit) return bestFit;
  throw new Error('generated decoy exceeds real value length');
}

function b64urlNoPad(buf: Uint8Array | string): string {
  const b = typeof buf === 'string' ? Buffer.from(buf, 'utf8') : Buffer.from(buf);
  return b.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * JWT decoy whose REAL structure survives the obvious oracle: a real JWT's
 * header AND payload base64url-decode to valid JSON. The old generator filled
 * all three segments with random base64url, so `JSON.parse(atob(payload))`
 * threw on the decoy and parsed on the real value: a one-line distinguisher
 * (red-team AUC 1.000). We emit a real JSON header (alg/typ) and a real JSON
 * claims payload (sub/iat/exp/...), padding the payload's string fields so the
 * encoded segment lengths track the real token's segment lengths without
 * exceeding the overall budget. The signature stays opaque base64url (real
 * signatures are opaque bytes).
 */
function randomJwt(real: string): string {
  const segs = real.split('.');
  const targetH = segs[0]?.length ?? 30;
  const targetP = segs[1]?.length ?? Math.floor(real.length / 2);
  const targetS = segs[2]?.length ?? 43;

  // alg distribution skewed to real-world frequency: HS256 dominates, then
  // RS256, with the rest rare. A flat random pick over algs is itself a tell
  // (real corpora are ~HS256-heavy).
  const algRoll = randInt(100);
  const alg = algRoll < 62 ? 'HS256' : algRoll < 88 ? 'RS256' : algRoll < 94 ? 'ES256' : algRoll < 98 ? 'HS512' : 'RS512';
  // Decode the real header to mirror its field set (typ present? kid present?).
  // Real short tokens often omit typ; matching that keeps short-token decoys
  // within budget AND structurally faithful.
  let realTyp = true;
  try {
    const rh = Buffer.from((segs[0] ?? '').replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    const parsed = JSON.parse(rh);
    realTyp = Object.prototype.hasOwnProperty.call(parsed, 'typ');
  } catch { /* keep default */ }
  const header: Record<string, unknown> = realTyp ? { alg, typ: 'JWT' } : { alg };
  // RS/ES tokens commonly carry a kid; HS tokens usually don't.
  if ((alg[0] === 'R' || alg[0] === 'E') && randInt(10) < 7) header['kid'] = chars('0123456789abcdef', 8 + randInt(25));
  let headerSeg = b64urlNoPad(JSON.stringify(header));
  // If even the chosen header overshoots the real header segment badly, fall
  // back to the most minimal valid header so short tokens still fit.
  if (headerSeg.length > targetH && targetH >= 10) {
    headerSeg = b64urlNoPad(JSON.stringify({ alg }));
  }

  const now = 1700000000 + randInt(90000000);
  // Build claims from the same shape real tokens use: sub + iat + exp are near-
  // universal; iss/aud/nbf/jti appear sometimes. Values are realistic (numeric
  // timestamps, opaque sub) and carry no tells like pseudo-word issuers.
  const claims: Record<string, unknown> = { sub: chars(ALNUM, 8 + randInt(10)) };
  if (randInt(10) < 6) {
    const issuers = ['https://accounts.google.com', 'https://login.microsoftonline.com', 'https://auth0.com', 'https://api.stripe.com', 'https://github.com'];
    claims['iss'] = issuers[randInt(issuers.length)];
  }
  if (randInt(10) < 4) claims['aud'] = chars(ALNUM, 6 + randInt(12));
  claims['iat'] = now;
  if (randInt(10) < 3) claims['nbf'] = now;
  claims['exp'] = now + 3600 + randInt(86400);
  let payloadSeg = b64urlNoPad(JSON.stringify(claims));
  // Grow the payload toward the real segment length with realistic claims, so
  // the decoded JSON stays valid and the segment length is plausible.
  if (payloadSeg.length < targetP) {
    const need = Math.floor((targetP - payloadSeg.length) * 0.74); // base64 expands ~4/3
    if (need > 0) {
      if (!claims['jti']) claims['jti'] = chars(ALNUM, Math.min(Math.max(8, need), 36));
      payloadSeg = b64urlNoPad(JSON.stringify(claims));
    }
    if (payloadSeg.length < targetP) {
      const more = Math.floor((targetP - payloadSeg.length) * 0.74);
      // High-entropy filler claim (base64url-class) so the decoded payload's
      // byte entropy matches a real token's opaque claim values rather than
      // running low (a residual entropy distinguisher).
      if (more > 0) { claims['data'] = chars(BASE64URL, Math.min(more, 64)); payloadSeg = b64urlNoPad(JSON.stringify(claims)); }
    }
  }

  let sigSeg = segment(Math.max(1, targetS));

  let out = `${headerSeg}.${payloadSeg}.${sigSeg}`;
  // Enforce the byte budget. Trim the signature first (opaque), then payload
  // padding fields, never breaking JSON validity of header/payload.
  if (out.length > real.length) {
    const overflow = out.length - real.length;
    if (sigSeg.length - overflow >= 1) {
      sigSeg = sigSeg.slice(0, sigSeg.length - overflow);
      out = `${headerSeg}.${payloadSeg}.${sigSeg}`;
    }
  }
  if (out.length > real.length) {
    // Shrink the payload while keeping valid JSON. Real short JWTs carry minimal
    // claims, so try progressively smaller claim sets and a shrinking subject
    // until header + payload + 1-char sig fits the byte budget.
    const claimSets: Array<(subLen: number) => Record<string, unknown>> = [
      (s) => ({ sub: chars(ALNUM, s), iat: now, exp: now + 3600 }),
      (s) => ({ sub: chars(ALNUM, s), exp: now + 3600 }),
      (s) => ({ sub: chars(ALNUM, s) }),
    ];
    let fitted = false;
    for (const make of claimSets) {
      for (let subLen = (claims['sub'] as string).length; subLen >= 1 && !fitted; subLen--) {
        const ps = b64urlNoPad(JSON.stringify(make(subLen)));
        if (headerSeg.length + 1 + ps.length + 1 + 1 <= real.length) {
          payloadSeg = ps;
          const sigLen = Math.max(1, Math.min(targetS, real.length - headerSeg.length - payloadSeg.length - 2));
          sigSeg = segment(sigLen);
          out = `${headerSeg}.${payloadSeg}.${sigSeg}`;
          fitted = true;
        }
      }
      if (fitted) break;
    }
  }
  if (out.length > real.length) {
    // Last resort: the header alone may exceed budget only for absurdly short
    // inputs; chooseDecoy catches the throw and falls back to a generic decoy.
    throw new Error('generated decoy exceeds real value length');
  }
  return out;
}

function randomIban(real: string): string {
  const clean = real.replace(/\s+/g, '').toUpperCase();
  if (clean.length < 15) throw new Error('real IBAN value too short (minimum 15 chars)');
  const cc = /^[A-Z]{2}/.test(clean.slice(0, 2)) ? clean.slice(0, 2) : 'GB';
  // Generate a random BBAN then compute the ISO 7064 mod-97 check digits so the
  // decoy passes ibanMod97Valid (a real IBAN does; an invalid one would be a
  // distinguisher). BBAN length = total length - 2 (country) - 2 (check).
  const bban = chars(ALNUM_UPPER, clean.length - 4);
  const check = ibanCheckDigits(cc, bban);
  return `${cc}${check}${bban}`;
}

function randomCreditCard(real: string): string {
  // Build a Luhn-valid number with the same digit/separator layout as the real
  // value. A real card passes Luhn, so a decoy that failed it would let an
  // adversary pick the real one. We randomise every digit except the final
  // check digit, which we compute so the whole number satisfies Luhn.
  const layout = Array.from(real); // preserve separators (spaces/dashes) in place
  const digitPositions: number[] = [];
  for (let i = 0; i < layout.length; i++) {
    if (/\d/.test(layout[i]!)) digitPositions.push(i);
  }
  if (digitPositions.length < 2) {
    // Too few digits to carry a check digit; fall back to per-digit randomisation.
    return real.replace(/\d/g, () => String(randInt(10)));
  }
  // Randomise all but the last digit position.
  for (let k = 0; k < digitPositions.length - 1; k++) {
    layout[digitPositions[k]!] = String(randInt(10));
  }
  const bodyDigits = digitPositions.slice(0, -1).map((p) => layout[p]!).join('');
  const checkDigit = luhnCheckDigit(bodyDigits);
  layout[digitPositions[digitPositions.length - 1]!] = String(checkDigit);
  return layout.join('');
}

function randomPrivateKeyPem(real: string): string {
  const begin = '-----BEGIN PRIVATE KEY-----\n';
  const end = '\n-----END PRIVATE KEY-----';
  const budget = real.length - begin.length - end.length;
  if (budget < 1) throw new Error('generated decoy exceeds real value length');
  return `${begin}${chars(BASE64URL, budget)}${end}`;
}

function randomSlug(): string {
  const len = 8 + randInt(12);
  let out = ALPHA_LOWER[randInt(ALPHA_LOWER.length)]!;
  for (let i = 1; i < len; i++) {
    out += randInt(10) < 2 ? '-' : ALNUM_LOWER[randInt(ALNUM_LOWER.length)]!;
  }
  if (out.endsWith('-')) out = out.slice(0, -1) + ALNUM_LOWER[randInt(ALNUM_LOWER.length)]!;
  return out;
}

function pemBodyLines(lineCount: number): string {
  const lines: string[] = [];
  for (let i = 0; i < lineCount; i++) lines.push(chars(BASE64, 64));
  return lines.join('\n');
}

function randomGcpServiceAccountKey(real: string): string {
  let projectId = randomSlug();
  let accountName = `svc-${randomSlug()}`.slice(0, 28).replace(/-$/, 'a');
  try {
    const parsed = JSON.parse(real) as Record<string, unknown>;
    if (typeof parsed['project_id'] === 'string' && /^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(parsed['project_id'])) {
      projectId = parsed['project_id'];
    }
    if (typeof parsed['client_email'] === 'string') {
      const local = parsed['client_email'].split('@')[0];
      if (local && /^[a-z][a-z0-9-]{2,28}[a-z0-9]$/.test(local)) accountName = local;
    }
  } catch { /* keep generated identifiers */ }

  const obj = {
    type: 'service_account',
    project_id: projectId,
    private_key_id: chars(HEX, 40),
    private_key: `-----BEGIN PRIVATE KEY-----\n${pemBodyLines(10)}\n-----END PRIVATE KEY-----\n`,
    client_email: `${accountName}@${projectId}.iam.gserviceaccount.com`,
    client_id: `${1 + randInt(9)}${digits(20)}`,
    auth_uri: 'https://accounts.google.com/o/oauth2/auth',
    token_uri: 'https://oauth2.googleapis.com/token',
    auth_provider_x509_cert_url: 'https://www.googleapis.com/oauth2/v1/certs',
    client_x509_cert_url: `https://www.googleapis.com/robot/v1/metadata/x509/${accountName}%40${projectId}.iam.gserviceaccount.com`,
    universe_domain: 'googleapis.com',
  };
  return JSON.stringify(obj, null, 2);
}

const URI_HOST_LABELS = ['db', 'pg', 'mongo', 'cluster0', 'cluster1', 'main', 'prod', 'master', 'primary', 'reader', 'shard0', 'rds', 'atlas'];
const URI_DOMAINS = ['amazonaws.com', 'mongodb.net', 'herokuapp.com', 'azure.com', 'gcp.internal', 'render.com', 'supabase.co', 'compute.internal', 'rds.amazonaws.com'];
const URI_DBNAMES = ['app', 'prod', 'main', 'users', 'data', 'core', 'api', 'service', 'production', 'analytics', 'auth'];

/**
 * DB-connection-URI decoy that looks like a real connection string. The old
 * generator hardcoded `<8char>.example.test` (an RFC reserved test TLD no real
 * DB ever uses) plus fixed `u`/`p` credential prefixes and rigid segment
 * lengths: a structural fingerprint giving red-team AUC 1.000. We now build a
 * realistic host (real-looking subdomain + public cloud domain + port),
 * word-shaped username, mixed-charset password, and a real db-name path, with
 * lengths profiled from the real value, capped to its byte budget.
 */
function randomUri(real: string, fallbackScheme: string): string {
  const match = real.match(/^([a-z][a-z0-9+.-]*:\/\/)(.*)$/i);
  const scheme = match?.[1] ?? fallbackScheme;
  const rest = match?.[2] ?? '';
  // mongodb+srv:// (and any +srv scheme) resolves the port via DNS SRV records,
  // so a literal :port in an SRV URI is invalid and a real DB never has one.
  // Appending one is a format tell for that decoy sub-type (GPT-5.5 audit
  // 2026-06-07 P3). Suppress the port entirely for SRV schemes.
  const isSrvScheme = /\+srv:/i.test(scheme);

  // Profile the real credential/host/path lengths where present.
  const credMatch = rest.match(/^([^:@/]+):([^@/]+)@/);
  const realUserLen = credMatch ? credMatch[1]!.length : 8;
  const realPassLen = credMatch ? credMatch[2]!.length : 12;

  const buildHost = () => {
    const sub = URI_HOST_LABELS[randInt(URI_HOST_LABELS.length)]!;
    const sub2 = randInt(2) === 0 ? `-${chars('abcdefghijklmnopqrstuvwxyz0123456789', 4 + randInt(6))}` : '';
    const dom = URI_DOMAINS[randInt(URI_DOMAINS.length)]!;
    return `${sub}${sub2}.${dom}`;
  };

  const buildUser = (len: number): string => {
    // Real DB usernames are a mix of common service names and opaque tokens.
    const roll = randInt(10);
    if (roll < 5) {
      const common = ['postgres', 'admin', 'root', 'app', 'app_user', 'dbuser', 'service', 'readonly', 'master', 'mongo'];
      const pick = common[randInt(common.length)]!;
      if (pick.length <= len) return pick;
    }
    // opaque token: mixed alnum like a real generated credential
    return chars(ALNUM, Math.max(3, len));
  };

  const buildOnce = (withCreds: boolean, withPath: boolean, port: boolean): string => {
    const host = buildHost();
    const user = buildUser(Math.max(4, Math.min(realUserLen, 16)));
    const pass = chars(ALNUM, Math.max(6, Math.min(realPassLen, 24)));
    const portStr = (port && !isSrvScheme) ? `:${[5432, 27017, 3306, 6379, 5433][randInt(5)]}` : '';
    const path = withPath ? `/${URI_DBNAMES[randInt(URI_DBNAMES.length)]}` : '';
    const creds = withCreds ? `${user}:${pass}@` : '';
    return `${scheme}${creds}${host}${portStr}${path}`;
  };

  // Try richest form first, then progressively simpler forms to fit the budget.
  // Within each form, keep the LONGEST candidate that fits (real connection
  // strings are credential+host+port+path heavy; running short on length is
  // itself a distinguishing feature).
  const forms: Array<() => string> = [
    () => buildOnce(true, true, true),
    () => buildOnce(true, true, false),
    () => buildOnce(true, false, true),
    () => buildOnce(true, false, false),
    () => buildOnce(false, true, false),
    () => buildOnce(false, false, false),
  ];
  for (const form of forms) {
    let best = '';
    for (let attempt = 0; attempt < 16; attempt++) {
      const out = form();
      if (out.length <= real.length && out.length > best.length) best = out;
    }
    if (best) return best;
  }
  // Minimal fallback: scheme + short real-looking host.
  const minimal = `${scheme}${URI_HOST_LABELS[randInt(URI_HOST_LABELS.length)]}.${URI_DOMAINS[randInt(URI_DOMAINS.length)]}`;
  if (minimal.length <= real.length) return minimal;
  throw new Error('generated decoy exceeds real value length');
}

function randomBitcoinWif(realLen: number): string {
  if (realLen < 51) throw new Error('generated decoy exceeds real value length');
  // A real WIF key is Base58Check(0x80 + 32-byte key [+ 0x01 compressed]). A
  // decoy that fails the Base58Check checksum would be distinguishable, so we
  // build a proper Base58Check string. Uncompressed (0x80 + 32B) encodes to 51
  // chars and starts with '5'; compressed (0x80 + 32B + 0x01) encodes to 52
  // chars and starts with K or L. Pick the form that fits the real length.
  const compressed = realLen >= 52;
  const payload = new Uint8Array(compressed ? 34 : 33);
  payload[0] = 0x80;
  payload.set(sourceBytes(32), 1);
  if (compressed) payload[33] = 0x01;
  const wif = base58CheckEncode(payload);
  if (wif.length > realLen) {
    // Base58 length can vary by ±1 depending on leading bytes; regenerate a
    // handful of times to land within budget before giving up.
    for (let i = 0; i < 16; i++) {
      payload.set(sourceBytes(32), 1);
      const retry = base58CheckEncode(payload);
      if (retry.length <= realLen) return retry;
    }
    throw new Error('generated decoy exceeds real value length');
  }
  return wif;
}

export function generateLocalDecoy(realValue: string, type: DecoyType): string {
  const realLen = realValue.length;
  switch (type) {
    case 'stripe-test-key':
      return token('sk_test_', realLen, ALNUM, 24);
    case 'stripe-live-key':
      return token('sk_live_', realLen, ALNUM, 24);
    case 'github-pat-classic':
      return token('ghp_', realLen, ALNUM, 36, 36);
    case 'github-pat-fine':
      return token('github_pat_', realLen, `${ALNUM}_`, 60);
    case 'openai-key':
      return token(realValue.startsWith('sk-proj-') ? 'sk-proj-' : 'sk-', realLen, BASE64URL, 40);
    case 'anthropic-key':
      return token(realValue.startsWith('sk-ant-api03-') ? 'sk-ant-api03-' : 'sk-ant-', realLen, BASE64URL, 80);
    case 'resend-key':
      return token('re_', realLen, `${ALNUM}_`, 20);
    case 'aws-access-key':
      return (realValue.startsWith('ASIA') ? 'ASIA' : 'AKIA') + chars(ALNUM_UPPER, boundedLen(realLen, 4, 16, 16));
    case 'bip39-phrase':
      return randomWords(realValue.trim().split(/\s+/).filter(Boolean).length, realLen);
    case 'jwt-token':
      return randomJwt(realValue);
    case 'iban':
      return randomIban(realValue);
    case 'credit-card':
      return randomCreditCard(realValue);
    case 'private-key-pem':
      return randomPrivateKeyPem(realValue);
    case 'postgres-uri':
      return randomUri(realValue, 'postgres://');
    case 'mongodb-uri':
      return randomUri(realValue, 'mongodb://');
    case 'slack-bot-token':
      return `xoxb-${digits(11)}-${digits(11)}-${chars(ALNUM, boundedLen(realLen, 'xoxb-'.length + 11 + 1 + 11 + 1, 24))}`;
    case 'slack-user-token':
      return `xoxp-${digits(11)}-${digits(11)}-${digits(11)}-${chars(ALNUM, boundedLen(realLen, 'xoxp-'.length + 11 + 1 + 11 + 1 + 11 + 1, 24))}`;
    case 'discord-bot-token': {
      const lengths = splitLengths(realValue, 3);
      lengths[0] = Math.max(23, Math.min(28, lengths[0]!));
      lengths[1] = Math.max(6, Math.min(7, lengths[1]!));
      lengths[2] = Math.max(27, Math.min(38, realLen - lengths[0]! - lengths[1]! - 2));
      const out = `${segment(lengths[0]!)}.${segment(lengths[1]!)}.${segment(lengths[2]!)}`;
      if (out.length > realLen) throw new Error('generated decoy exceeds real value length');
      return out;
    }
    case 'digitalocean-pat':
      return token('dop_v1_', realLen, HEX, 64, 64);
    case 'gcp-api-key':
      return token('AIza', realLen, BASE64URL, 35, 35);
    case 'gcp-service-account-key':
      return randomGcpServiceAccountKey(realValue);
    case 'azure-client-secret': {
      if (realLen < 34) throw new Error('generated decoy exceeds real value length');
      const len = Math.min(44, realLen);
      return `${chars(ALNUM, 4)}~${chars(`${ALNUM}_.-`, len - 5)}`;
    }
    case 'azure-storage-key':
      if (realLen < 88) throw new Error('generated decoy exceeds real value length');
      return `${chars(BASE64, 86)}==`;
    case 'twilio-auth-token':
      return token('SK', realLen, HEX, 32, 32);
    case 'sendgrid-key':
      if (realLen < 69) throw new Error('generated decoy exceeds real value length');
      return `SG.${segment(22)}.${segment(43)}`;
    case 'huggingface-token':
      return token('hf_', realLen, ALNUM, Math.min(30, Math.max(1, realLen - 3)));
    case 'npm-publish-token':
      return token('npm_', realLen, ALNUM, 36, 36);
    case 'pypi-token':
      return token('pypi-AgE', realLen, BASE64URL, 80);
    case 'gitlab-pat':
      return token('glpat-', realLen, BASE64URL, 20, 20);
    case 'mailgun-api-key':
      return token('key-', realLen, HEX, 32, 32);
    case 'linear-api-key':
      return token('lin_api_', realLen, ALNUM, 40, 40);
    case 'notion-token':
      return token(realValue.startsWith('ntn_') ? 'ntn_' : 'secret_', realLen, ALNUM, Math.min(43, Math.max(1, realLen - (realValue.startsWith('ntn_') ? 4 : 7))));
    case 'shopify-token':
      return token('shpat_', realLen, HEX, 32, 32);
    case 'square-token':
      return realValue.startsWith('sq0atp-')
        ? token('sq0atp-', realLen, BASE64URL, 22, 22)
        : token('EAAA', realLen, BASE64URL, 60);
    case 'cloudflare-api-token':
      return chars(BASE64URL, realLen);
    case 'ethereum-private-key':
      return realValue.startsWith('0x') ? token('0x', realLen, HEX, 64, 64) : chars(HEX, boundedLen(realLen, 0, 64, 64));
    case 'bitcoin-wif':
      return randomBitcoinWif(realLen);
    case 'solana-private-key': {
      if (realLen < 87) throw new Error('generated decoy exceeds real value length');
      // A real Solana secret key is 64 raw bytes Base58-encoded (87-88 chars).
      // Encode actual random 64-byte material so the decoy passes solanaKeyValid
      // (decodes to exactly 64 bytes) instead of being an arbitrary Base58 run.
      for (let i = 0; i < 16; i++) {
        const enc = base58Encode(sourceBytes(64));
        if (enc.length >= 87 && enc.length <= realLen) return enc;
      }
      throw new Error('generated decoy exceeds real value length');
    }
    case 'uk-nhs-number':
      return digits(realValue.replace(/\s+/g, '').length);
    case 'us-ssn':
      return `${100 + randInt(799)}-${10 + randInt(90)}-${1000 + randInt(9000)}`;
    case 'uk-ni-number':
      return `${NI_FIRST[randInt(NI_FIRST.length)]}${NI_SECOND[randInt(NI_SECOND.length)]}${digits(6)}${'ABCD'[randInt(4)]}`;
    case 'phone-e164': {
      const len = Math.max(8, Math.min(15, realValue.replace(/^\+/, '').length));
      const out = `+${1 + randInt(9)}${digits(len - 1)}`;
      if (out.length > realLen) throw new Error('generated decoy exceeds real value length');
      return out;
    }
    case 'generic':
    case 'freeform-secret':
      return randomHumanLike(realValue);
  }
}

export interface GenerateDecoyWithHashOptions {
  /** Length hint for shape generation. If omitted, uses sensible default per type. */
  realLengthHint?: number;
}

export interface DecoyWithHash {
  /** Generated decoy value (matches the shape of `type`). */
  value: string;
  /** SHA-256 of `value` as 64-char lowercase hex. Server-format. */
  sha256: string;
}

/**
 * Generate a shape-matching decoy for a known field type AND its SHA-256 hash,
 * ready to register as a tripwire via POST /v1/decoy-tripwires/bulk.
 */
export function generateDecoyWithHash(type: DecoyType, opts: GenerateDecoyWithHashOptions = {}): DecoyWithHash {
  const lenHint = opts.realLengthHint ?? defaultLengthForType(type);
  const dummyReal = dummyRealForType(type, lenHint);
  const value = generateLocalDecoy(dummyReal, type);
  const sha256 = createHash('sha256').update(value, 'utf8').digest('hex');
  return { value, sha256 };
}

function dummyRealForType(type: DecoyType, lenHint: number): string {
  switch (type) {
    case 'bip39-phrase':
      return 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    case 'jwt-token': {
      const bodyLen = Math.max(1, lenHint - 'e30..'.length);
      const first = Math.max(1, Math.floor(bodyLen / 2));
      return `e30.${'x'.repeat(first)}.${'x'.repeat(bodyLen - first)}`;
    }
    case 'credit-card':
      return '4'.repeat(lenHint);
    case 'iban':
      return `GB${'0'.repeat(Math.max(0, lenHint - 2))}`;
    case 'postgres-uri':
      return `postgres://${'x'.repeat(Math.max(0, lenHint - 'postgres://'.length))}`;
    case 'mongodb-uri':
      return `mongodb://${'x'.repeat(Math.max(0, lenHint - 'mongodb://'.length))}`;
    case 'phone-e164':
      return `+${'1'.repeat(Math.max(0, lenHint - 1))}`;
    case 'gcp-service-account-key':
      return JSON.stringify({
        type: 'service_account',
        project_id: 'demo-prod-123',
        private_key_id: '0'.repeat(40),
        private_key: `-----BEGIN PRIVATE KEY-----\n${'A'.repeat(640)}\n-----END PRIVATE KEY-----\n`,
        client_email: 'svc-demo@demo-prod-123.iam.gserviceaccount.com',
        client_id: '1'.repeat(21),
      });
    default:
      return 'x'.repeat(lenHint);
  }
}

function defaultLengthForType(type: DecoyType): number {
  switch (type) {
    case 'stripe-test-key':
      return 32;
    case 'stripe-live-key':
      return 107;
    case 'github-pat-classic':
      return 40;
    case 'github-pat-fine':
      return 93;
    case 'openai-key':
      return 51;
    case 'anthropic-key':
      return 108;
    case 'resend-key':
      return 36;
    case 'aws-access-key':
      return 20;
    case 'bip39-phrase':
      return 200;
    case 'jwt-token':
      return 300;
    case 'iban':
      return 22;
    case 'credit-card':
      return 16;
    case 'private-key-pem':
      return 1700;
    case 'postgres-uri':
      return 80;
    case 'mongodb-uri':
      return 90;
    case 'slack-bot-token':
      return 57;
    case 'slack-user-token':
      return 65;
    case 'discord-bot-token':
      return 72;
    case 'digitalocean-pat':
      return 71;
    case 'gcp-api-key':
      return 39;
    case 'gcp-service-account-key':
      return 1600;
    case 'azure-client-secret':
      return 40;
    case 'azure-storage-key':
      return 88;
    case 'twilio-auth-token':
      return 34;
    case 'sendgrid-key':
      return 69;
    case 'huggingface-token':
      return 40;
    case 'npm-publish-token':
      return 40;
    case 'pypi-token':
      return 156;
    case 'gitlab-pat':
      return 26;
    case 'mailgun-api-key':
      return 36;
    case 'linear-api-key':
      return 51;
    case 'notion-token':
      return 50;
    case 'shopify-token':
      return 38;
    case 'square-token':
      return 64;
    case 'cloudflare-api-token':
      return 40;
    case 'ethereum-private-key':
      return 64;
    case 'bitcoin-wif':
      return 51;
    case 'solana-private-key':
      return 88;
    case 'uk-nhs-number':
      return 10;
    case 'us-ssn':
      return 11;
    case 'uk-ni-number':
      return 9;
    case 'phone-e164':
      return 15;
    case 'generic':
      return 32;
    case 'freeform-secret':
      return 32;
    default: {
      const _exhaustive: never = type;
      return 32;
    }
  }
}

// --- Honey Mode (per-type opt-in) ---

/**
 * Types that are NOT honey-eligible. Honey Mode requires that EVERY wrong
 * password yield a believable, type-correct fake across the whole keyspace.
 * For unstructured types we cannot guarantee that (an arbitrary blob has no
 * fixed shape to fake), so a wrong guess could decrypt to obviously-broken
 * output and collapse the deniability. These types are refused for Honey Mode;
 * the caller must keep them on the classic real+decoy+noise model.
 */
const HONEY_INELIGIBLE: ReadonlySet<DecoyType> = new Set<DecoyType>([
  // Unstructured fallback types: no type-correct fake possible.
  'generic',
  'freeform-secret',
  // Post-v1 honey types. Their record-decoy generators build JSON / multi-branch
  // connection strings whose byte output cannot (yet) be reproduced identically
  // across the Rust/Python/Go ports, so honey decrypt would diverge per language
  // (a real-vs-honey distinguisher). The HONEY-MODE-SPEC already marks these
  // "post-v1, stub to throw" until a byte-exact cross-SDK port lands. The classic
  // record-decoy path (non-honey) still uses the full generators for these types.
  'jwt-token',
  'postgres-uri',
  'mongodb-uri',
  // gcp-service-account-key is a 2-space-indented JSON blob with an embedded
  // PEM body and identifiers parsed out of the real value: the same
  // JSON/multi-branch class as the URI types above, byte-parity not provable
  // across the Rust/Python/Go ports. Honey-ineligible; the classic
  // record-decoy path still uses the full generator for it. The other three
  // cloud types (gcp-api-key, azure-client-secret, azure-storage-key) are
  // simple charset tokens and ARE honey-eligible.
  'gcp-service-account-key',
]);

/** True iff `type` can be safely honey-backed (structured, fully fakeable). */
export function isHoneyEligible(type: DecoyType): boolean {
  return !HONEY_INELIGIBLE.has(type);
}

/**
 * Run a synchronous decoy generation against a deterministic seeded source.
 * Restores the prior ambient source afterwards (re-entrant-safe within one
 * synchronous call stack). Internal helper for generateHoneyDecoy.
 */
function withSeededSource<T>(seed: Uint8Array, fn: () => T): T {
  const prev = AMBIENT_SOURCE;
  AMBIENT_SOURCE = new SeededByteSource(seed);
  try {
    return fn();
  } finally {
    AMBIENT_SOURCE = prev;
  }
}

export interface HoneyDecoyParams {
  /** Declared structured type of the protected secret (must be honey-eligible). */
  type: DecoyType;
  /** Wrong-password decrypt bytes (the would-be nonsense payload). Seeds the RNG. */
  decryptBytes: Uint8Array;
  /** Public salt from the ciphertext header. Part of the seed. */
  salt: Uint8Array;
  /**
   * Length hint for shape generation, matching the real value's length band so
   * the honey fake sits in the same size bucket (no length oracle). Defaults to
   * the type's canonical length.
   */
  realLengthHint?: number;
}

/**
 * Deterministically generate a plausible, type-correct honey fake for a WRONG
 * password. Same (type, decryptBytes, salt) always yields the same fake (stable
 * across retries — a changing fake is a honeypot tell). The seed is derived only
 * from the wrong-password decrypt bytes + public salt + type tag, so the fake is
 * independent of the real plaintext and leaks nothing about it.
 *
 * Throws if `type` is not honey-eligible (caller must check isHoneyEligible).
 *
 * NOTE: determinism here is the cross-SDK contract. The seed derivation
 * (deriveHoneySeed), the byte stream (SeededByteSource), the rejection rule
 * (sourcedInt), and each generator's draw order must be replicated byte-exactly
 * in the Rust / Python / Go ports, or decrypt diverges across languages.
 */
export function generateHoneyDecoy(params: HoneyDecoyParams): string {
  const { type, decryptBytes, salt } = params;
  if (!isHoneyEligible(type)) {
    throw new Error(`Honey Mode is not supported for unstructured type "${type}"`);
  }
  const lenHint = params.realLengthHint ?? defaultLengthForType(type);
  const dummyReal = dummyRealForType(type, lenHint);
  const seed = deriveHoneySeed(decryptBytes, salt, type);
  return withSeededSource(seed, () => generateLocalDecoy(dummyReal, type));
}
