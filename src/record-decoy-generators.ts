import { randomBytes } from 'node:crypto';
import { BIP39_WORDS } from './decoy-engine/bip39-wordlist.js';
import type { DecoyType } from './decoy-engine/types.js';

const ALNUM = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const ALNUM_UPPER = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const BASE64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-';
const HEX = '0123456789abcdef';
const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const PRINTABLE = Array.from({ length: 95 }, (_, i) => String.fromCharCode(32 + i)).join('');
const NI_FIRST = 'ABCEGHJKLMNOPRSTWXYZ';
const NI_SECOND = 'ABCEGHJKLMNPRSTWXYZ';

function randInt(max: number): number {
  if (max <= 0) return 0;
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

function randomPrintableSameLength(real: string): string {
  return chars(PRINTABLE, real.length);
}

function randomWords(count: number, budget: number): string {
  const maxWordLen = Math.floor((budget - Math.max(0, count - 1)) / Math.max(1, count));
  const pool = BIP39_WORDS.filter((w) => w.length <= maxWordLen);
  if (pool.length === 0) throw new Error('generated decoy exceeds real value length');
  const words: string[] = [];
  for (let i = 0; i < count; i++) words.push(pool[randInt(pool.length)]!);
  return words.join(' ');
}

function randomJwt(real: string): string {
  const lengths = splitLengths(real, 3);
  const minHeader = 'e30';
  lengths[0] = Math.max(lengths[0]!, minHeader.length);
  const out = `${minHeader}${segment(lengths[0]! - minHeader.length)}.${segment(lengths[1]!)}.${segment(lengths[2]!)}`;
  if (out.length > real.length) throw new Error('generated decoy exceeds real value length');
  return out;
}

function randomIban(real: string): string {
  const clean = real.replace(/\s+/g, '').toUpperCase();
  if (clean.length < 15) throw new Error('real IBAN value too short (minimum 15 chars)');
  const cc = /^[A-Z]{2}/.test(clean.slice(0, 2)) ? clean.slice(0, 2) : 'GB';
  return `${cc}${digits(2)}${chars(ALNUM_UPPER, clean.length - 4)}`;
}

function randomCreditCard(real: string): string {
  let out = '';
  for (const ch of real) out += /\d/.test(ch) ? String(randInt(10)) : ch;
  return out;
}

function randomPrivateKeyPem(real: string): string {
  const begin = '-----BEGIN PRIVATE KEY-----\n';
  const end = '\n-----END PRIVATE KEY-----';
  const budget = real.length - begin.length - end.length;
  if (budget < 1) throw new Error('generated decoy exceeds real value length');
  return `${begin}${chars(BASE64URL, budget)}${end}`;
}

function randomUri(real: string, fallbackScheme: string): string {
  const match = real.match(/^([a-z][a-z0-9+.-]*:\/\/)(.*)$/i);
  const scheme = match?.[1] ?? fallbackScheme;
  const host = `${chars('abcdefghijklmnopqrstuvwxyz', 8)}.example.test`;
  const user = `u${chars(ALNUM, 5)}`;
  const pass = `p${chars(ALNUM, 8)}`;
  const path = `/${chars('abcdefghijklmnopqrstuvwxyz', 6)}`;
  let out = `${scheme}${user}:${pass}@${host}${path}`;
  if (out.length > real.length) out = `${scheme}${host}`;
  if (out.length > real.length) throw new Error('generated decoy exceeds real value length');
  return out;
}

function randomBitcoinWif(realLen: number): string {
  if (realLen < 51) throw new Error('generated decoy exceeds real value length');
  const prefix = realLen >= 52 ? (randInt(2) === 0 ? 'K' : 'L') : '5';
  return prefix + chars(BASE58, (prefix === '5' ? 51 : 52) - 1);
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
      return `xoxb-${digits(11)}-${digits(11)}-${chars(ALNUM, boundedLen(realLen, 6 + 11 + 1 + 11 + 1, 24))}`;
    case 'slack-user-token':
      return `xoxp-${digits(11)}-${digits(11)}-${digits(11)}-${chars(ALNUM, boundedLen(realLen, 6 + 11 + 1 + 11 + 1 + 11 + 1, 24))}`;
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
    case 'solana-private-key':
      if (realLen < 87) throw new Error('generated decoy exceeds real value length');
      return chars(BASE58, Math.min(88, realLen));
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
      return randomPrintableSameLength(realValue);
  }
}
