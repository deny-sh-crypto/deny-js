/**
 * Stage-1 regex classifier for decoy types.
 *
 * Spec: ARCHITECTURE.md §4 (regex rules) + PROMPTING.md §3 (per-type detail).
 * Phase 1 ships regex only; LLM fallback (stage 2) lands in Phase 2.
 *
 * `classifyByRegex` returns the most specific type that matches the hint, or
 * null if no rule fires. `matchesShape` answers the reverse question for the
 * validator: does an arbitrary value look like the given type's shape?
 *
 * Note: the regex layer is INTENTIONALLY a shape check only. Deep validity
 * (Luhn, mod-97, BIP-39 checksum, JWT JSON header parse, NHS mod-11, Base58
 * checksum) lives in validators.ts so a single piece of value can be classified
 * by regex AND later validated for plausibility separately.
 *
 * Expanded from 15 to 37 named types on 2026-05-22.
 */

import type { DecoyType } from './types.js';
import { BIP39_WORDS } from './bip39-wordlist.js';

// ─── Regex rules (original 15) ────────────────────────────────────────────

// stripe-test-key: sk_test_ + 24+ alphanumeric
const RE_STRIPE_TEST = /^sk_test_[A-Za-z0-9]{24,}$/;
// stripe-live-key: sk_live_ + 24+ alphanumeric
const RE_STRIPE_LIVE = /^sk_live_[A-Za-z0-9]{24,}$/;
// github-pat-classic: ghp_ + exactly 36 alphanumeric
const RE_GITHUB_PAT_CLASSIC = /^ghp_[A-Za-z0-9]{36}$/;
// github-pat-fine: github_pat_ + 60+ chars from [A-Za-z0-9_]
const RE_GITHUB_PAT_FINE = /^github_pat_[A-Za-z0-9_]{60,}$/;
// anthropic-key: sk-ant- (optional api03-) + 80+ chars from [A-Za-z0-9_-]
const RE_ANTHROPIC = /^sk-ant-(api03-)?[A-Za-z0-9_-]{80,}$/;
// openai-key: sk- (optional proj-) + 40+ chars from [A-Za-z0-9_-]  (must NOT match anthropic)
const RE_OPENAI = /^sk-(proj-)?[A-Za-z0-9_-]{40,}$/;
// resend-key: re_ + 20+ chars from [A-Za-z0-9_]
const RE_RESEND = /^re_[A-Za-z0-9_]{20,}$/;
// aws-access-key: (AKIA|ASIA) + 16 uppercase alphanumeric, total 20 chars
const RE_AWS = /^(AKIA|ASIA)[A-Z0-9]{16}$/;
// iban: 2 letter country + 2 check digits + 11-30 alphanumeric (shape only)
const RE_IBAN = /^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$/;
// credit-card: 13-19 digits (optional spaces stripped before test)
const RE_CC = /^[0-9]{13,19}$/;
// private-key-pem: starts with -----BEGIN <TYPE> PRIVATE KEY-----
const RE_PRIV_PEM = /^-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/;
// postgres-uri: postgres:// or postgresql://
const RE_POSTGRES = /^postgres(ql)?:\/\//i;
// mongodb-uri: mongodb:// or mongodb+srv://
const RE_MONGO = /^mongodb(\+srv)?:\/\//i;
// jwt-token: 3 base64url segments separated by dots
const RE_JWT_SHAPE = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;

// ─── Regex rules (added 2026-05-22) ───────────────────────────────────────

// slack-bot-token: xoxb- followed by 3 dash-separated groups of digits/alphanumerics.
// Real shape: xoxb-<team-id 11-13d>-<bot-user-id 11-13d>-<secret 24+ chars>
// We require: xoxb- + 9+ digits + - + 9+ digits + - + 24+ [A-Za-z0-9]
const RE_SLACK_BOT = /^xoxb-\d{9,16}-\d{9,16}-[A-Za-z0-9]{24,}$/;
// slack-user-token: xoxp- + similar 3-group structure
const RE_SLACK_USER = /^xoxp-\d{9,16}-\d{9,16}-\d{9,16}-[A-Za-z0-9]{24,}$/;
// discord-bot-token: 3 segments base64url separated by dots, total 50+ chars (header.timestamp.hmac)
// e.g. MTIzNDU2Nzg5MDEyMzQ1Njc4OQ.GabcDe.fghIJklMnoPQrstUVwxYZ012345678aBcDe
const RE_DISCORD_BOT = /^[A-Za-z0-9_-]{23,28}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27,38}$/;
// digitalocean-pat: dop_v1_ + 64 hex chars
const RE_DO_PAT = /^dop_v1_[a-f0-9]{64}$/;
// twilio-auth-token: AC + 32 hex (account sid is AC + 32 hex; we treat as token)
//   real auth tokens are 32 hex alone, but the SK<32hex>:<32hex> API key pair is
//   the more distinctive Twilio shape. We use SK + 32 hex chars as the canonical
//   "Twilio key" form because it's unambiguous (AC<32hex> collides with generic).
const RE_TWILIO_AUTH = /^SK[a-f0-9]{32}$/;
// sendgrid-key: SG. + 22 chars + . + 43 chars (id . secret), no padding
const RE_SENDGRID = /^SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}$/;
// huggingface-token: hf_ + 30-40 chars from [A-Za-z0-9]
const RE_HF = /^hf_[A-Za-z0-9]{30,40}$/;
// npm-publish-token: npm_ + 36 chars from [A-Za-z0-9]
const RE_NPM = /^npm_[A-Za-z0-9]{36}$/;
// pypi-token: pypi-AgE + base64url body, 80+ chars total
const RE_PYPI = /^pypi-AgE[A-Za-z0-9_-]{80,}$/;
// gitlab-pat: glpat- + 20 chars from [A-Za-z0-9_-]
const RE_GITLAB_PAT = /^glpat-[A-Za-z0-9_-]{20}$/;
// mailgun-api-key: key- + 32 hex
const RE_MAILGUN = /^key-[a-f0-9]{32}$/;
// linear-api-key: lin_api_ + 40 chars from [A-Za-z0-9]
const RE_LINEAR = /^lin_api_[A-Za-z0-9]{40}$/;
// notion-token: secret_ or ntn_ + 43+ chars from [A-Za-z0-9]
const RE_NOTION = /^(secret_|ntn_)[A-Za-z0-9]{43,50}$/;
// shopify-token: shpat_ + 32 hex
const RE_SHOPIFY = /^shpat_[a-f0-9]{32}$/;
// square-token: sq0atp- or EAAA + 22+ chars (production: EAAA + base64url body)
const RE_SQUARE = /^(sq0atp-[A-Za-z0-9_-]{22}|EAAA[A-Za-z0-9_-]{60,})$/;
// cloudflare-api-token: 40 chars from [A-Za-z0-9_-] (raw token, distinguished by
// context not shape — too generic to classify by regex alone in absence of prefix.
// Newer Cloudflare tokens follow this shape; we accept it only via explicit_type.)
const RE_CLOUDFLARE = /^[A-Za-z0-9_-]{40}$/;

// ethereum-private-key: 0x + 64 hex chars (or 64 hex bare)
const RE_ETH = /^(0x)?[a-fA-F0-9]{64}$/;
// bitcoin-wif: starts with 5/K/L (mainnet), Base58 alphabet, 51-52 chars
//   5... = uncompressed (51 chars), K/L... = compressed (52 chars)
const RE_BTC_WIF = /^[5KL][1-9A-HJ-NP-Za-km-z]{50,51}$/;
// solana-private-key: 87-88 Base58 chars (64-byte secret key, Base58 encoded)
const RE_SOLANA = /^[1-9A-HJ-NP-Za-km-z]{87,88}$/;

// uk-nhs-number: 10 digits, no separators (or "NNN NNN NNNN" form normalised first)
const RE_UK_NHS = /^[0-9]{10}$/;
// us-ssn: NNN-NN-NNNN
const RE_US_SSN = /^[0-9]{3}-[0-9]{2}-[0-9]{4}$/;
// uk-ni-number: 2 letters + 6 digits + 1 letter (e.g. AB123456C)
//   First letter: any but D F I Q U V O. Second: any but D F I Q U V (also not O).
//   Final letter: A/B/C/D only. We use a permissive shape here; the validator
//   enforces the prefix exclusions.
const RE_UK_NI = /^[A-Z]{2}[0-9]{6}[A-D]$/;

// phone-e164: + then 8-15 digits (E.164 max length 15 including country code)
const RE_E164 = /^\+[1-9][0-9]{7,14}$/;

/** Try to decode a base64url segment back to a UTF-8 string. */
function base64urlDecode(seg: string): string | null {
  try {
    const padded = seg.replace(/-/g, '+').replace(/_/g, '/');
    const pad = padded.length % 4;
    const full = pad === 0 ? padded : padded + '='.repeat(4 - pad);
    return Buffer.from(full, 'base64').toString('utf8');
  } catch {
    return null;
  }
}

/** JWT structural check: 3 base64url segments AND header parses as JSON. */
function looksLikeJwt(value: string): boolean {
  if (!RE_JWT_SHAPE.test(value)) return false;
  const [h] = value.split('.');
  const decoded = base64urlDecode(h);
  if (decoded === null) return false;
  try {
    const obj = JSON.parse(decoded);
    return obj !== null && typeof obj === 'object';
  } catch {
    return false;
  }
}

/** Strip whitespace + lowercase. Used for BIP-39 phrase shape check. */
function normalisePhrase(s: string): string[] {
  return s.trim().split(/\s+/).map((w) => w.toLowerCase());
}

const BIP39_SET: Set<string> = new Set(BIP39_WORDS);

/**
 * BIP-39 shape check (not checksum): 12 / 15 / 18 / 21 / 24 lowercase tokens,
 * every token in the BIP-39 English wordlist. Checksum check lives in
 * validators.ts (`bip39ChecksumPasses`).
 */
function looksLikeBip39Phrase(value: string): boolean {
  const words = normalisePhrase(value);
  if (![12, 15, 18, 21, 24].includes(words.length)) return false;
  for (const w of words) {
    if (!BIP39_SET.has(w)) return false;
  }
  return true;
}

/**
 * Return the most specific DecoyType the hint matches, or null.
 * Order matters: more-specific prefixes (anthropic, openai-proj) are tested
 * before more-general ones (openai bare sk-).
 */
export function classifyByRegex(hint: string): DecoyType | null {
  const v = hint;

  // Multi-line / shape-anchored matches first
  if (RE_PRIV_PEM.test(v)) return 'private-key-pem';

  if (RE_STRIPE_TEST.test(v)) return 'stripe-test-key';
  if (RE_STRIPE_LIVE.test(v)) return 'stripe-live-key';

  if (RE_GITHUB_PAT_FINE.test(v)) return 'github-pat-fine';
  if (RE_GITHUB_PAT_CLASSIC.test(v)) return 'github-pat-classic';

  if (RE_ANTHROPIC.test(v)) return 'anthropic-key';
  if (RE_OPENAI.test(v)) return 'openai-key';

  if (RE_RESEND.test(v)) return 'resend-key';
  if (RE_AWS.test(v)) return 'aws-access-key';

  if (RE_POSTGRES.test(v)) return 'postgres-uri';
  if (RE_MONGO.test(v)) return 'mongodb-uri';

  // SaaS / API tokens (specific prefixes, tested before generic shapes)
  if (RE_SLACK_USER.test(v)) return 'slack-user-token';
  if (RE_SLACK_BOT.test(v)) return 'slack-bot-token';
  if (RE_DO_PAT.test(v)) return 'digitalocean-pat';
  if (RE_SENDGRID.test(v)) return 'sendgrid-key';
  if (RE_HF.test(v)) return 'huggingface-token';
  if (RE_NPM.test(v)) return 'npm-publish-token';
  if (RE_PYPI.test(v)) return 'pypi-token';
  if (RE_GITLAB_PAT.test(v)) return 'gitlab-pat';
  if (RE_MAILGUN.test(v)) return 'mailgun-api-key';
  if (RE_LINEAR.test(v)) return 'linear-api-key';
  if (RE_NOTION.test(v)) return 'notion-token';
  if (RE_SHOPIFY.test(v)) return 'shopify-token';
  if (RE_SQUARE.test(v)) return 'square-token';
  if (RE_TWILIO_AUTH.test(v)) return 'twilio-auth-token';

  // Multi-word checks
  if (looksLikeBip39Phrase(v)) return 'bip39-phrase';
  if (looksLikeJwt(v)) return 'jwt-token';

  // Discord shape (3 dotted segments without JSON header — overlap-guarded by
  // checking JWT first).
  if (RE_DISCORD_BOT.test(v)) return 'discord-bot-token';

  // Identity numbers (digit-only or digit+letter shapes)
  if (RE_US_SSN.test(v)) return 'us-ssn';
  if (RE_UK_NI.test(v)) return 'uk-ni-number';
  if (RE_E164.test(v)) return 'phone-e164';

  // Numeric-ish checks last (cheap but very generic shape)
  // Credit-card strings may include spaces; strip and test digits.
  const stripped = v.replace(/[\s-]/g, '');
  if (RE_CC.test(stripped)) return 'credit-card';
  if (RE_IBAN.test(v.replace(/\s+/g, ''))) return 'iban';

  // NHS comes after CC (CC takes precedence since most 10-digit strings are
  // ambiguous; NHS is only confidently classifiable via the validator's mod-11).
  // We only classify here if it's exactly 10 digits AND looks like NHS spacing.
  // Bare 10-digit hits fall through to generic so we don't false-positive on
  // phone-numbers-without-plus.

  // Hex-only shapes (crypto private keys) — tested late because they overlap
  // heavily with generic random strings. We require the 0x prefix for ETH to
  // disambiguate; bare 64-hex is too ambiguous (could be a hash) so we skip.
  if (/^0x[a-fA-F0-9]{64}$/.test(v)) return 'ethereum-private-key';
  if (RE_BTC_WIF.test(v)) return 'bitcoin-wif';
  // Solana shape requires 87-88 Base58 chars — distinctive enough.
  if (RE_SOLANA.test(v)) return 'solana-private-key';

  return null;
}

/**
 * Reverse direction of classifyByRegex: does `value` match the visible shape
 * required of `type`? Used by validators.ts and by tests.
 *
 * For composite checks (BIP-39, JWT) we only check shape, NOT checksum /
 * signature. Validators handle those.
 */
export function matchesShape(value: string, type: DecoyType): boolean {
  switch (type) {
    case 'stripe-test-key':
      return RE_STRIPE_TEST.test(value);
    case 'stripe-live-key':
      return RE_STRIPE_LIVE.test(value);
    case 'github-pat-classic':
      return RE_GITHUB_PAT_CLASSIC.test(value);
    case 'github-pat-fine':
      return RE_GITHUB_PAT_FINE.test(value);
    case 'openai-key':
      // openai shape but not anthropic shape (anthropic also starts with sk-)
      return RE_OPENAI.test(value) && !RE_ANTHROPIC.test(value);
    case 'anthropic-key':
      return RE_ANTHROPIC.test(value);
    case 'resend-key':
      return RE_RESEND.test(value);
    case 'aws-access-key':
      return RE_AWS.test(value);
    case 'bip39-phrase':
      return looksLikeBip39Phrase(value);
    case 'jwt-token':
      return looksLikeJwt(value);
    case 'iban':
      return RE_IBAN.test(value.replace(/\s+/g, ''));
    case 'credit-card':
      return RE_CC.test(value.replace(/[\s-]/g, ''));
    case 'private-key-pem':
      return RE_PRIV_PEM.test(value);
    case 'postgres-uri':
      return RE_POSTGRES.test(value);
    case 'mongodb-uri':
      return RE_MONGO.test(value);
    case 'slack-bot-token':
      return RE_SLACK_BOT.test(value);
    case 'slack-user-token':
      return RE_SLACK_USER.test(value);
    case 'discord-bot-token':
      return RE_DISCORD_BOT.test(value);
    case 'digitalocean-pat':
      return RE_DO_PAT.test(value);
    case 'twilio-auth-token':
      return RE_TWILIO_AUTH.test(value);
    case 'sendgrid-key':
      return RE_SENDGRID.test(value);
    case 'huggingface-token':
      return RE_HF.test(value);
    case 'npm-publish-token':
      return RE_NPM.test(value);
    case 'pypi-token':
      return RE_PYPI.test(value);
    case 'gitlab-pat':
      return RE_GITLAB_PAT.test(value);
    case 'mailgun-api-key':
      return RE_MAILGUN.test(value);
    case 'linear-api-key':
      return RE_LINEAR.test(value);
    case 'notion-token':
      return RE_NOTION.test(value);
    case 'shopify-token':
      return RE_SHOPIFY.test(value);
    case 'square-token':
      return RE_SQUARE.test(value);
    case 'cloudflare-api-token':
      return RE_CLOUDFLARE.test(value);
    case 'ethereum-private-key':
      return /^0x[a-fA-F0-9]{64}$/.test(value) || /^[a-fA-F0-9]{64}$/.test(value);
    case 'bitcoin-wif':
      return RE_BTC_WIF.test(value);
    case 'solana-private-key':
      return RE_SOLANA.test(value);
    case 'uk-nhs-number':
      return RE_UK_NHS.test(value.replace(/\s+/g, ''));
    case 'us-ssn':
      return RE_US_SSN.test(value);
    case 'uk-ni-number':
      return RE_UK_NI.test(value.replace(/\s+/g, ''));
    case 'phone-e164':
      return RE_E164.test(value);
    case 'generic':
    case 'freeform-secret':
      // No shape constraint; any non-empty string qualifies.
      return value.length > 0;
  }
}
