/**
 * Decoy Realism Engine - shared types.
 *
 * NOTE on validation: ARCHITECTURE.md §3 specs SuggestRequest as a "zod schema"
 * but `zod` is NOT present in package.json (verified Phase 1). To avoid adding
 * a dep in this phase we ship a hand-rolled parser with the same semantics
 * (`parseSuggestRequest` below). Phase 2 can swap to zod once Anthropic / OpenAI
 * SDK installs land (since they'll bring zod-like validators anyway).
 *
 * Type list grew from the original 17 (15 named + generic + freeform-secret) to
 * 40 on 2026-05-22 (37 named + generic + freeform-secret) ahead of the
 * walkthrough video. New types: 14 additional API tokens (slack-bot/user,
 * discord-bot, digitalocean-pat, twilio-auth, sendgrid, huggingface, npm-publish,
 * pypi, gitlab-pat, mailgun, linear, notion, shopify, square, cloudflare),
 * 3 crypto private keys (ethereum, bitcoin-wif, solana), 3 identity numbers
 * (uk-nhs, us-ssn, uk-ni), 1 phone (e164).
 */

export type DecoyType =
  // Original 15 named types
  | 'stripe-test-key'
  | 'stripe-live-key'
  | 'github-pat-classic'
  | 'github-pat-fine'
  | 'openai-key'
  | 'anthropic-key'
  | 'resend-key'
  | 'aws-access-key'
  | 'bip39-phrase'
  | 'jwt-token'
  | 'iban'
  | 'credit-card'
  | 'private-key-pem'
  | 'postgres-uri'
  | 'mongodb-uri'
  // Added 2026-05-22: API / SaaS tokens
  | 'slack-bot-token'
  | 'slack-user-token'
  | 'discord-bot-token'
  | 'digitalocean-pat'
  | 'twilio-auth-token'
  | 'sendgrid-key'
  | 'huggingface-token'
  | 'npm-publish-token'
  | 'pypi-token'
  | 'gitlab-pat'
  | 'mailgun-api-key'
  | 'linear-api-key'
  | 'notion-token'
  | 'shopify-token'
  | 'square-token'
  | 'cloudflare-api-token'
  // Added 2026-05-22: crypto private keys
  | 'ethereum-private-key'
  | 'bitcoin-wif'
  | 'solana-private-key'
  // Added 2026-05-22: identity numbers
  | 'uk-nhs-number'
  | 'us-ssn'
  | 'uk-ni-number'
  // Added 2026-05-22: phone
  | 'phone-e164'
  // Fallbacks
  | 'generic'
  | 'freeform-secret';

/** Runtime enumeration of the 40 known types. */
export const KNOWN_TYPES: readonly DecoyType[] = Object.freeze([
  'stripe-test-key',
  'stripe-live-key',
  'github-pat-classic',
  'github-pat-fine',
  'openai-key',
  'anthropic-key',
  'resend-key',
  'aws-access-key',
  'bip39-phrase',
  'jwt-token',
  'iban',
  'credit-card',
  'private-key-pem',
  'postgres-uri',
  'mongodb-uri',
  'slack-bot-token',
  'slack-user-token',
  'discord-bot-token',
  'digitalocean-pat',
  'twilio-auth-token',
  'sendgrid-key',
  'huggingface-token',
  'npm-publish-token',
  'pypi-token',
  'gitlab-pat',
  'mailgun-api-key',
  'linear-api-key',
  'notion-token',
  'shopify-token',
  'square-token',
  'cloudflare-api-token',
  'ethereum-private-key',
  'bitcoin-wif',
  'solana-private-key',
  'uk-nhs-number',
  'us-ssn',
  'uk-ni-number',
  'phone-e164',
  'generic',
  'freeform-secret',
]);

export interface DecoyCandidate {
  decoy_text: string;
  plausibility_score: number;
  source: 'llm' | 'template' | 'fallback';
}

/** Shape of POST /v1/decoy/suggest request body (ARCHITECTURE.md §3). */
export interface SuggestRequest {
  plaintext_hint?: string;
  explicit_type?: DecoyType;
  context_tags?: string[];
  n_decoys?: number;
}

/** Shape of POST /v1/decoy/suggest 200 response (ARCHITECTURE.md §3). */
export interface SuggestResponse {
  type_detected: DecoyType;
  decoys: DecoyCandidate[];
  cache_hit: boolean;
  generation_latency_ms: number;
}

/** Parse error shape mimicking zod's flattened issues for forward-compat. */
export interface ParseIssue {
  path: string;
  message: string;
}

export type ParseResult<T> =
  | { ok: true; value: T }
  | { ok: false; issues: ParseIssue[] };

const TAG_RE = /^[A-Za-z0-9_-]{1,32}$/;

/**
 * Hand-rolled validator for SuggestRequest. Mirrors the zod schema specified
 * in ARCHITECTURE.md §3 + PROMPTING.md §9 (context_tags must be alphanumeric
 * + dash/underscore only, max 5 tags, max 32 chars each).
 */
export function parseSuggestRequest(input: unknown): ParseResult<SuggestRequest> {
  const issues: ParseIssue[] = [];
  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    return { ok: false, issues: [{ path: '', message: 'body must be a JSON object' }] };
  }
  const body = input as Record<string, unknown>;
  const out: SuggestRequest = {};

  if (body.plaintext_hint !== undefined) {
    if (typeof body.plaintext_hint !== 'string') {
      issues.push({ path: 'plaintext_hint', message: 'must be a string' });
    } else if (body.plaintext_hint.length > 128) {
      // Limit to 128 chars: type classification only needs a short prefix
      // (longest recognisable prefix is ~32 chars). Accepting more would
      // allow callers to send their real credential as a hint, which would
      // appear in server logs. Reject with a clear error so callers trim
      // before sending.
      issues.push({ path: 'plaintext_hint', message: 'must be <= 128 chars (send only a short prefix for type classification, not the full value)' });
    } else {
      out.plaintext_hint = body.plaintext_hint;
    }
  }

  if (body.explicit_type !== undefined) {
    if (typeof body.explicit_type !== 'string') {
      issues.push({ path: 'explicit_type', message: 'must be a string' });
    } else if (!(KNOWN_TYPES as readonly string[]).includes(body.explicit_type)) {
      issues.push({ path: 'explicit_type', message: `must be one of ${KNOWN_TYPES.join(', ')}` });
    } else {
      out.explicit_type = body.explicit_type as DecoyType;
    }
  }

  if (body.context_tags !== undefined) {
    if (!Array.isArray(body.context_tags)) {
      issues.push({ path: 'context_tags', message: 'must be an array' });
    } else if (body.context_tags.length > 5) {
      issues.push({ path: 'context_tags', message: 'max 5 tags' });
    } else {
      const tags: string[] = [];
      for (let i = 0; i < body.context_tags.length; i++) {
        const t = body.context_tags[i];
        if (typeof t !== 'string') {
          issues.push({ path: `context_tags[${i}]`, message: 'must be a string' });
        } else if (!TAG_RE.test(t)) {
          issues.push({ path: `context_tags[${i}]`, message: 'must match /^[A-Za-z0-9_-]{1,32}$/' });
        } else {
          tags.push(t);
        }
      }
      out.context_tags = tags;
    }
  }

  if (body.n_decoys !== undefined) {
    if (typeof body.n_decoys !== 'number' || !Number.isInteger(body.n_decoys)) {
      issues.push({ path: 'n_decoys', message: 'must be an integer' });
    } else if (body.n_decoys < 1 || body.n_decoys > 10) {
      issues.push({ path: 'n_decoys', message: 'must be in [1, 10]' });
    } else {
      out.n_decoys = body.n_decoys;
    }
  } else {
    out.n_decoys = 3;
  }

  // ARCHITECTURE.md §4 stage 3: must have at least one of hint / explicit_type.
  if (!out.plaintext_hint && !out.explicit_type) {
    issues.push({ path: '', message: 'one of plaintext_hint or explicit_type is required' });
  }

  if (issues.length > 0) return { ok: false, issues };
  return { ok: true, value: out };
}
