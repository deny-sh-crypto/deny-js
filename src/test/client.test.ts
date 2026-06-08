/**
 * Tests for src/client.ts (deny-sh/client vaultGet wrapper).
 *
 * These tests use a stub fetch to avoid network. The wire shape under test:
 *   - GET /vault/list  -> { items: [{ id, label, created_at, ... }], count }
 *   - GET /vault/:id   -> { id, label, encryptedData, iv, salt, ... }
 * Decryption is AES-256-CTR with an Argon2id-derived key (same as web/js/vault-app.js).
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, randomBytes } from 'node:crypto';
import { argon2id } from 'hash-wasm';

import { vaultGet, vaultGetById, vaultList, VaultError } from '../client.js';

const ARGON2_T_COST = 3;
const ARGON2_M_COST = 65536;
const ARGON2_P = 1;
const KEY_LEN = 32;

function toHex(b: Uint8Array): string {
  return Buffer.from(b).toString('hex');
}

async function encryptForVault(plaintext: string, password: string) {
  const salt = randomBytes(32);
  const iv = randomBytes(16);
  const key = await argon2id({
    password: new TextEncoder().encode(password),
    salt,
    parallelism: ARGON2_P,
    iterations: ARGON2_T_COST,
    memorySize: ARGON2_M_COST,
    hashLength: KEY_LEN,
    outputType: 'binary',
  });
  const cipher = createCipheriv('aes-256-ctr', Buffer.from(key), iv);
  const ct = Buffer.concat([cipher.update(Buffer.from(plaintext, 'utf8')), cipher.final()]);
  return {
    encryptedData: ct.toString('hex'),
    iv: toHex(iv),
    salt: toHex(salt),
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json' } });
}

interface RouteMap {
  list?: () => Promise<Response> | Response;
  items?: Record<string, () => Promise<Response> | Response>;
}

function makeFetch(routes: RouteMap, capture?: { headers: Record<string, string>[] }) {
  return async (url: string | URL | Request, init?: RequestInit) => {
    const u = new URL(typeof url === 'string' ? url : url.toString());
    if (capture && init?.headers) {
      capture.headers.push(init.headers as Record<string, string>);
    }
    if (u.pathname.endsWith('/vault/list') && routes.list) return routes.list();
    const m = u.pathname.match(/\/vault\/([^/]+)$/);
    if (m && routes.items?.[m[1]!]) return routes.items[m[1]!]!();
    return new Response('not found', { status: 404 });
  };
}

describe('client.vaultGet', () => {
  it('lists, decrypts, and returns plaintext', async () => {
    const blob = await encryptForVault('sk_live_real_value', 'wrap-password-1');
    const fetchImpl = makeFetch({
      list: () => jsonResponse({ items: [{ id: 'abc123', label: 'stripe-prod', size: 18, created_at: '2026-05-28T00:00:00Z' }], count: 1 }),
      items: { abc123: () => jsonResponse({ id: 'abc123', label: 'stripe-prod', ...blob, size: 18 }) },
    });

    const result = await vaultGet('stripe-prod', 'wrap-password-1', {
      apiKey: 'cs_test',
      baseUrl: 'https://example.com/api',
      fetch: fetchImpl,
    });

    assert.equal(result, 'sk_live_real_value');
  });

  it('vaultGetById skips the label list call', async () => {
    const blob = await encryptForVault('sk_live_by_id', 'pw');
    let listCalls = 0;
    const fetchImpl = makeFetch({
      list: () => { listCalls++; return jsonResponse({ items: [], count: 0 }); },
      items: { xyz789: () => jsonResponse({ id: 'xyz789', label: 'whatever', ...blob, size: 13 }) },
    });

    const result = await vaultGetById('xyz789', 'pw', {
      apiKey: 'cs_test',
      baseUrl: 'https://example.com/api',
      fetch: fetchImpl,
    });

    assert.equal(result, 'sk_live_by_id');
    assert.equal(listCalls, 0, 'vaultGetById must not call /vault/list');
  });

  it('throws vault_label_not_found for unknown label', async () => {
    const fetchImpl = makeFetch({
      list: () => jsonResponse({ items: [{ id: 'a', label: 'other', size: 5 }], count: 1 }),
    });

    await assert.rejects(
      () => vaultGet('missing', 'pw', { apiKey: 'cs_test', baseUrl: 'https://x/api', fetch: fetchImpl }),
      (err: unknown) => err instanceof VaultError && err.code === 'vault_label_not_found',
    );
  });

  it('throws vault_unauthorized on 401', async () => {
    const fetchImpl = makeFetch({
      list: () => new Response('nope', { status: 401 }),
    });

    await assert.rejects(
      () => vaultGet('x', 'pw', { apiKey: 'cs_test', baseUrl: 'https://x/api', fetch: fetchImpl }),
      (err: unknown) => err instanceof VaultError && err.code === 'vault_unauthorized' && err.status === 401,
    );
  });

  it('throws vault_missing_api_key when neither opts.apiKey nor env DENY_API_KEY is set', async () => {
    const prev = process.env.DENY_API_KEY;
    delete process.env.DENY_API_KEY;
    try {
      await assert.rejects(
        () => vaultGet('x', 'pw', { baseUrl: 'https://x/api', fetch: makeFetch({}) }),
        (err: unknown) => err instanceof VaultError && err.code === 'vault_missing_api_key',
      );
    } finally {
      if (prev !== undefined) process.env.DENY_API_KEY = prev;
    }
  });

  it('sends Bearer token in Authorization header', async () => {
    const blob = await encryptForVault('value', 'pw');
    const capture = { headers: [] as Record<string, string>[] };
    const fetchImpl = makeFetch({
      list: () => jsonResponse({ items: [{ id: 'i1', label: 'L', size: 5, created_at: 't' }], count: 1 }),
      items: { i1: () => jsonResponse({ id: 'i1', label: 'L', ...blob, size: 5 }) },
    }, capture);

    await vaultGet('L', 'pw', { apiKey: 'cs_my_test_key', baseUrl: 'https://x/api', fetch: fetchImpl });

    assert.ok(capture.headers.length >= 1, 'expected at least one fetch call');
    for (const h of capture.headers) {
      assert.equal(h.Authorization, 'Bearer cs_my_test_key');
    }
  });

  it('refuses to scan a vault larger than labelIndexLimit', async () => {
    const items = Array.from({ length: 250 }, (_, i) => ({ id: `i${i}`, label: `lbl-${i}`, size: 5 }));
    const fetchImpl = makeFetch({
      list: () => jsonResponse({ items, count: items.length }),
    });

    await assert.rejects(
      () => vaultGet('lbl-3', 'pw', {
        apiKey: 'cs_test',
        baseUrl: 'https://x/api',
        fetch: fetchImpl,
        labelIndexLimit: 100,
      }),
      (err: unknown) => err instanceof VaultError && err.code === 'vault_label_index_too_large',
    );
  });

  it('vaultList returns the raw items array', async () => {
    const fetchImpl = makeFetch({
      list: () => jsonResponse({ items: [{ id: 'a', label: 'one' }, { id: 'b', label: 'two' }], count: 2 }),
    });

    const items = await vaultList({ apiKey: 'cs_test', baseUrl: 'https://x/api', fetch: fetchImpl });
    assert.equal(items.length, 2);
    assert.equal(items[0]!.label, 'one');
  });

  // P1-3 regression: the SDK must never trust server-supplied crypto params.
  // A hostile/buggy server returning a wrong-length salt or IV should produce a
  // typed VaultError, not a native ERR_CRYPTO_INVALID_IV that escapes the
  // VaultError catch contract consumers rely on.
  it('rejects a server-supplied IV of the wrong length with a typed VaultError', async () => {
    const blob = await encryptForVault('sk_live_real_value', 'pw');
    // Corrupt the IV to 8 bytes (16 hex chars).
    const badBlob = { ...blob, iv: '0011223344556677' };
    const fetchImpl = makeFetch({
      items: { bad1: () => jsonResponse({ id: 'bad1', label: 'x', ...badBlob, size: 18 }) },
    });
    await assert.rejects(
      () => vaultGetById('bad1', 'pw', { apiKey: 'cs_test', baseUrl: 'https://x/api', fetch: fetchImpl }),
      (err: unknown) => err instanceof VaultError && err.code === 'vault_invalid_crypto_params',
    );
  });

  it('rejects a server-supplied salt of the wrong length with a typed VaultError', async () => {
    const blob = await encryptForVault('sk_live_real_value', 'pw');
    const badBlob = { ...blob, salt: 'deadbeef' }; // 4 bytes
    const fetchImpl = makeFetch({
      items: { bad2: () => jsonResponse({ id: 'bad2', label: 'x', ...badBlob, size: 18 }) },
    });
    await assert.rejects(
      () => vaultGetById('bad2', 'pw', { apiKey: 'cs_test', baseUrl: 'https://x/api', fetch: fetchImpl }),
      (err: unknown) => err instanceof VaultError && err.code === 'vault_invalid_crypto_params',
    );
  });
});
