/**
 * path-traversal-safety.test.ts — Tests for safeJoin / safeResolve
 */

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import { safeJoin, safeResolve } from '../utils/path-safety.js';

const BASE = '/tmp/deny-test-base';

describe('safeJoin', () => {
  // --- Rejection cases ---

  it('rejects path traversal: ../../.ssh/authorized_keys', () => {
    assert.throws(
      () => safeJoin(BASE, '../../.ssh/authorized_keys'),
      /unsafe path/,
    );
  });

  it('rejects absolute path: /etc/passwd', () => {
    assert.throws(
      () => safeJoin(BASE, '/etc/passwd'),
      /unsafe path/,
    );
  });

  it('rejects pure dotdot: ..', () => {
    assert.throws(
      () => safeJoin(BASE, '..'),
      /unsafe path/,
    );
  });

  it('rejects slash anywhere: foo/bar', () => {
    assert.throws(
      () => safeJoin(BASE, 'foo/bar'),
      /unsafe path/,
    );
  });

  it('rejects backslash anywhere: foo\\\\bar', () => {
    assert.throws(
      () => safeJoin(BASE, 'foo\\bar'),
      /unsafe path/,
    );
  });

  it('rejects pure dot: .', () => {
    assert.throws(
      () => safeJoin(BASE, '.'),
      /unsafe path/,
    );
  });

  // --- Acceptance cases ---

  it('accepts safe-name.json', () => {
    const result = safeJoin(BASE, 'safe-name.json');
    assert.equal(result, path.join(BASE, 'safe-name.json'));
  });

  it('accepts with-hyphens_and_underscores.txt', () => {
    const result = safeJoin(BASE, 'with-hyphens_and_underscores.txt');
    assert.equal(result, path.join(BASE, 'with-hyphens_and_underscores.txt'));
  });

  it('resolved path is inside the intended base', () => {
    const result = safeJoin(BASE, 'control.dat');
    assert.ok(
      result.startsWith(BASE + path.sep),
      `Expected ${result} to be inside ${BASE}`,
    );
  });
});

describe('safeResolve', () => {
  // --- Rejection cases ---

  it('rejects path traversal: ../../.ssh/authorized_keys', () => {
    assert.throws(
      () => safeResolve(BASE, '../../.ssh/authorized_keys'),
      /unsafe path/,
    );
  });

  it('rejects absolute path: /etc/passwd', () => {
    assert.throws(
      () => safeResolve(BASE, '/etc/passwd'),
      /unsafe path/,
    );
  });

  it('rejects pure dotdot: ..', () => {
    assert.throws(
      () => safeResolve(BASE, '..'),
      /unsafe path/,
    );
  });

  it('rejects embedded dotdot: controls/../../../etc/passwd', () => {
    assert.throws(
      () => safeResolve(BASE, 'controls/../../../etc/passwd'),
      /unsafe path/,
    );
  });

  it('rejects backslash', () => {
    assert.throws(
      () => safeResolve(BASE, 'controls\\..\\etc'),
      /unsafe path/,
    );
  });

  // --- Acceptance cases ---

  it('accepts single-level: control.dat', () => {
    const result = safeResolve(BASE, 'control.dat');
    assert.equal(result, path.join(BASE, 'control.dat'));
  });

  it('accepts sub-directory path: controls/foo.dat', () => {
    const result = safeResolve(BASE, 'controls/foo.dat');
    assert.equal(result, path.join(BASE, 'controls', 'foo.dat'));
  });

  it('resolved sub-path is inside the intended base', () => {
    const result = safeResolve(BASE, 'controls/foo.dat');
    assert.ok(
      result.startsWith(BASE + path.sep),
      `Expected ${result} to be inside ${BASE}`,
    );
  });
});
