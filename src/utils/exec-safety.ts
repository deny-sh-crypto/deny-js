/**
 * exec-safety.ts — Input validators for shell-adjacent operations.
 *
 * Use these before passing user-controlled values to child_process functions.
 * All validators throw a descriptive Error on invalid input so callers can
 * handle it before any exec call is made.
 */

import * as path from 'node:path';

/**
 * Validates an AWS S3 bucket name.
 * Rules: 3–63 chars, lowercase alphanumeric, hyphens, dots. No slashes or metacharacters.
 */
export function validateS3Bucket(bucket: string): void {
  if (typeof bucket !== 'string' || bucket.length === 0) {
    throw new Error('S3 bucket name must be a non-empty string.');
  }
  if (!/^[a-z0-9.-]{3,63}$/.test(bucket)) {
    throw new Error(
      `Invalid S3 bucket name: "${bucket}". ` +
      'Must be 3–63 characters, lowercase alphanumeric, hyphens, or dots.',
    );
  }
}

/**
 * Validates an rclone remote name (the part before the colon).
 * Only alphanumeric, hyphens, and underscores are permitted.
 * The "remote:path" form must be constructed by the caller AFTER validation.
 */
export function validateRcloneRemote(remote: string): void {
  if (typeof remote !== 'string' || remote.length === 0) {
    throw new Error('rclone remote name must be a non-empty string.');
  }
  if (!/^[a-zA-Z0-9_-]+$/.test(remote)) {
    throw new Error(
      `Invalid rclone remote name: "${remote}". ` +
      'Must be alphanumeric, hyphens, or underscores only ' +
      '(no colons, spaces, or shell metacharacters).',
    );
  }
}

/**
 * Validates a file path for use in child_process argv arrays.
 * Rejects any path whose resolved form contains shell metacharacters.
 * Even when using execFileSync / spawnSync (no shell), a malformed path
 * could still confuse argument parsing in some tools.
 */
export function validateFilePath(filePath: string): void {
  if (typeof filePath !== 'string' || filePath.length === 0) {
    throw new Error('File path must be a non-empty string.');
  }
  const resolved = path.resolve(filePath);
  // Shell metacharacters that have no place in a filesystem path
  if (/[;&|`$<>\\"']/.test(resolved)) {
    throw new Error(
      `Invalid file path: "${filePath}". Shell metacharacters are not permitted.`,
    );
  }
}
