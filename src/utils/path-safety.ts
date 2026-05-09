/**
 * path-safety.ts — Path traversal prevention utilities
 */

import path from 'node:path';

/**
 * Safely join `name` onto `base`, rejecting any input that escapes the base.
 *
 * Rejects:
 *   - absolute paths ('/etc/passwd', 'C:\\foo')
 *   - names containing `/` or `\` or `..`
 *   - names that resolve outside the base after path.resolve()
 *
 * Returns: absolute path inside base.
 * Throws:  Error('unsafe path: ...') with the offending input.
 */
export function safeJoin(base: string, name: string): string {
  // Reject absolute paths
  if (path.isAbsolute(name)) {
    throw new Error(`unsafe path: ${name}`);
  }

  // Reject path separators, '..' sequences, or pure '.'
  if (/[\\/]|\.\./.test(name) || name === '.') {
    throw new Error(`unsafe path: ${name}`);
  }

  // Resolve and verify containment
  const resolved = path.resolve(base, name);
  const resolvedBase = path.resolve(base);
  if (!resolved.startsWith(resolvedBase + path.sep) && resolved !== resolvedBase) {
    throw new Error(`unsafe path: ${name}`);
  }

  return resolved;
}

/**
 * Safely resolve a relative path (which may contain '/' sub-directories) onto `base`.
 * Unlike safeJoin, forward slashes are permitted — but '..' components, absolute
 * paths, backslashes, and null bytes are all rejected, and containment inside `base`
 * is verified after resolution.
 *
 * Use this for manifest-style paths like 'controls/foo.dat'.
 * Use safeJoin for simple single-component filenames.
 *
 * Returns: absolute path inside base.
 * Throws:  Error('unsafe path: ...') with the offending input.
 */
export function safeResolve(base: string, relPath: string): string {
  // Reject absolute paths
  if (path.isAbsolute(relPath)) {
    throw new Error(`unsafe path: ${relPath}`);
  }

  // Reject backslashes and null bytes
  if (/[\\\0]/.test(relPath)) {
    throw new Error(`unsafe path: ${relPath}`);
  }

  // Reject any path component that is '..'
  const components = relPath.split('/');
  if (components.some(c => c === '..')) {
    throw new Error(`unsafe path: ${relPath}`);
  }

  // Resolve and verify containment
  const resolved = path.resolve(base, relPath);
  const resolvedBase = path.resolve(base);
  if (!resolved.startsWith(resolvedBase + path.sep) && resolved !== resolvedBase) {
    throw new Error(`unsafe path: ${relPath}`);
  }

  return resolved;
}
