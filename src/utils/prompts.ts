/**
 * prompts.ts — node:readline wrappers for interactive CLI prompts
 */

import * as readline from 'node:readline';

/** Read a line with normal echo. */
export function textInput(prompt: string, validator?: (s: string) => string | null): Promise<string> {
  return new Promise(resolve => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const ask = () => {
      rl.question(prompt, answer => {
        if (validator) {
          const err = validator(answer);
          if (err) {
            process.stdout.write(`  ${err}\n`);
            ask();
            return;
          }
        }
        rl.close();
        resolve(answer);
      });
    };
    ask();
  });
}

/**
 * Hidden password input — characters are not echoed.
 * Falls back to visible input if stdin is not a TTY (piped input).
 */
export function hiddenInput(prompt: string): Promise<string> {
  return new Promise(resolve => {
    if (!process.stdin.isTTY) {
      // Non-TTY: just read a line normally
      const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
      rl.question(prompt, answer => { rl.close(); resolve(answer); });
      return;
    }

    process.stdout.write(prompt);

    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
      terminal: true,
    });

    // Mute output
    (rl as unknown as { _writeToOutput: (s: string) => void })._writeToOutput = () => {};

    rl.question('', answer => {
      process.stdout.write('\n');
      rl.close();
      resolve(answer);
    });
  });
}

/** Yes/no prompt. Returns true for y/Y/yes. */
export function confirm(prompt: string, defaultYes = true): Promise<boolean> {
  const hint = defaultYes ? '[Y/n]' : '[y/N]';
  return new Promise(resolve => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question(`${prompt} ${hint} `, answer => {
      rl.close();
      const trimmed = answer.trim().toLowerCase();
      if (trimmed === '') { resolve(defaultYes); return; }
      resolve(trimmed === 'y' || trimmed === 'yes');
    });
  });
}

/** Read a password with confirmation. Retries until they match. */
export async function confirmedPassword(prompt: string, confirmPrompt: string): Promise<string> {
  while (true) {
    const pw1 = await hiddenInput(prompt);
    if (!pw1) {
      process.stdout.write('  Password cannot be empty.\n');
      continue;
    }
    const pw2 = await hiddenInput(confirmPrompt);
    if (pw1 === pw2) return pw1;
    process.stdout.write('  Passwords do not match. Try again.\n');
  }
}

/** Read all stdin as a string (for piped input). */
export function readStdin(): Promise<string> {
  return new Promise(resolve => {
    const chunks: Buffer[] = [];
    process.stdin.on('data', chunk => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8').trimEnd()));
    process.stdin.resume();
  });
}

/** Detect if stdin has piped data (not a TTY). */
export function isStdinPiped(): boolean {
  return !process.stdin.isTTY;
}
