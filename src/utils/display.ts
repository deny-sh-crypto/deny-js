/**
 * display.ts — ANSI terminal output utilities (zero dependencies)
 */

// --- ANSI colours ---

const ESC = '\x1b[';

export const c = {
  reset:  `${ESC}0m`,
  bold:   `${ESC}1m`,
  dim:    `${ESC}2m`,
  green:  `${ESC}32m`,
  red:    `${ESC}31m`,
  yellow: `${ESC}33m`,
  blue:   `${ESC}34m`,
  cyan:   `${ESC}36m`,
  white:  `${ESC}37m`,
};

export function green(s: string): string  { return `${c.green}${s}${c.reset}`; }
export function red(s: string): string    { return `${c.red}${s}${c.reset}`; }
export function yellow(s: string): string { return `${c.yellow}${s}${c.reset}`; }
export function blue(s: string): string   { return `${c.blue}${s}${c.reset}`; }
export function cyan(s: string): string   { return `${c.cyan}${s}${c.reset}`; }
export function bold(s: string): string   { return `${c.bold}${s}${c.reset}`; }
export function dim(s: string): string    { return `${c.dim}${s}${c.reset}`; }

// --- Log helpers ---

export function success(msg: string): void { console.log(`${c.green}✓${c.reset} ${msg}`); }
export function error(msg: string): void   { console.error(`${c.red}✗${c.reset} ${msg}`); }
export function warn(msg: string): void    { console.warn(`${c.yellow}⚠${c.reset} ${msg}`); }
export function info(msg: string): void    { console.log(`${c.blue}ℹ${c.reset} ${msg}`); }
export function step(msg: string): void    { console.log(`  ${dim('→')} ${msg}`); }

// --- Progress bar ---

/**
 * Render an ASCII progress bar.
 * progressBar(65, 30) → [████████████████████░░░░░░░░░░] 65%
 */
export function progressBar(percent: number, width = 28): string {
  const filled = Math.round((width * percent) / 100);
  const empty = width - filled;
  const bar = '█'.repeat(filled) + '░'.repeat(empty);
  return `[${bar}] ${percent}%`;
}

/** Write progress bar in-place (overwrites current line). */
export function printProgress(label: string, percent: number, width = 28): void {
  const bar = progressBar(percent, width);
  process.stdout.write(`\r  ${label} ${bar}   `);
  if (percent >= 100) process.stdout.write('\n');
}

// --- Table ---

/** Render an aligned table to stdout. */
export function table(headers: string[], rows: string[][]): void {
  const allRows = [headers, ...rows];
  const widths = headers.map((_, ci) =>
    Math.max(...allRows.map(r => (r[ci] ?? '').length))
  );

  const divider = widths.map(w => '─'.repeat(w + 2)).join('┼');
  const fmt = (row: string[], dim_ = false) =>
    row.map((cell, ci) => {
      const padded = (cell ?? '').padEnd(widths[ci] ?? 0);
      return dim_ ? dim(padded) : padded;
    }).join(' │ ');

  console.log(`  ${bold(fmt(headers))}`);
  console.log(`  ${dim(divider)}`);
  for (const row of rows) {
    console.log(`  ${fmt(row)}`);
  }
}

// --- Box ---

/** Render a Unicode box around content. */
export function box(title: string, lines: string[]): void {
  const maxLen = Math.max(title.length, ...lines.map(l => stripAnsi(l).length));
  const width = maxLen + 4;
  const top    = `╔${'═'.repeat(width)}╗`;
  const bottom = `╚${'═'.repeat(width)}╝`;
  const titleLine = `║  ${bold(title)}${' '.repeat(width - title.length - 2)}║`;

  console.log(top);
  console.log(titleLine);
  console.log(`║${'─'.repeat(width)}║`);
  for (const line of lines) {
    const raw = stripAnsi(line);
    const pad = width - raw.length - 2;
    console.log(`║  ${line}${' '.repeat(Math.max(0, pad))}║`);
  }
  console.log(bottom);
}

// Strip ANSI codes to measure real string length
function stripAnsi(s: string): string {
  // eslint-disable-next-line no-control-regex
  return s.replace(/\x1b\[[0-9;]*m/g, '');
}

/** Print a header banner. */
export function banner(title: string): void {
  console.log();
  console.log(`  ${bold(cyan('deny.sh'))} ${dim('—')} ${bold(title)}`);
  console.log();
}
