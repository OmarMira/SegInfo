import * as fs from 'node:fs';
import * as path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { glob } from 'glob';

const execFileAsync = promisify(execFile);

export type FindingSource = 'working-tree' | 'git-history';

/** A raw secret finding produced by the engine (module-agnostic shape). */
export interface RawFinding {
  /** Path relative to the scan root (or cwd for globs), always posix separators. */
  file: string;
  line: number;
  type: string;
  entropy: number;
  source: FindingSource;
  /** Commit sha when source is 'git-history'. */
  commit?: string;
}

export interface ScanOptions {
  /** Base directory for relative targets/globs. Defaults to process.cwd(). */
  cwd?: string;
  /** Scan committed history for deleted secrets. Defaults to true. */
  gitHistory?: boolean;
  /** Skip files larger than this. Defaults to 2 MiB. */
  maxFileBytes?: number;
  /** Maximum number of commits to inspect. Defaults to 500. */
  maxCommits?: number;
}

interface SecretPattern {
  /**
   * Regex source shared verbatim by the JS engine and `git grep -E`.
   * Must stay POSIX-ERE-safe: no lookarounds, no `\b`/`\s`/`\d`, no `(?:`.
   */
  src: string;
  type: string;
  /** 1-based capture group holding the candidate value for entropy checks. */
  valueGroup?: number;
  /** Skip the blob-boundary check for structurally unique patterns. */
  noBoundary?: boolean;
}

/**
 * Pattern order matters: specific token shapes win over the generic
 * keyword+entropy rule, which runs last.
 */
const SECRET_PATTERNS: SecretPattern[] = [
  { src: 'AKIA[0-9A-Z]{16}', type: 'aws-access-key' },
  { src: 'ASIA[0-9A-Z]{16}', type: 'aws-sts-access-key' },
  { src: 'gh[pousr]_?[A-Za-z0-9]{36,}', type: 'github-token' },
  { src: 'github_pat_[A-Za-z0-9_]{22,}', type: 'github-fine-grained-pat' },
  { src: 'xox[baprs]-[A-Za-z0-9-]{10,}', type: 'slack-token' },
  { src: 'sk_(live|test)_[0-9a-zA-Z]{24,}', type: 'stripe-key' },
  { src: 'AIza[0-9A-Za-z_-]{35}', type: 'google-api-key' },
  { src: 'npm_[A-Za-z0-9]{36}', type: 'npm-token' },
  {
    src: 'eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}',
    type: 'jwt-token',
  },
  {
    src: '-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----',
    type: 'private-key',
  },
  {
    // The scheme + embedded user:password@host structure cannot occur inside
    // base64/hex blobs — `:` and `@` are not base64 characters — so the URL
    // path's trailing `/` must not disqualify a match.
    src: '[a-z][a-z0-9+.\\-]*://[^ \\t/:@]+:[^ \\t/:@]+@[^ \\t/]+',
    type: 'db-url-credentials',
    noBoundary: true,
  },
  {
    src: '[A-Za-z0-9_.\\-]*(api[_-]?key|apikey|secret|token|password|passwd|pwd|credential)[A-Za-z0-9_\\-]*["\']?[ \t]*[:=][ \t]*["\']?([A-Za-z0-9/+=_\\-]{16,})',
    type: 'hardcoded-credential',
    valueGroup: 2,
  },
];

const COMPILED = SECRET_PATTERNS.map((p) => ({
  ...p,
  re: new RegExp(p.src, 'i'),
}));

/**
 * Characters that indicate a match is embedded inside a larger base64 or
 * hex blob rather than a standalone token. A real token is delimited by
 * quotes, spaces, parens or line edges — never by `+/` or surrounding
 * alphanumerics. This kills lookalikes such as `gho...` inside sha512
 * integrity hashes without needing lookarounds (which git grep cannot
 * compile anyway).
 */
const BLOB_CHAR = /[A-Za-z0-9+/]/;

function hasCleanBoundary(line: string, index: number, length: number): boolean {
  const before = index > 0 ? line[index - 1] : '';
  const after = index + length < line.length ? line[index + length] : '';
  return (
    (before === '' || !BLOB_CHAR.test(before)) &&
    (after === '' || !BLOB_CHAR.test(after))
  );
}

const SKIP_DIRS = new Set([
  '.git',
  'node_modules',
  'dist',
  'build',
  'coverage',
  '.venv',
  'venv',
  '.next',
  '.cache',
  '.gradle',
  'target',
  '__pycache__',
  '.terraform',
  'bower_components',
]);

const GLOB_IGNORE = [
  '**/.git/**',
  '**/node_modules/**',
  '**/dist/**',
  '**/coverage/**',
  '**/.venv/**',
  '**/vendor/**',
];

const DEFAULT_EXTS = new Set([
  '.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts',
  '.py', '.rb', '.go', '.java', '.php', '.cs', '.pl', '.rs',
  '.sh', '.bash', '.zsh', '.ps1',
  '.json', '.yml', '.yaml', '.toml', '.ini', '.cfg', '.conf',
  '.properties', '.tf', '.tfvars', '.xml', '.txt', '.md', '.sql',
  '.env', '.pem', '.key', '.p12', '.pfx', '.crt', '.cer', '.jks',
]);

/** Extensionless files that are known secret carriers. */
const SECRET_FILENAMES = new Set([
  'id_rsa',
  'id_dsa',
  'id_ecdsa',
  'id_ed25519',
  'credentials',
  'credentials.json',
  'shadow',
]);

const DEFAULTS = {
  gitHistory: true,
  maxFileBytes: 2 * 1024 * 1024,
  maxCommits: 500,
};

const MAX_DEPTH = 32;
const MAX_FILES = 50_000;
const MAX_LINE_LENGTH = 10_000;
const GIT_GREP_BATCH = 50;
const MIN_SECRET_LENGTH = 16;
const MIN_ENTROPY = 3.0;

function calcEntropy(text: string): number {
  const freq = new Map<string, number>();
  for (const ch of text) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / text.length;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 100) / 100;
}

/**
 * Filters generic keyword matches down to values that actually look like
 * generated credentials: long enough, mixed letters+digits, and not a
 * repetitive string. This is what keeps `password = "hunter2"`-style noise
 * and `tokenize = someFunctionCall()` out of reports.
 */
function plausibleSecret(value: string): boolean {
  if (value.length < MIN_SECRET_LENGTH) return false;
  if (!/[0-9]/.test(value) || !/[A-Za-z]/.test(value)) return false;
  return calcEntropy(value) >= MIN_ENTROPY;
}

/** First pattern that validates wins; returns null when nothing matches. */
function matchLine(line: string): { type: string; entropy: number } | null {
  for (const p of COMPILED) {
    const m = p.re.exec(line);
    if (!m) continue;
    if (!p.noBoundary && !hasCleanBoundary(line, m.index, m[0].length)) continue;
    if (p.valueGroup !== undefined) {
      const value = m[p.valueGroup];
      if (!value || !plausibleSecret(value)) continue;
      return { type: p.type, entropy: calcEntropy(value) };
    }
    return { type: p.type, entropy: calcEntropy(m[0]) };
  }
  return null;
}

function isScannable(filePath: string): boolean {
  const base = path.basename(filePath);
  if (base.startsWith('.env')) return true;
  if (SECRET_FILENAMES.has(base)) return true;
  return DEFAULT_EXTS.has(path.extname(base).toLowerCase());
}

/**
 * Breadth-first walk that never follows symlinks (a malicious repo could
 * otherwise point one at /etc/shadow or loop forever) and skips known
 * noise directories.
 */
async function collectFiles(root: string): Promise<string[]> {
  const out: string[] = [];
  const queue: Array<{ dir: string; depth: number }> = [{ dir: root, depth: 0 }];
  while (queue.length > 0) {
    const { dir, depth } = queue.shift()!;
    if (depth > MAX_DEPTH) continue;
    let entries: fs.Dirent[];
    try {
      entries = await fs.promises.readdir(dir, { withFileTypes: true });
    } catch {
      continue; // unreadable directory: skip, never crash the scan
    }
    for (const entry of entries) {
      if (out.length >= MAX_FILES) return out;
      if (entry.isSymbolicLink()) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) queue.push({ dir: full, depth: depth + 1 });
      } else if (entry.isFile() && isScannable(full)) {
        out.push(full);
      }
    }
  }
  return out;
}

async function scanFile(
  abs: string,
  relBase: string,
  maxBytes: number,
): Promise<RawFinding[]> {
  try {
    const st = await fs.promises.lstat(abs);
    if (!st.isFile() || st.size > maxBytes) return [];
    const content = await fs.promises.readFile(abs, 'utf8');
    if (content.includes('\u0000')) return []; // binary file
    const rel = path.relative(relBase, abs).split(path.sep).join('/');
    const findings: RawFinding[] = [];
    const lines = content.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line =
        lines[i].length > MAX_LINE_LENGTH ? lines[i].slice(0, MAX_LINE_LENGTH) : lines[i];
      const hit = matchLine(line);
      if (hit) {
        findings.push({
          file: rel,
          line: i + 1,
          type: hit.type,
          entropy: hit.entropy,
          source: 'working-tree',
        });
      }
    }
    return findings;
  } catch {
    return []; // unreadable file: skip
  }
}

function isExitCode(err: unknown, code: number): boolean {
  return (
    typeof err === 'object' &&
    err !== null &&
    'code' in err &&
    (err as { code: unknown }).code === code
  );
}

function parseGitGrepLine(
  raw: string,
): { commit?: string; file: string; line: number; content: string } | null {
  const withSha = /^([0-9a-f]{7,64}):(.+?):(\d+):([\s\S]*)$/.exec(raw);
  if (withSha) {
    return { commit: withSha[1], file: withSha[2], line: Number(withSha[3]), content: withSha[4] };
  }
  const noSha = /^(.+?):(\d+):([\s\S]*)$/.exec(raw);
  if (noSha) {
    return { file: noSha[1], line: Number(noSha[2]), content: noSha[3] };
  }
  return null;
}

/**
 * Scans committed history with a single broad `git grep -E` prefilter per
 * batch of commits, then re-validates every candidate line with the strict
 * in-process patterns. Never uses a shell (no injection surface).
 */
async function scanHistory(root: string, maxCommits: number): Promise<RawFinding[]> {
  try {
    await execFileAsync('git', ['-C', root, 'rev-parse', '--is-inside-work-tree'], {
      timeout: 10_000,
    });
  } catch {
    return []; // not a git repository (or git unavailable): working tree only
  }

  let shas: string[];
  try {
    const { stdout } = await execFileAsync(
      'git',
      ['-C', root, 'rev-list', `--max-count=${maxCommits}`, '--all'],
      { timeout: 30_000 },
    );
    shas = stdout
      .split('\n')
      .map((s) => s.trim())
      .filter(Boolean);
  } catch {
    return [];
  }
  if (shas.length === 0) return [];

  const combined = SECRET_PATTERNS.map((p) => p.src).join('|');
  const findings: RawFinding[] = [];

  for (let i = 0; i < shas.length; i += GIT_GREP_BATCH) {
    const batch = shas.slice(i, i + GIT_GREP_BATCH);
    let stdout: string;
    try {
      ({ stdout } = await execFileAsync(
        'git',
        ['-C', root, 'grep', '-n', '-i', '-I', '-E', '-e', combined, ...batch],
        { timeout: 60_000, maxBuffer: 64 * 1024 * 1024 },
      ));
    } catch (err) {
      if (isExitCode(err, 1)) continue; // no matches in this batch
      break; // git error: keep findings gathered so far
    }
    for (const raw of stdout.split('\n')) {
      if (!raw) continue;
      const parsed = parseGitGrepLine(raw);
      if (!parsed) continue;
      const hit = matchLine(parsed.content);
      if (hit) {
        findings.push({
          file: parsed.file,
          line: parsed.line,
          type: hit.type,
          entropy: hit.entropy,
          source: 'git-history',
          ...(parsed.commit ? { commit: parsed.commit } : {}),
        });
      }
    }
  }
  return findings;
}

/** Working-tree findings always win over their historical duplicates. */
function dedupe(findings: RawFinding[]): RawFinding[] {
  const map = new Map<string, RawFinding>();
  for (const f of findings) {
    const key = `${f.file}:${f.line}:${f.type}`;
    const prev = map.get(key);
    if (!prev || (prev.source === 'git-history' && f.source === 'working-tree')) {
      map.set(key, f);
    }
  }
  return [...map.values()];
}

/**
 * Scan a directory or glob pattern for secrets.
 *
 * @param target Directory, file or glob pattern. Defaults to options.cwd.
 * @returns findings sorted by discovery order, deduplicated per file:line:type.
 */
export async function scanRepo(
  target?: string,
  options: ScanOptions = {},
): Promise<RawFinding[]> {
  const gitHistory = options.gitHistory ?? DEFAULTS.gitHistory;
  const maxFileBytes = options.maxFileBytes ?? DEFAULTS.maxFileBytes;
  const maxCommits = options.maxCommits ?? DEFAULTS.maxCommits;
  const cwd = options.cwd ?? process.cwd();

  const findings: RawFinding[] = [];
  const resolved = target ? path.resolve(cwd, target) : cwd;
  const isDir = fs.existsSync(resolved) && safeIsDirectory(resolved);

  if (target && !isDir) {
    // Glob mode: match relative to cwd, then filter to scannable files.
    const matches = await glob(target, {
      cwd,
      dot: true,
      nodir: true,
      follow: false,
      ignore: GLOB_IGNORE,
    });
    for (const rel of matches) {
      const abs = path.resolve(cwd, rel);
      if (!isScannable(abs)) continue;
      findings.push(...(await scanFile(abs, cwd, maxFileBytes)));
    }
    if (gitHistory) findings.push(...(await scanHistory(cwd, maxCommits)));
    return dedupe(findings);
  }

  const root = resolved;
  const files = await collectFiles(root);
  for (const file of files) {
    findings.push(...(await scanFile(file, root, maxFileBytes)));
  }
  if (gitHistory) findings.push(...(await scanHistory(root, maxCommits)));
  return dedupe(findings);
}

function safeIsDirectory(p: string): boolean {
  try {
    return fs.statSync(p).isDirectory();
  } catch {
    return false;
  }
}
