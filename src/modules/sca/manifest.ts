export type Ecosystem = 'npm' | 'PyPI';

/** A pinned dependency extracted from a manifest file. */
export interface Dependency {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  /** Manifest filename relative to the scan root (posix separators). */
  file: string;
  /** 1-based line in the manifest. */
  line: number;
}

const NODE_MODULES = 'node_modules/';
const MAX_V1_DEPTH = 25;

/** Maps every `"key": {` occurrence in a JSON document to its line number. */
function buildKeyLineIndex(content: string): Map<string, number> {
  const index = new Map<string, number>();
  const newlines: number[] = [];
  for (let i = 0; i < content.length; i++) {
    if (content.charCodeAt(i) === 10) newlines.push(i);
  }
  const lineAt = (pos: number): number => {
    let lo = 0;
    let hi = newlines.length;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (newlines[mid] < pos) lo = mid + 1;
      else hi = mid;
    }
    return lo + 1;
  };
  const re = /"((?:[^"\\]|\\.)*)"\s*:\s*\{/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(content)) !== null) {
    if (!index.has(m[1])) index.set(m[1], lineAt(m.index));
  }
  return index;
}

function packageNameFromLockKey(key: string): string | undefined {
  const idx = key.lastIndexOf(NODE_MODULES);
  if (idx >= 0) {
    const name = key.slice(idx + NODE_MODULES.length);
    return name.length > 0 ? name : undefined;
  }
  return undefined;
}

/**
 * Parses npm lockfiles: v2/v3 (`packages` map, preferred) and legacy v1
 * (nested `dependencies`). Entries without a version (workspace links) are
 * skipped because OSV needs an exact version to match advisories.
 */
export function parsePackageLock(content: string, file = 'package-lock.json'): Dependency[] {
  let doc: unknown;
  try {
    doc = JSON.parse(content);
  } catch (err) {
    const reason = err instanceof Error ? err.message : String(err);
    throw new Error(`Invalid ${file}: ${reason}`, { cause: err });
  }
  if (typeof doc !== 'object' || doc === null || Array.isArray(doc)) {
    throw new Error(`Invalid ${file}: expected a JSON object`);
  }
  const root = doc as Record<string, unknown>;
  const lineIndex = buildKeyLineIndex(content);
  const deps: Dependency[] = [];
  const seen = new Set<string>();

  const add = (name: string, version: string, line: number): void => {
    const key = `npm:${name}@${version}`;
    if (seen.has(key)) return;
    seen.add(key);
    deps.push({ name, version, ecosystem: 'npm', file, line });
  };

  if (typeof root.packages === 'object' && root.packages !== null) {
    for (const [key, raw] of Object.entries(root.packages as Record<string, unknown>)) {
      if (key === '') continue;
      const entry = (raw ?? {}) as Record<string, unknown>;
      const name =
        packageNameFromLockKey(key) ??
        (typeof entry.name === 'string' && entry.name ? entry.name : undefined);
      const version = typeof entry.version === 'string' ? entry.version : '';
      if (!name || !version) continue;
      add(name, version, lineIndex.get(key) ?? 1);
    }
    return deps;
  }

  if (typeof root.dependencies === 'object' && root.dependencies !== null) {
    const walk = (obj: Record<string, unknown>, depth: number): void => {
      if (depth > MAX_V1_DEPTH) return;
      for (const [name, raw] of Object.entries(obj)) {
        const entry = (raw ?? {}) as Record<string, unknown>;
        const version = typeof entry.version === 'string' ? entry.version : '';
        if (version) add(name, version, lineIndex.get(name) ?? 1);
        if (typeof entry.dependencies === 'object' && entry.dependencies !== null) {
          walk(entry.dependencies as Record<string, unknown>, depth + 1);
        }
      }
    };
    walk(root.dependencies as Record<string, unknown>, 0);
  }
  return deps;
}

const VERSION_RE = /^[0-9a-zA-Z][0-9a-zA-Z._+!*()~-]*$/;

/**
 * Parses pinned Python requirements (`name==version`). Unpinned specs
 * (`>=`, bare names), VCS/URL references and comments are skipped — OSV
 * needs an exact version to match an advisory reliably.
 */
export function parseRequirementsTxt(content: string, file = 'requirements.txt'): Dependency[] {
  const deps: Dependency[] = [];
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const withoutMarker = lines[i].split(';')[0];
    const eq = withoutMarker.indexOf('==');
    if (eq < 0) continue;
    let name = withoutMarker.slice(0, eq).trim();
    const bracket = name.indexOf('[');
    if (bracket >= 0) name = name.slice(0, bracket).trim();
    const version = (withoutMarker.slice(eq + 2).trim().split(/\s+/)[0] ?? '').replace(/^==+/, '');
    if (!name || !version || !VERSION_RE.test(version)) continue;
    if (name.startsWith('#')) continue;
    deps.push({ name, version, ecosystem: 'PyPI', file, line: i + 1 });
  }
  return deps;
}
