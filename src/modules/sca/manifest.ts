export type Ecosystem = 'npm' | 'PyPI';

/** Root manifest fields used to tell direct from transitive dependencies. */
export interface RootManifest {
  dependencies?: Record<string, unknown>;
  devDependencies?: Record<string, unknown>;
  optionalDependencies?: Record<string, unknown>;
  peerDependencies?: Record<string, unknown>;
}

/** One manifest location that pins a dependency. */
export interface DependencyLocation {
  file: string;
  line: number;
}

/** A pinned dependency extracted from a manifest file. */
export interface Dependency {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  /** Primary location (first by file/line); kept for existing consumers. */
  file: string;
  /** 1-based line of the primary location. */
  line: number;
  /** Every manifest location that pins this name@version. */
  locations: DependencyLocation[];
  /**
   * `true` when the root manifest resolves this installed instance directly,
   * `false` when it only arrives through another package, `null` when the
   * graph cannot tell.
   */
  direct: boolean | null;
  /** `true` when every path to it goes through dev dependencies, `null` when unknown. */
  dev: boolean | null;
  /** Immediate packages that require this one, as `name@version`. */
  introducedBy: string[];
  /** Introduction chains from the root, e.g. `next > undici` (display cap). */
  paths: string[];
  /** True when more chains exist than the ones listed in `paths`. */
  pathsTruncated: boolean;
  /** Exact number of introduction chains when fully enumerated, else `null`. */
  pathsTotal: number | null;
}

/** Chains rendered per dependency; the real total is reported separately. */
export const MAX_PATHS = 10;

/** Upper bound on enumerated chains per installed instance (keeps huge trees bounded). */
const MAX_PATH_ENUMERATION = 1_000;
/** Upper bound on traversal steps per installed instance. */
const MAX_PATH_STEPS = 20_000;
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

function asObject(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

/**
 * Names this entry installs. npm never installs a dependency's own
 * devDependencies, and a dependency's peerDependencies are satisfied by its
 * consumer, so those two only create edges at the project's root entry.
 */
function declaredNames(entry: Record<string, unknown>, isRoot: boolean): string[] {
  const names = [
    ...Object.keys(asObject(entry.dependencies)),
    ...Object.keys(asObject(entry.optionalDependencies)),
  ];
  if (isRoot) {
    names.push(...Object.keys(asObject(entry.devDependencies)));
    names.push(...Object.keys(asObject(entry.peerDependencies)));
  }
  return [...new Set(names)];
}

/** Production vs development names declared by the project. */
interface DeclaredSets {
  prod: Set<string>;
  dev: Set<string>;
}

/**
 * `package.json` wins over the lockfile's own root entry; `null` means there
 * is no evidence at all, so directness must stay unknown.
 */
function declaredSets(
  rootManifest: RootManifest | undefined,
  rootEntry: Record<string, unknown>,
): DeclaredSets | null {
  const source = (rootManifest ??
    (Object.keys(rootEntry).length > 0 ? rootEntry : undefined)) as
    | Record<string, unknown>
    | undefined;
  if (!source) return null;
  const prod = new Set([
    ...Object.keys(asObject(source.dependencies)),
    ...Object.keys(asObject(source.optionalDependencies)),
    ...Object.keys(asObject(source.peerDependencies)),
  ]);
  const dev = new Set(Object.keys(asObject(source.devDependencies)));
  // A root entry that only carries name/version proves nothing about
  // directness: without a declared dependency list the answer is unknown.
  if (prod.size === 0 && dev.size === 0) return null;
  return { prod, dev };
}

/** Every manifest location that pins the same `name@version` is kept. */
class DependencyMerger {
  private readonly entries = new Map<string, Dependency>();

  add(
    name: string,
    version: string,
    location: DependencyLocation,
    facts: {
      direct: boolean | null;
      dev: boolean | null;
      introducedBy: string[];
      pathResult: PathResult;
    },
  ): void {
    const key = `npm:${name}@${version}`;
    const existing = this.entries.get(key);
    if (!existing) {
      this.entries.set(key, {
        name,
        version,
        ecosystem: 'npm',
        file: location.file,
        line: location.line,
        locations: [{ ...location }],
        direct: facts.direct,
        dev: facts.dev,
        introducedBy: [...new Set(facts.introducedBy)].sort(),
        paths: [...facts.pathResult.paths],
        pathsTruncated: facts.pathResult.truncated,
        pathsTotal: facts.pathResult.total,
      });
      return;
    }

    if (!existing.locations.some((l) => l.file === location.file && l.line === location.line)) {
      existing.locations.push({ ...location });
    }

    // One direct instance is enough: the project declares that version.
    if (facts.direct === true) existing.direct = true;
    else if (facts.direct === false && existing.direct === null) existing.direct = false;

    // Production wins over development when both paths reach the same version.
    if (facts.dev === false) existing.dev = false;
    else if (facts.dev === true && existing.dev === null) existing.dev = true;

    existing.introducedBy = [
      ...new Set([...existing.introducedBy, ...facts.introducedBy]),
    ].sort();

    const merged = [...new Set([...existing.paths, ...facts.pathResult.paths])];
    existing.paths = merged.slice(0, MAX_PATHS);
    existing.pathsTruncated =
      existing.pathsTruncated || facts.pathResult.truncated || merged.length > MAX_PATHS;
    existing.pathsTotal =
      existing.pathsTotal === null || facts.pathResult.total === null
        ? null
        : existing.pathsTotal + facts.pathResult.total;
  }

  values(): Dependency[] {
    return [...this.entries.values()].map((dep) => {
      const locations = [...dep.locations].sort(
        (a, b) => a.file.localeCompare(b.file) || a.line - b.line,
      );
      return {
        ...dep,
        locations,
        file: locations[0]?.file ?? dep.file,
        line: locations[0]?.line ?? dep.line,
      };
    });
  }
}

/** One installed copy, keyed by its physical location in the tree. */
interface LockNode {
  key: string;
  name: string;
  version: string;
  /** Names this entry installs (npm resolution targets). */
  deps: string[];
  /** npm's own dev marker, when the lockfile provides it. */
  dev?: boolean;
  line: number;
}

/** Result of enumerating root to package chains for one installed copy. */
interface PathResult {
  paths: string[];
  /** Exact chain count when enumeration completed, `null` when it was bounded. */
  total: number | null;
  truncated: boolean;
}

/** Location of the package that owns `key` (`node_modules/a/node_modules/b` -> `node_modules/a`). */
function parentLocation(key: string): string {
  const marker = `/${NODE_MODULES}`;
  const idx = key.lastIndexOf(marker);
  return idx < 0 ? '' : key.slice(0, idx);
}

/**
 * npm resolution: look for `<location>/node_modules/<name>`, then walk one
 * level up until the root, so hoisted packages are found from nested ones.
 */
function resolveDependency(
  from: string,
  name: string,
  nodes: Map<string, LockNode>,
): string | undefined {
  let base = from;
  for (;;) {
    const candidate = base === '' ? `${NODE_MODULES}${name}` : `${base}/${NODE_MODULES}${name}`;
    if (nodes.has(candidate)) return candidate;
    if (base === '') return undefined;
    base = parentLocation(base);
  }
}

/**
 * Walks the full parent graph backwards from one installed copy and renders
 * every root chain it finds, up to the display cap. Nothing is dropped
 * silently: `total` carries the real count and `truncated` says whether the
 * rendered list is shorter than the graph.
 */
function enumerateChains(
  key: string,
  nodes: Map<string, LockNode>,
  parents: Map<string, Set<string>>,
): PathResult {
  const node = nodes.get(key);
  if (!node) return { paths: [], total: 0, truncated: false };

  const paths: string[] = [];
  let found = 0;
  let aborted = false;
  let steps = 0;

  const walk = (current: string, chain: string[], seen: Set<string>): void => {
    if (aborted) return;
    if (++steps > MAX_PATH_STEPS || found > MAX_PATH_ENUMERATION) {
      aborted = true;
      return;
    }
    const incoming = parents.get(current);
    if (!incoming || incoming.size === 0) return;
    for (const parentKey of incoming) {
      if (seen.has(parentKey)) continue; // circular dependency guard
      if (parentKey === '') {
        // A chain of one name is the direct dependency itself, not an
        // introduction path; `direct` already reports it.
        if (chain.length > 1) {
          found++;
          if (paths.length < MAX_PATHS) paths.push(chain.join(' > '));
        }
        continue;
      }
      const parent = nodes.get(parentKey);
      if (!parent) continue;
      seen.add(parentKey);
      walk(parentKey, [parent.name, ...chain], seen);
      seen.delete(parentKey);
      if (aborted) return;
    }
  };

  walk(key, [node.name], new Set([key]));
  return {
    paths,
    total: aborted ? null : found,
    truncated: aborted || found > paths.length,
  };
}

/**
 * Builds the dependency list from installed copies plus npm's hoisting rules.
 *
 * Directness is decided per installed copy (the exact location the root
 * resolves), never by name alone: `a@2.0.0` can be a direct dependency while
 * `a@1.0.0`, nested under another package, is transitive.
 */
function buildDependencies(
  nodes: Map<string, LockNode>,
  file: string,
  declared: DeclaredSets | null,
  directKnown: boolean,
): Dependency[] {
  const all = new Map(nodes);

  // A root node is required to derive chains. Lockfile v2/v3 ships one;
  // legacy v1 and hand-written fixtures do not, so synthesize it.
  const existingRoot = all.get('');
  const topLevel = [...all.values()].filter(
    (node) => node.key !== '' && parentLocation(node.key) === '',
  );
  const rootDeps =
    existingRoot && existingRoot.deps.length > 0
      ? existingRoot.deps
      : declared
        ? [...declared.prod, ...declared.dev]
        : topLevel.map((node) => node.name);
  const root: LockNode = existingRoot
    ? { ...existingRoot, deps: rootDeps }
    : { key: '', name: '', version: '', deps: rootDeps, line: 1 };
  all.set('', root);

  const edges = new Map<string, { to: string; name: string }[]>();
  const parents = new Map<string, Set<string>>();
  for (const node of all.values()) {
    for (const depName of node.deps) {
      const to = resolveDependency(node.key, depName, all);
      if (!to || to === node.key) continue;
      const list = edges.get(node.key) ?? [];
      if (list.some((edge) => edge.to === to)) continue;
      list.push({ to, name: depName });
      edges.set(node.key, list);
      const incoming = parents.get(to) ?? new Set<string>();
      incoming.add(node.key);
      parents.set(to, incoming);
    }
  }

  const directKeys = new Set((edges.get('') ?? []).map((edge) => edge.to));

  // Production reachability: a copy is production when at least one path from
  // the root uses only production-declared dependencies.
  const prodSeeds: string[] = [];
  for (const edge of edges.get('') ?? []) {
    const target = all.get(edge.to);
    if (!target || target.dev === true) continue;
    if (declared ? declared.prod.has(edge.name) : true) prodSeeds.push(edge.to);
  }
  const prodSeen = new Set(prodSeeds);
  const prodQueue = [...prodSeeds];
  while (prodQueue.length > 0) {
    const current = prodQueue.shift() as string;
    for (const edge of edges.get(current) ?? []) {
      const target = all.get(edge.to);
      if (!target || target.dev === true || prodSeen.has(edge.to)) continue;
      prodSeen.add(edge.to);
      prodQueue.push(edge.to);
    }
  }

  const reachable = new Set<string>(['']);
  const reachQueue = [''];
  while (reachQueue.length > 0) {
    const current = reachQueue.shift() as string;
    for (const edge of edges.get(current) ?? []) {
      if (reachable.has(edge.to)) continue;
      reachable.add(edge.to);
      reachQueue.push(edge.to);
    }
  }

  const devStatus = (node: LockNode): boolean | null => {
    // npm's own marker is direct evidence and wins over inference.
    if (node.dev === true) return true;
    if (declared) {
      if (prodSeen.has(node.key)) return false;
      if (reachable.has(node.key)) return true; // only reachable through dev paths
    }
    if (node.dev === false) return false;
    return null;
  };

  const merger = new DependencyMerger();
  for (const node of all.values()) {
    if (node.key === '') continue;
    const introducedBy = [...(parents.get(node.key) ?? [])]
      .filter((parentKey) => parentKey !== '')
      .map((parentKey) => all.get(parentKey))
      .filter((parent): parent is LockNode => Boolean(parent))
      .map((parent) => `${parent.name}@${parent.version}`);

    merger.add(
      node.name,
      node.version,
      { file, line: node.line },
      {
        direct: directKnown ? directKeys.has(node.key) : null,
        dev: devStatus(node),
        introducedBy,
        pathResult: enumerateChains(node.key, all, parents),
      },
    );
  }
  return merger.values();
}

/** Parses the `packages` map (lockfileVersion 2/3). */
function parsePackagesMap(
  packages: Record<string, unknown>,
  file: string,
  lineIndex: Map<string, number>,
  rootManifest: RootManifest | undefined,
): Dependency[] {
  const nodes = new Map<string, LockNode>();
  for (const [key, raw] of Object.entries(packages)) {
    const entry = asObject(raw);
    const isRoot = key === '';
    const name = isRoot
      ? ''
      : (packageNameFromLockKey(key) ?? (typeof entry.name === 'string' ? entry.name : ''));
    const version = isRoot ? '' : typeof entry.version === 'string' ? entry.version : '';
    if (!isRoot && (!name || !version)) continue; // workspace links have no version
    nodes.set(key, {
      key,
      name,
      version,
      deps: declaredNames(entry, isRoot),
      dev: typeof entry.dev === 'boolean' ? entry.dev : undefined,
      line: lineIndex.get(key) ?? 1,
    });
  }

  const declared = declaredSets(rootManifest, asObject(packages['']));
  const directKnown = declared !== null || (nodes.get('')?.deps.length ?? 0) > 0;
  return buildDependencies(nodes, file, declared, directKnown);
}

/** Rebuilds physical copies from a legacy v1 nested `dependencies` tree. */
function collectV1Nodes(
  root: Record<string, unknown>,
  lineIndex: Map<string, number>,
): Map<string, LockNode> {
  const nodes = new Map<string, LockNode>();
  const walk = (deps: Record<string, unknown>, prefix: string, depth: number): void => {
    if (depth > MAX_V1_DEPTH) return;
    for (const [name, raw] of Object.entries(deps)) {
      const entry = asObject(raw);
      const version = typeof entry.version === 'string' ? entry.version : '';
      const key = prefix === '' ? `${NODE_MODULES}${name}` : `${prefix}/${NODE_MODULES}${name}`;
      if (version) {
        nodes.set(key, {
          key,
          name,
          version,
          // v1 stores the declared relations in `requires`; the physical
          // nesting alone is not the dependency graph.
          deps: Object.keys(asObject(entry.requires)),
          dev: typeof entry.dev === 'boolean' ? entry.dev : undefined,
          line: lineIndex.get(name) ?? 1,
        });
      }
      walk(asObject(entry.dependencies), key, depth + 1);
    }
  };
  walk(asObject(root.dependencies), '', 0);
  return nodes;
}

/**
 * Parses npm lockfiles: v2/v3 (`packages` map, preferred) and legacy v1
 * (nested `dependencies` plus `requires`). Entries without a version
 * (workspace links) are skipped because OSV needs an exact version to match
 * advisories.
 *
 * `rootManifest` is the project's `package.json`, which is the authority for
 * telling direct from transitive dependencies; without it the root entry of
 * the lockfile is used, and when neither is available directness is unknown.
 */
export function parsePackageLock(
  content: string,
  file = 'package-lock.json',
  rootManifest?: RootManifest,
): Dependency[] {
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

  if (typeof root.packages === 'object' && root.packages !== null) {
    return parsePackagesMap(
      root.packages as Record<string, unknown>,
      file,
      lineIndex,
      rootManifest,
    );
  }
  if (typeof root.dependencies === 'object' && root.dependencies !== null) {
    const declared = declaredSets(rootManifest, {});
    return buildDependencies(
      collectV1Nodes(root, lineIndex),
      file,
      declared,
      declared !== null,
    );
  }
  return [];
}

const VERSION_RE = /^[0-9a-zA-Z][0-9a-zA-Z._+!*()~-]*$/;

/**
 * Parses pinned Python requirements (`name==version`). Unpinned specs
 * (`>=`, bare names), VCS/URL references and comments are skipped — OSV
 * needs an exact version to match an advisory reliably.
 *
 * The file alone cannot prove whether a pin is direct, transitive or
 * development-only (a `pip freeze` dump mixes all three), so those facts stay
 * `null` instead of being invented.
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
    deps.push({
      name,
      version,
      ecosystem: 'PyPI',
      file,
      line: i + 1,
      locations: [{ file, line: i + 1 }],
      direct: null,
      dev: null,
      introducedBy: [],
      paths: [],
      pathsTruncated: false,
      pathsTotal: null,
    });
  }
  return deps;
}
