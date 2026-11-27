import { describe, expect, it } from 'vitest';
import { parsePackageLock, parseRequirementsTxt } from '../../src/modules/sca/manifest.js';

function indexByNameVersion(content: string, rootManifest?: Parameters<typeof parsePackageLock>[2]) {
  const deps = parsePackageLock(content, 'package-lock.json', rootManifest);
  return new Map(deps.map((dep) => [`${dep.name}@${dep.version}`, dep]));
}

describe('parsePackageLock', () => {
  it('parses lockfileVersion 3 (packages map), skipping the root entry', () => {
    const content = [
      '{',
      '  "name": "fixture",',
      '  "lockfileVersion": 3,',
      '  "packages": {',
      '    "": { "name": "fixture", "version": "1.0.0" },',
      '    "node_modules/lodash": { "version": "4.17.15" },',
      '    "node_modules/@babel/core": { "version": "7.20.0" },',
      '    "node_modules/a/node_modules/b": { "version": "1.2.3" }',
      '  }',
      '}',
    ].join('\n');
    const deps = parsePackageLock(content);
    expect(deps).toHaveLength(3);
    expect(deps[0]).toEqual({
      name: 'lodash',
      version: '4.17.15',
      ecosystem: 'npm',
      file: 'package-lock.json',
      line: 6,
      locations: [{ file: 'package-lock.json', line: 6 }],
      direct: null,
      dev: null,
      introducedBy: [],
      paths: [],
      pathsTruncated: false,
      pathsTotal: 0,
    });
    expect(deps.map((d) => d.name)).toEqual(['lodash', '@babel/core', 'b']);
    expect(deps[1].line).toBe(7);
    expect(deps[2].line).toBe(8);
  });

  it('parses legacy lockfileVersion 1 (nested dependencies)', () => {
    const content = [
      '{',
      '  "dependencies": {',
      '    "lodash": {',
      '      "version": "4.17.15"',
      '    }',
      '  }',
      '}',
    ].join('\n');
    const deps = parsePackageLock(content);
    expect(deps).toHaveLength(1);
    expect(deps[0].name).toBe('lodash');
    expect(deps[0].version).toBe('4.17.15');
    expect(deps[0].line).toBe(3);
  });

  it('skips entries without a version (link/workspace entries)', () => {
    const content = JSON.stringify({
      packages: {
        '': { name: 'root', version: '1.0.0' },
        'node_modules/link-pkg': { resolved: 'packages/link', link: true },
        'node_modules/real': { version: '2.0.0' },
      },
    });
    const deps = parsePackageLock(content);
    expect(deps.map((d) => d.name)).toEqual(['real']);
  });

  it('throws a clear error on invalid JSON', () => {
    expect(() => parsePackageLock('{ not json')).toThrow(/package-lock/);
  });

  // ERROR 01: directness is a property of the installed instance, not the name.
  it('separates a direct instance from a transitive copy of the same package', () => {
    const content = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': {
          name: 'fixture',
          version: '1.0.0',
          dependencies: { 'paquete-a': '^2.0.0', 'paquete-b': '^1.0.0' },
        },
        'node_modules/paquete-a': { version: '2.0.0' },
        'node_modules/paquete-b': {
          version: '1.0.0',
          dependencies: { 'paquete-a': '^1.0.0' },
        },
        'node_modules/paquete-b/node_modules/paquete-a': { version: '1.0.0' },
      },
    });
    const deps = indexByNameVersion(content);
    expect(deps.get('paquete-a@2.0.0')?.direct).toBe(true);
    expect(deps.get('paquete-a@1.0.0')?.direct).toBe(false);
    expect(deps.get('paquete-a@1.0.0')?.introducedBy).toEqual(['paquete-b@1.0.0']);
  });

  // ERROR 02: every introduction chain is preserved and truncation is explicit.
  it('keeps all introduction paths and reports when the display list is capped', () => {
    const packages: Record<string, unknown> = {
      '': {
        name: 'fixture',
        version: '1.0.0',
        dependencies: Object.fromEntries(
          Array.from({ length: 11 }, (_, i) => [`p${i}`, '^1.0.0']),
        ),
      },
      'node_modules/victima': { version: '1.0.0' },
    };
    for (let i = 0; i < 11; i++) {
      packages[`node_modules/p${i}`] = { version: '1.0.0', dependencies: { victima: '^1.0.0' } };
    }
    const deps = indexByNameVersion(JSON.stringify({ lockfileVersion: 3, packages }));
    const victima = deps.get('victima@1.0.0');
    expect(victima?.introducedBy).toHaveLength(11);
    expect(victima?.pathsTotal).toBe(11);
    expect(victima?.paths).toHaveLength(10);
    expect(victima?.pathsTruncated).toBe(true);
    expect(victima?.paths).toContain('p0 > victima');
  });

  it('keeps every path when two parents share the same child', () => {
    const content = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': { name: 'fixture', version: '1.0.0', dependencies: { a: '^1.0.0', b: '^1.0.0' } },
        'node_modules/a': { version: '1.0.0', dependencies: { c: '^1.0.0' } },
        'node_modules/b': { version: '1.0.0', dependencies: { c: '^1.0.0' } },
        'node_modules/c': { version: '1.0.0', dependencies: { victima: '^1.0.0' } },
        'node_modules/victima': { version: '1.0.0' },
      },
    });
    const deps = indexByNameVersion(content);
    const victima = deps.get('victima@1.0.0');
    expect(victima?.pathsTotal).toBe(2);
    expect(victima?.pathsTruncated).toBe(false);
    expect(victima?.paths).toEqual(['a > c > victima', 'b > c > victima']);
  });

  // ERROR 04: merging by name@version must not drop manifest locations.
  it('preserves every location when the same version is installed twice', () => {
    const content = JSON.stringify(
      {
        lockfileVersion: 3,
        packages: {
          '': {
            name: 'fixture',
            version: '1.0.0',
            dependencies: { x: '^1.0.0', dup: '^1.0.0' },
          },
          'node_modules/dup': { version: '1.0.0' },
          'node_modules/x': { version: '1.0.0', dependencies: { dup: '^1.0.0' } },
          'node_modules/x/node_modules/dup': { version: '1.0.0' },
        },
      },
      null,
      2,
    );
    const deps = indexByNameVersion(content);
    const dup = deps.get('dup@1.0.0');
    expect(dup?.locations).toHaveLength(2);
    expect(dup?.locations[0].line).not.toBe(dup?.locations[1].line);
    expect(dup?.direct).toBe(true);
  });

  // ERROR 05: root devDependencies create real edges, so dev paths exist.
  it('walks root devDependencies and marks their subtree as development', () => {
    const content = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        '': {
          name: 'fixture',
          version: '1.0.0',
          dependencies: { prod: '^1.0.0' },
          devDependencies: { jest: '^29.0.0' },
        },
        'node_modules/prod': { version: '1.0.0' },
        'node_modules/jest': {
          version: '29.0.0',
          dev: true,
          dependencies: { 'jest-cli': '^29.0.0' },
        },
        'node_modules/jest-cli': { version: '29.0.0', dev: true },
      },
    });
    const deps = indexByNameVersion(content);
    expect(deps.get('jest@29.0.0')?.direct).toBe(true);
    expect(deps.get('jest@29.0.0')?.dev).toBe(true);
    expect(deps.get('jest-cli@29.0.0')?.direct).toBe(false);
    expect(deps.get('jest-cli@29.0.0')?.dev).toBe(true);
    expect(deps.get('jest-cli@29.0.0')?.paths).toEqual(['jest > jest-cli']);
    expect(deps.get('prod@1.0.0')?.dev).toBe(false);
  });

  // ERROR 05 (legacy): v1 stores relations in `requires`, not only nesting.
  it('rebuilds v1 relations from requires instead of physical nesting alone', () => {
    const content = JSON.stringify({
      dependencies: {
        a: { version: '1.0.0', requires: { b: '^1.0.0' } },
        b: { version: '1.0.5' },
      },
    });
    const deps = indexByNameVersion(content, { dependencies: { a: '^1.0.0' } });
    expect(deps.get('a@1.0.0')?.direct).toBe(true);
    expect(deps.get('b@1.0.5')?.direct).toBe(false);
    expect(deps.get('b@1.0.5')?.introducedBy).toEqual(['a@1.0.0']);
    expect(deps.get('b@1.0.5')?.paths).toEqual(['a > b']);
  });

  it('leaves directness unknown when the v1 lockfile has no root manifest', () => {
    const content = JSON.stringify({
      dependencies: { a: { version: '1.0.0', requires: { b: '^1.0.0' } }, b: { version: '1.0.5' } },
    });
    const deps = indexByNameVersion(content);
    expect(deps.get('a@1.0.0')?.direct).toBeNull();
    expect(deps.get('b@1.0.5')?.direct).toBeNull();
    expect(deps.get('b@1.0.5')?.paths).toEqual(['a > b']);
  });
});

describe('parseRequirementsTxt', () => {
  const content = [
    '# comment line',
    'requests==2.31.0',
    '',
    'flask>=2.0',
    'pyyaml==6.0.1 ; python_version >= "3.8"',
    'requests[security]==2.19.0',
    'git+https://github.com/x/y.git',
    'numpy',
  ].join('\n');

  it('extracts pinned versions with exact line numbers', () => {
    const deps = parseRequirementsTxt(content);
    expect(deps).toEqual([
      {
        name: 'requests',
        version: '2.31.0',
        ecosystem: 'PyPI',
        file: 'requirements.txt',
        line: 2,
        locations: [{ file: 'requirements.txt', line: 2 }],
        direct: null,
        dev: null,
        introducedBy: [],
        paths: [],
        pathsTruncated: false,
        pathsTotal: null,
      },
      {
        name: 'pyyaml',
        version: '6.0.1',
        ecosystem: 'PyPI',
        file: 'requirements.txt',
        line: 5,
        locations: [{ file: 'requirements.txt', line: 5 }],
        direct: null,
        dev: null,
        introducedBy: [],
        paths: [],
        pathsTruncated: false,
        pathsTotal: null,
      },
      {
        name: 'requests',
        version: '2.19.0',
        ecosystem: 'PyPI',
        file: 'requirements.txt',
        line: 6,
        locations: [{ file: 'requirements.txt', line: 6 }],
        direct: null,
        dev: null,
        introducedBy: [],
        paths: [],
        pathsTruncated: false,
        pathsTotal: null,
      },
    ]);
  });

  // ERROR 03: a requirements file cannot prove directness or dev-only usage.
  it('never invents direct or production status for Python pins', () => {
    const deps = parseRequirementsTxt('requests==2.31.0\n');
    expect(deps[0].direct).toBeNull();
    expect(deps[0].dev).toBeNull();
  });

  it('skips comments, blanks, unpinned requirements, VCS urls and extras markers', () => {
    const deps = parseRequirementsTxt(content);
    const names = deps.map((d) => `${d.name}@${d.version}`);
    expect(names).not.toContain('flask@>=2.0');
    expect(names).not.toContain('numpy@');
    expect(names.every((n) => !n.startsWith('git+'))).toBe(true);
  });

  it('returns an empty list for a comment-only file', () => {
    expect(parseRequirementsTxt('# nothing\n\n')).toEqual([]);
  });
});
