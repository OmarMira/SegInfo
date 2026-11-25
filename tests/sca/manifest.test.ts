import { describe, expect, it } from 'vitest';
import { parsePackageLock, parseRequirementsTxt } from '../../src/modules/sca/manifest.js';

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
      { name: 'requests', version: '2.31.0', ecosystem: 'PyPI', file: 'requirements.txt', line: 2 },
      { name: 'pyyaml', version: '6.0.1', ecosystem: 'PyPI', file: 'requirements.txt', line: 5 },
      { name: 'requests', version: '2.19.0', ecosystem: 'PyPI', file: 'requirements.txt', line: 6 },
    ]);
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
