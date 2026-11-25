import { describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { loadConfig, parseConfig, DEFAULT_CONFIG } from '../../src/orchestrator/config.js';

let dir: string;

function tmpDir(): string {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'seginfo-config-'));
  return dir;
}

function cleanup(): void {
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
}

describe('parseConfig', () => {
  it('returns defaults for an empty object', () => {
    expect(parseConfig({})).toEqual(DEFAULT_CONFIG);
  });

  it('accepts a fully specified valid config', () => {
    const config = parseConfig({
      modules: ['leakscan', 'iac'],
      output: 'out/scan.sarif',
      failOn: 'error',
      ignore: ['tests/**', '**/*.test.ts'],
    });
    expect(config.modules).toEqual(['leakscan', 'iac']);
    expect(config.output).toBe('out/scan.sarif');
    expect(config.failOn).toBe('error');
    expect(config.ignore).toEqual(['tests/**', '**/*.test.ts']);
  });

  it('rejects unknown modules with the allowed values in the message', () => {
    expect(() => parseConfig({ modules: ['leakscan', 'fuzzing'] })).toThrow(/leakscan/);
    expect(() => parseConfig({ modules: ['fuzzing'] })).toThrow(/iac/);
  });

  it('rejects an empty module list', () => {
    expect(() => parseConfig({ modules: [] })).toThrow(/modules/);
  });

  it('rejects an invalid failOn threshold', () => {
    expect(() => parseConfig({ failOn: 'fatal' })).toThrow(/failOn/);
  });

  it('rejects non-array ignore entries', () => {
    expect(() => parseConfig({ ignore: 'tests/**' })).toThrow(/ignore/);
  });

  it('rejects malformed JSON types (e.g. modules as string)', () => {
    expect(() => parseConfig({ modules: 'leakscan' })).toThrow(/modules/);
  });
});

describe('loadConfig', () => {
  it('returns defaults when no config file exists', async () => {
    const cwd = tmpDir();
    try {
      expect(loadConfig({ cwd })).toEqual(DEFAULT_CONFIG);
    } finally {
      cleanup();
    }
  });

  it('loads secure-scan.config.json from the scan directory', async () => {
    const cwd = tmpDir();
    try {
      fs.writeFileSync(
        path.join(cwd, 'secure-scan.config.json'),
        JSON.stringify({ modules: ['sca'], failOn: 'note' }),
      );
      const config = loadConfig({ cwd });
      expect(config.modules).toEqual(['sca']);
      expect(config.failOn).toBe('note');
      expect(config.output).toBe(DEFAULT_CONFIG.output);
    } finally {
      cleanup();
    }
  });

  it('honors an explicit config path outside the scan directory', async () => {
    const cwd = tmpDir();
    try {
      const external = path.join(cwd, 'custom.json');
      fs.writeFileSync(external, JSON.stringify({ output: 'custom.sarif' }));
      const config = loadConfig({ cwd: path.join(cwd, 'nested'), configPath: external });
      expect(config.output).toBe('custom.sarif');
    } finally {
      cleanup();
    }
  });

  it('throws when the explicit config path does not exist', async () => {
    const cwd = tmpDir();
    try {
      expect(() => loadConfig({ cwd, configPath: path.join(cwd, 'missing.json') })).toThrow(
        /missing\.json/,
      );
    } finally {
      cleanup();
    }
  });

  it('reports the file name on malformed JSON', async () => {
    const cwd = tmpDir();
    try {
      fs.writeFileSync(path.join(cwd, 'secure-scan.config.json'), '{ not json');
      expect(() => loadConfig({ cwd })).toThrow(/secure-scan\.config\.json/);
    } finally {
      cleanup();
    }
  });

  it('reports validation issues on an invalid config file', async () => {
    const cwd = tmpDir();
    try {
      fs.writeFileSync(
        path.join(cwd, 'secure-scan.config.json'),
        JSON.stringify({ failOn: 'catastrophe' }),
      );
      expect(() => loadConfig({ cwd })).toThrow(/failOn/);
    } finally {
      cleanup();
    }
  });
});
