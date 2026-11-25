import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { runOrchestrator, type ModuleRunner } from '../../src/orchestrator/orchestrator.js';
import { DEFAULT_CONFIG, type ScanConfig } from '../../src/orchestrator/config.js';
import { NothingToScanError } from '../../src/util/errors.js';
import type { Finding } from '../../src/report/sarif.js';

let dir: string;
const outputs: string[] = [];

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'seginfo-orch-'));
});

afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
  for (const f of outputs.splice(0)) fs.rmSync(f, { force: true });
});

function makeConfig(overrides: Partial<ScanConfig> = {}): ScanConfig {
  return { ...DEFAULT_CONFIG, ...overrides };
}

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    ruleId: 'test/rule',
    message: 'test finding',
    file: 'src/app.ts',
    line: 1,
    column: 1,
    level: 'warning',
    ...overrides,
  };
}

function readSarif(outputPath: string): {
  runs: Array<{ tool: { driver: { name: string } }; results: unknown[] }>;
} {
  return JSON.parse(fs.readFileSync(outputPath, 'utf8'));
}

describe('runOrchestrator', () => {
  it('runs all enabled modules in parallel (each waits for the others to start)', async () => {
    let started = 0;
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    const rendezvous: ModuleRunner = async () => {
      started += 1;
      if (started === 3) release();
      await gate; // sequential execution would deadlock here and time out
      return [];
    };

    const result = await runOrchestrator(undefined, {
      cwd: dir,
      config: makeConfig(),
      runners: { leakscan: rendezvous, sca: rendezvous, iac: rendezvous },
    });
    expect(started).toBe(3);
    expect(result.exitCode).toBe(0);
  });

  it('merges findings from every module into one SARIF with a run per module', async () => {
    const config = makeConfig({ output: path.join(dir, 'merged.sarif') });
    outputs.push(config.output);
    const runners: Partial<Record<string, ModuleRunner>> = {
      leakscan: async () => [finding({ ruleId: 'leakscan/aws-access-key', file: 'a.ts' })],
      sca: async () => [finding({ ruleId: 'sca/GHSA-x', level: 'error', file: 'package-lock.json' })],
      iac: async () => [],
    };

    const result = await runOrchestrator(undefined, { cwd: dir, config, runners });

    expect(result.outputPath).toBe(path.resolve(config.output));
    const doc = readSarif(result.outputPath);
    expect(doc.runs).toHaveLength(3);
    expect(doc.runs.map((r) => r.tool.driver.name)).toEqual([
      'secure-scan/leakscan',
      'secure-scan/sca',
      'secure-scan/iac',
    ]);
    expect(doc.runs[0].results).toHaveLength(1);
    expect(doc.runs[1].results).toHaveLength(1);
    expect(doc.runs[2].results).toHaveLength(0);
    expect(result.exitCode).toBe(1); // error-level finding present
  });

  it('runs only the modules enabled by config', async () => {
    const called: string[] = [];
    const spy = (name: string): ModuleRunner => async () => {
      called.push(name);
      return [];
    };
    await runOrchestrator(undefined, {
      cwd: dir,
      config: makeConfig({ modules: ['leakscan'] }),
      runners: { leakscan: spy('leakscan'), sca: spy('sca'), iac: spy('iac') },
    });
    expect(called).toEqual(['leakscan']);
  });

  it('keeps other modules running when one fails, and reports the failure', async () => {
    const runners: Partial<Record<string, ModuleRunner>> = {
      leakscan: async () => [finding()],
      sca: async () => {
        throw new TypeError('OSV query failed: fetch failed');
      },
      iac: async () => [],
    };
    const result = await runOrchestrator(undefined, {
      cwd: dir,
      config: makeConfig(),
      runners,
    });
    expect(result.failures).toHaveLength(1);
    expect(result.failures[0].module).toBe('sca');
    expect(result.failures[0].message).toContain('OSV query failed');
    expect(result.totalFindings).toBe(1); // leakscan finding survived
    expect(result.exitCode).toBe(1); // failure never counts as clean
  });

  it('treats NothingToScanError as a skip, not a failure', async () => {
    const runners: Partial<Record<string, ModuleRunner>> = {
      leakscan: async () => [],
      sca: async () => {
        throw new NothingToScanError('No manifests found: SCA scanning needs package-lock.json');
      },
      iac: async () => {
        throw new NothingToScanError('No Terraform or Kubernetes files found under /x');
      },
    };
    const result = await runOrchestrator(undefined, {
      cwd: dir,
      config: makeConfig(),
      runners,
    });
    expect(result.failures).toHaveLength(0);
    expect(result.skipped.map((s) => s.module)).toEqual(['sca', 'iac']);
    expect(result.skipped[0].reason).toContain('manifests');
    expect(result.exitCode).toBe(0); // honest: the modules that ran were clean
    expect(readSarif(result.outputPath).runs).toHaveLength(1); // skipped modules have no run
  });

  it('fails when every module skips nothing... but writes an empty report', async () => {
    const runners: Partial<Record<string, ModuleRunner>> = {
      leakscan: async () => {
        throw new NothingToScanError('nothing to scan');
      },
      sca: async () => {
        throw new NothingToScanError('nothing to scan');
      },
      iac: async () => {
        throw new NothingToScanError('nothing to scan');
      },
    };
    const result = await runOrchestrator(undefined, {
      cwd: dir,
      config: makeConfig(),
      runners,
    });
    expect(result.exitCode).toBe(0);
    expect(result.totalFindings).toBe(0);
    expect(readSarif(result.outputPath).runs).toHaveLength(0);
  });

  it('applies failOn: note-only findings do not fail at the warning threshold', async () => {
    const runners: Partial<Record<string, ModuleRunner>> = {
      leakscan: async () => [finding({ level: 'note' })],
      sca: async () => [],
      iac: async () => [],
    };
    const atWarning = await runOrchestrator(undefined, {
      cwd: dir,
      config: makeConfig({ failOn: 'warning' }),
      runners,
    });
    expect(atWarning.exitCode).toBe(0);
    expect(atWarning.totalFindings).toBe(1); // still reported in SARIF

    const atNote = await runOrchestrator(undefined, {
      cwd: dir,
      config: makeConfig({ failOn: 'note' }),
      runners,
    });
    expect(atNote.exitCode).toBe(1);
  });

  it('fails at the error threshold only for error-level findings', async () => {
    const runners: Partial<Record<string, ModuleRunner>> = {
      leakscan: async () => [finding({ level: 'warning' })],
      sca: async () => [],
      iac: async () => [],
    };
    const result = await runOrchestrator(undefined, {
      cwd: dir,
      config: makeConfig({ failOn: 'error' }),
      runners,
    });
    expect(result.exitCode).toBe(0);

    const withError = await runOrchestrator(undefined, {
      cwd: dir,
      config: makeConfig({ failOn: 'error' }),
      runners: { ...runners, leakscan: async () => [finding({ level: 'error' })] },
    });
    expect(withError.exitCode).toBe(1);
  });

  it('filters findings matching ignore patterns before reporting', async () => {
    const config = makeConfig({ ignore: ['tests/**'], output: path.join(dir, 'ig.sarif') });
    outputs.push(config.output);
    const runners: Partial<Record<string, ModuleRunner>> = {
      leakscan: async () => [
        finding({ file: 'tests/fixture.test.ts' }),
        finding({ file: 'src/real.ts' }),
      ],
      sca: async () => [],
      iac: async () => [],
    };
    const result = await runOrchestrator(undefined, { cwd: dir, config, runners });
    expect(result.totalFindings).toBe(1);
    const doc = readSarif(result.outputPath);
    expect(doc.runs[0].results).toHaveLength(1);
    expect(result.exitCode).toBe(1);
  });

  it('rejects a non-directory target with a clear message', async () => {
    await expect(
      runOrchestrator('some/glob/*.ts', {
        cwd: dir,
        config: makeConfig(),
        runners: { leakscan: async () => [], sca: async () => [], iac: async () => [] },
      }),
    ).rejects.toThrow(/directory/);
  });

  it('uses the real leakscan engine through the default runner', async () => {
    fs.writeFileSync(path.join(dir, 'secret.ts'), 'const k = "AKIA1234567890ABCDEF";\n');
    const result = await runOrchestrator(undefined, {
      cwd: dir,
      config: makeConfig({ output: path.join(dir, 'real.sarif') }),
      runners: {
        sca: async () => [],
        iac: async () => [],
        // leakscan uses its real default runner
      },
    });
    expect(result.totalFindings).toBe(1);
    const doc = readSarif(result.outputPath);
    expect(doc.runs[0].tool.driver.name).toBe('secure-scan/leakscan');
    expect(doc.runs[0].results).toHaveLength(1);
  });
});
