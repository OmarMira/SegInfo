import { beforeAll, describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync, execSync } from 'node:child_process';

/**
 * End-to-end tests that run the compiled artifact (dist/cli.js) — the same
 * binary the GitHub Action and `npm run scan:ci` execute.
 */

const ROOT = path.resolve(__dirname, '../..');
const CLI = path.join(ROOT, 'dist', 'cli.js');
const OUTPUT = 'seginfo-secure-scan-results.sarif';

interface CliResult {
  code: number;
  stdout: string;
  stderr: string;
}

function runCli(args: string[], cwd: string): CliResult {
  try {
    const stdout = execFileSync('node', [CLI, ...args], {
      cwd,
      encoding: 'utf8',
      timeout: 60_000,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { code: 0, stdout, stderr: '' };
  } catch (err) {
    const e = err as { status?: number | null; code?: number | string; stdout?: string; stderr?: string };
    const code =
      typeof e.status === 'number'
        ? e.status
        : typeof e.code === 'number'
          ? e.code
          : -1;
    return { code, stdout: e.stdout ?? '', stderr: e.stderr ?? '' };
  }
}

function tmpDir(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'seginfo-cli-'));
}

function write(dir: string, rel: string, content: string): void {
  const p = path.join(dir, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content);
}

function readSarif(dir: string, name = OUTPUT): ReturnType<typeof JSON.parse> {
  return JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8'));
}

beforeAll(() => {
  // The integration suite always exercises a freshly built artifact.
  execSync('npm run build', { cwd: ROOT, stdio: 'ignore', timeout: 180_000 });
}, 240_000);

describe('secure-scan CLI (compiled artifact)', () => {
  it('prints help and exits 0', () => {
    const result = runCli(['--help'], ROOT);
    expect(result.code).toBe(0);
    expect(result.stdout).toContain('Modular security scanner');
    expect(result.stdout).toContain('all');
  });

  it('rejects an unknown mode with exit 1', () => {
    const dir = tmpDir();
    try {
      const result = runCli(['--mode', 'fuzzing'], dir);
      expect(result.code).toBe(1);
      expect(result.stderr).toContain('Unknown mode: fuzzing');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('leakscan: clean tree → exit 0 with an explicit clean message', () => {
    const dir = tmpDir();
    try {
      write(dir, 'app.ts', 'export const answer = 42;\n');
      const result = runCli(['--mode', 'leakscan', '--files', '.'], dir);
      expect(result.code).toBe(0);
      expect(result.stdout).toContain('No secrets detected');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('leakscan: finds a secret, exits 1, never prints the raw secret value', () => {
    const dir = tmpDir();
    try {
      const secret = 'AKIA1234567890ABCDEF';
      write(dir, 'conf.ts', `const key = "${secret}";\n`);
      const result = runCli(['--mode', 'leakscan', '--files', '.'], dir);

      expect(result.code).toBe(1);
      expect(result.stdout).toContain('leakscan/aws-access-key');
      // The secret must not leak through any channel, incl. the SARIF file.
      expect(result.stdout).not.toContain(secret);
      expect(result.stderr).not.toContain(secret);

      const doc = readSarif(dir);
      const serialized = JSON.stringify(doc);
      expect(serialized).not.toContain(secret);
      expect(doc.runs[0].tool.driver.name).toBe('secure-scan/leakscan');
      expect(doc.runs[0].results).toHaveLength(1);
      expect(doc.runs[0].results[0].level).toBe('warning');
      expect(doc.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri).toBe(
        'conf.ts',
      );
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('sca: fails loudly (exit 1) when no manifest exists — never a fake clean scan', () => {
    const dir = tmpDir();
    try {
      write(dir, 'app.ts', 'export const x = 1;\n');
      const result = runCli(['--mode', 'sca'], dir);
      expect(result.code).toBe(1);
      expect(result.stderr).toMatch(/manifest/i);
      expect(result.stdout).not.toContain('No vulnerable dependencies');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('iac: fails loudly (exit 1) when no IaC files exist', () => {
    const dir = tmpDir();
    try {
      write(dir, 'app.ts', 'export const x = 1;\n');
      const result = runCli(['--mode', 'iac'], dir);
      expect(result.code).toBe(1);
      expect(result.stderr).toContain('No Terraform or Kubernetes files');
      expect(result.stdout).not.toContain('No IaC misconfigurations');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('all: merges module runs into one SARIF and exits by severity', () => {
    const dir = tmpDir();
    try {
      write(dir, 'secret.ts', 'const k = "AKIA1234567890ABCDEF";\n');
      write(dir, 'infra/main.tf', 'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n');
      write(dir, 'secure-scan.config.json', JSON.stringify({ output: 'merged.sarif' }));

      const result = runCli(['--mode', 'all', '--files', '.'], dir);
      expect(result.code).toBe(1);
      expect(result.stdout).toContain('leakscan/aws-access-key');
      expect(result.stdout).toContain('iac/s3-public-acl');
      expect(result.stdout).toContain('skipped'); // sca has no manifest here

      const doc = readSarif(dir, 'merged.sarif');
      const names = doc.runs.map((r: { tool: { driver: { name: string } } }) => r.tool.driver.name);
      expect(names).toContain('secure-scan/leakscan');
      expect(names).toContain('secure-scan/iac');
      const total = doc.runs.reduce(
        (n: number, r: { results: unknown[] }) => n + r.results.length,
        0,
      );
      expect(total).toBeGreaterThanOrEqual(2);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('differential: the leakscan-only run reports a subset of the all-mode report', () => {
    const dir = tmpDir();
    try {
      write(dir, 'secret.ts', 'const k = "AKIA1234567890ABCDEF";\n');
      write(dir, 'infra/main.tf', 'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n');
      write(dir, 'secure-scan.config.json', JSON.stringify({ output: 'merged.sarif' }));

      const single = runCli(['--mode', 'leakscan', '--files', '.'], dir);
      const singleDoc = readSarif(dir);
      expect(single.code).toBe(1);

      const merged = runCli(['--mode', 'all', '--files', '.'], dir);
      const mergedDoc = readSarif(dir, 'merged.sarif');
      expect(merged.code).toBe(1);

      const key = (r: { ruleId: string; locations: Array<{ physicalLocation: { artifactLocation: { uri: string }; region: { startLine: number } } }> }) =>
        `${r.ruleId}@${r.locations[0].physicalLocation.artifactLocation.uri}:${r.locations[0].physicalLocation.region.startLine}`;

      const singleKeys = (singleDoc.runs[0].results as Array<Parameters<typeof key>[0]>).map(key);
      const mergedLeakscan = mergedDoc.runs.find(
        (r: { tool: { driver: { name: string } } }) => r.tool.driver.name === 'secure-scan/leakscan',
      );
      const mergedKeys = (mergedLeakscan.results as Array<Parameters<typeof key>[0]>).map(key);

      expect(singleKeys.length).toBeGreaterThan(0);
      // Every single-mode finding must appear identically in the merged run:
      // switching modes may add findings, never lose or relocate them.
      for (const k of singleKeys) expect(mergedKeys).toContain(k);
      // The merged report as a whole carries strictly more (the IaC finding).
      const mergedTotal = mergedDoc.runs.reduce(
        (n: number, r: { results: unknown[] }) => n + r.results.length,
        0,
      );
      expect(mergedTotal).toBeGreaterThan(singleKeys.length);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('all: respects failOn from the config file', () => {
    const dir = tmpDir();
    try {
      write(dir, 'secret.ts', 'const k = "AKIA1234567890ABCDEF";\n');
      write(dir, 'secure-scan.config.json', JSON.stringify({ failOn: 'error' }));

      // leakscan only produces warning-level findings → below the threshold.
      const result = runCli(['--mode', 'all', '--files', '.'], dir);
      expect(result.code).toBe(0);
      expect(result.stdout).toContain('finding(s)'); // still reported honestly

      const doc = readSarif(dir);
      expect(doc.runs[0].results).toHaveLength(1); // present in the SARIF
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
