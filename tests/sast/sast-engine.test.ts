import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { scanSast } from '../../src/modules/sast/sast-engine.js';
import { NothingToScanError } from '../../src/util/errors.js';

let workDir: string;

beforeAll(() => {
  workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'seginfo-sast-'));
  fs.mkdirSync(path.join(workDir, 'src'), { recursive: true });
  fs.mkdirSync(path.join(workDir, 'node_modules', 'pkg'), { recursive: true });
  fs.writeFileSync(
    path.join(workDir, 'src', 'app.ts'),
    'const q = db.query("SELECT * FROM t WHERE id = " + userId);\n',
  );
  fs.writeFileSync(path.join(workDir, 'src', 'script.py'), 'os.system(command)\n');
  fs.writeFileSync(
    path.join(workDir, 'node_modules', 'pkg', 'index.js'),
    'eval(userInput);\n',
  );
});

afterAll(() => {
  fs.rmSync(workDir, { recursive: true, force: true });
});

describe('sast engine', () => {
  it('scans a directory and reports relative posix paths', async () => {
    const findings = await scanSast(undefined, { cwd: workDir });
    expect(findings.map((f) => f.ruleId)).toContain('sast/sql-injection');
    expect(findings.map((f) => f.ruleId)).toContain('sast/command-injection');
    expect(findings.every((f) => !f.file.includes('\\'))).toBe(true);
    expect(findings.some((f) => f.file === 'src/app.ts')).toBe(true);
  });

  it('never scans node_modules', async () => {
    const findings = await scanSast(undefined, { cwd: workDir });
    expect(findings.some((f) => f.file.includes('node_modules'))).toBe(false);
  });

  it('accepts an explicit file target', async () => {
    const findings = await scanSast(path.join('src', 'app.ts'), { cwd: workDir });
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('sast/sql-injection');
  });

  it('throws NothingToScanError when there is no source to scan', async () => {
    const empty = fs.mkdtempSync(path.join(os.tmpdir(), 'seginfo-sast-empty-'));
    try {
      await expect(scanSast(undefined, { cwd: empty })).rejects.toBeInstanceOf(NothingToScanError);
    } finally {
      fs.rmSync(empty, { recursive: true, force: true });
    }
  });
});
