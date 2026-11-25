import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { scanIac } from '../../src/modules/iac/iac-engine.js';

let dir: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'seginfo-iac-'));
});

afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

function write(rel: string, content: string): void {
  const p = path.join(dir, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content);
}

describe('scanIac', () => {
  it('discovers .tf and .yaml files recursively with relative paths', async () => {
    write(
      'infra/main.tf',
      'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n',
    );
    write(
      'k8s/app.yaml',
      'apiVersion: v1\nkind: Pod\nspec:\n  hostNetwork: true\n  containers:\n    - name: a\n      image: x\n',
    );
    write('src/app.ts', 'export const x = 1;\n');

    const findings = await scanIac(undefined, { cwd: dir });
    const files = findings.map((f) => f.file).sort();
    expect(files).toEqual(['infra/main.tf', 'k8s/app.yaml']);
  });

  it('skips node_modules and .git directories', async () => {
    write('node_modules/pkg/main.tf', 'acl = "public-read"\n');
    write('.git/hooks/x.yaml', 'kind: Pod\n  broken: [\n');
    write('ok.tf', 'resource "aws_s3_bucket" "b" {\n  acl = "private"\n}\n');

    const findings = await scanIac(undefined, { cwd: dir });
    expect(findings).toHaveLength(0);
  });

  it('throws a clear error when no IaC files exist', async () => {
    write('app.ts', 'export const x = 1;\n');
    await expect(scanIac(undefined, { cwd: dir })).rejects.toThrow(/Terraform or Kubernetes/);
  });

  it('reports invalid YAML with the offending file name', async () => {
    write('bad.yaml', 'kind: Pod\n  broken: [unclosed\n');
    await expect(scanIac(undefined, { cwd: dir })).rejects.toThrow(/bad\.yaml/);
  });

  it('skips Helm templates (go templating makes them invalid YAML)', async () => {
    write(
      'chart/templates/deploy.yaml',
      'apiVersion: v1\nkind: Deployment\nmetadata:\n  name: {{ .Release.Name }}\n',
    );
    await expect(scanIac(undefined, { cwd: dir })).rejects.toThrow(/were skipped/);
  });

  it('skips GitHub Actions workflows (${{ }} expressions) and says so honestly', async () => {
    write(
      '.github/workflows/ci.yml',
      'name: ci\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          token: ${{ github.token }}\n',
    );
    await expect(scanIac(undefined, { cwd: dir })).rejects.toThrow(/GitHub Actions/);
  });

  it('reports plain absence differently from template-only candidates', async () => {
    write('app.ts', 'export const x = 1;\n');
    await expect(scanIac(undefined, { cwd: dir })).rejects.toThrow(
      /No Terraform or Kubernetes files/,
    );
  });

  it('accepts an explicit file target', async () => {
    write('single.tf', 'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n');
    const findings = await scanIac(path.join(dir, 'single.tf'), { cwd: dir });
    expect(findings).toHaveLength(1);
    expect(findings[0].file).toBe('single.tf');
  });
});
