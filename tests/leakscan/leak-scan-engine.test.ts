import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';
import { scanRepo } from '../../src/modules/leakscan/leak-scan-engine.js';

let dir: string;

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), 'seginfo-leakscan-'));
});

afterEach(() => {
  fs.rmSync(dir, { recursive: true, force: true });
});

function write(rel: string, content: string): void {
  const p = path.join(dir, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content);
}

function git(...args: string[]): void {
  execFileSync('git', ['-C', dir, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
}

describe('working tree scan', () => {
  it('detects an AWS access key in a nested file with relative path and line', async () => {
    write('src/app/config.ts', 'const a = 1;\nconst key = "AKIA1234567890ABCDEF";\n');
    const findings = await scanRepo(dir, { gitHistory: false });
    const hit = findings.find((f) => f.type === 'aws-access-key');
    expect(hit).toBeDefined();
    expect(hit!.file).toBe('src/app/config.ts');
    expect(hit!.line).toBe(2);
    expect(hit!.source).toBe('working-tree');
  });

  it('detects a GitHub token with underscore form (ghp_...)', async () => {
    write('cfg.js', 'const t = "ghp_abcdef1234567890abcdef1234567890abcd";\n');
    const findings = await scanRepo(dir, { gitHistory: false });
    expect(findings.some((f) => f.type === 'github-token')).toBe(true);
  });

  it('detects a full three-segment JWT', async () => {
    write(
      'auth.py',
      'token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"\n',
    );
    const findings = await scanRepo(dir, { gitHistory: false });
    expect(findings.some((f) => f.type === 'jwt-token')).toBe(true);
  });

  it('detects database URLs with embedded credentials (any scheme)', async () => {
    write('db.yml', 'url: mysql://user:pass@db.example.com:3306/app\n');
    const findings = await scanRepo(dir, { gitHistory: false });
    expect(findings.some((f) => f.type === 'db-url-credentials')).toBe(true);
  });

  it('detects private key material', async () => {
    write('id_rsa', '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ...\n');
    const findings = await scanRepo(dir, { gitHistory: false });
    expect(findings.some((f) => f.type === 'private-key')).toBe(true);
  });

  it('detects a high-entropy value assigned to a secret keyword', async () => {
    write('app.js', 'const apiKey = "k8Xm2Pq9Rt4Wv7Yz1Nb6Cd3Fg5Hj";\n');
    const findings = await scanRepo(dir, { gitHistory: false });
    expect(findings.some((f) => f.type === 'hardcoded-credential')).toBe(true);
  });

  it('does NOT flag a low-entropy value assigned to a secret keyword', async () => {
    write('app.js', 'const apiKey = "AAAAAAAAAAAAAAAAAAAA";\n');
    const findings = await scanRepo(dir, { gitHistory: false });
    expect(findings).toHaveLength(0);
  });

  it('does NOT flag package-lock integrity hashes', async () => {
    write(
      'package-lock.json',
      '{\n "packages": {\n  "x": {\n   "integrity": "sha512-abcDEF1234567890abcdEF1234567890abCDEF1234567890abcdEF1234567890abCDEF1234567890="\n  }\n }\n}\n',
    );
    const findings = await scanRepo(dir, { gitHistory: false });
    expect(findings).toHaveLength(0);
  });

  it('does NOT flag a long hex digest without a secret keyword', async () => {
    write(
      'util.js',
      'const hash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";\n',
    );
    const findings = await scanRepo(dir, { gitHistory: false });
    expect(findings).toHaveLength(0);
  });

  it('does NOT flag a UUID', async () => {
    write('id.js', 'const id = "123e4567-e89b-12d3-a456-426614174000";\n');
    const findings = await scanRepo(dir, { gitHistory: false });
    expect(findings).toHaveLength(0);
  });

  it('does NOT flag github-token lookalikes embedded in base64 blobs', async () => {
    write(
      'lock.json',
      '{\n "a": "sha512-sSATRjPeDBg3pdgHoQfoYBob11Kk1FGa9lui5RIHZCoCkJa9QKlvl3/vKz2usCmYYjs7ymJR/2Nnsqe+Hjt5nw==",\n "b": "sha512-RHxMLp9lnKHGHRng9QFhRCMbYAcVpn69smSGcq3f36xjgVVWThj4qqLbTLlq7Ssj8B+fIQ1EuCEGI2lKsyQeIw=="\n}\n',
    );
    const findings = await scanRepo(dir, { gitHistory: false });
    expect(findings).toHaveLength(0);
  });

  it('skips node_modules and .git directories', async () => {
    write('node_modules/lib/secret.js', 'const k = "AKIA9999999999999999";\n');
    write('.git/hooks/helper.js', 'const k = "AKIA8888888888888888";\n');
    const findings = await scanRepo(dir, { gitHistory: false });
    expect(findings).toHaveLength(0);
  });

  it('reports one finding per file:line even with several patterns on the line', async () => {
    write('multi.js', 'const a = "AKIA1234567890ABCDEF" + "AKIA1234567890ABCDEF";\n');
    const findings = await scanRepo(dir, { gitHistory: false });
    expect(findings).toHaveLength(1);
  });

  it('accepts a glob pattern via options.cwd', async () => {
    write('src/a.ts', 'const k = "AKIA1234567890ABCDEF";\n');
    write('other/b.ts', 'const k = "AKIA0987654321ABCDEF";\n');
    const findings = await scanRepo('src/**/*.ts', { cwd: dir, gitHistory: false });
    expect(findings).toHaveLength(1);
    expect(findings[0].file).toBe('src/a.ts');
  });

  it('returns an empty list for a clean tree', async () => {
    write('clean.ts', 'export const answer = 42;\n');
    const findings = await scanRepo(dir, { gitHistory: false });
    expect(findings).toHaveLength(0);
  });
});

describe('git history scan', () => {
  it('detects a secret that was committed and later deleted', async () => {
    git('init', '-q');
    git('config', 'user.email', 'test@example.com');
    git('config', 'user.name', 'test');
    write('secrets.env', 'AWS_ACCESS=AKIA7777777777777777\n');
    git('add', '-A');
    git('commit', '-qm', 'add secret');
    fs.rmSync(path.join(dir, 'secrets.env'));

    const findings = await scanRepo(dir);
    const hist = findings.find((f) => f.source === 'git-history');
    expect(hist).toBeDefined();
    expect(hist!.file).toBe('secrets.env');
    expect(hist!.type).toBe('aws-access-key');
    expect(hist!.line).toBe(1);
    expect(hist!.commit).toMatch(/^[0-9a-f]{7,40}$/);
  });

  it('marks live findings as working-tree when the repo also has history', async () => {
    git('init', '-q');
    git('config', 'user.email', 'test@example.com');
    git('config', 'user.name', 'test');
    write('old.env', 'AWS_ACCESS=AKIA6666666666666666\n');
    git('add', '-A');
    git('commit', '-qm', 'add');
    fs.rmSync(path.join(dir, 'old.env'));
    write('live.ts', 'const k = "AKIA5555555555555555";\n');

    const findings = await scanRepo(dir);
    expect(findings.some((f) => f.source === 'git-history' && f.file === 'old.env')).toBe(true);
    expect(findings.some((f) => f.source === 'working-tree' && f.file === 'live.ts')).toBe(true);
  });

  it('does not throw on a directory that is not a git repository', async () => {
    write('app.js', 'const k = "AKIA4444444444444444";\n');
    const findings = await scanRepo(dir);
    expect(findings.some((f) => f.source === 'working-tree')).toBe(true);
    expect(findings.some((f) => f.source === 'git-history')).toBe(false);
  });

  it('does not scan .git objects as working-tree files', async () => {
    git('init', '-q');
    git('config', 'user.email', 'test@example.com');
    git('config', 'user.name', 'test');
    write('ok.txt', 'nothing to see\n');
    git('add', '-A');
    git('commit', '-qm', 'init');

    const findings = await scanRepo(dir, { gitHistory: false });
    expect(findings).toHaveLength(0);
  });
});
