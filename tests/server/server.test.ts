import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';
import { startServer, type RunningServer } from '../../src/server/app.js';

const SARIF_NAME = 'seginfo-secure-scan-results.sarif';

let running: RunningServer;
let workDir: string;
let headerServer: http.Server;
let headerPort: number;

function rawRequest(
  port: number,
  pathname: string,
  method: string,
  headers: Record<string, string> = {},
  body = '',
): Promise<{ status: number; headers: http.IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const req = http.request(
      { host: '127.0.0.1', port, path: pathname, method, headers },
      (res) => {
        let data = '';
        res.setEncoding('utf8');
        res.on('data', (chunk: string) => (data += chunk));
        res.on('end', () => resolve({ status: res.statusCode ?? 0, headers: res.headers, body: data }));
      },
    );
    req.on('error', reject);
    req.end(body);
  });
}

function postScan(body: unknown, extraHeaders: Record<string, string> = {}): Promise<Response> {
  return fetch(`${running.url}/api/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...extraHeaders },
    body: JSON.stringify(body),
  });
}

beforeAll(async () => {
  workDir = fs.mkdtempSync(path.join(os.tmpdir(), 'seginfo-server-'));
  running = await startServer({ port: 0, cwd: workDir });

  headerServer = http.createServer((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    res.end('OK');
  });
  await new Promise<void>((resolve) => headerServer.listen(0, '127.0.0.1', () => resolve()));
  const address = headerServer.address();
  if (address === null || typeof address === 'string') throw new Error('no test server port');
  headerPort = address.port;
});

afterAll(async () => {
  await running.close();
  await new Promise<void>((resolve) => headerServer.close(() => resolve()));
  fs.rmSync(workDir, { recursive: true, force: true });
});

describe('local server: UI and health', () => {
  it('serves the single-page UI with a lockdown CSP', async () => {
    const res = await fetch(`${running.url}/`);
    expect(res.status).toBe(200);
    expect(res.headers.get('content-type')).toContain('text/html');
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    const csp = res.headers.get('content-security-policy') ?? '';
    expect(csp).toContain("default-src 'none'");
    expect(csp).toContain("frame-ancestors 'none'");
    const html = await res.text();
    expect(html).toContain('SegInfo Secure Scan');
    expect(html).toContain('/api/scan');
  });

  it('reports health and available modes', async () => {
    const res = await fetch(`${running.url}/api/health`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { ok: boolean; modes: string[] };
    expect(body.ok).toBe(true);
    expect(body.modes).toContain('web');
  });

  it('rejects unknown routes with 404', async () => {
    const res = await fetch(`${running.url}/nope`);
    expect(res.status).toBe(404);
  });
});

describe('local server: request hardening', () => {
  it('rejects non-POST on /api/scan', async () => {
    const res = await fetch(`${running.url}/api/scan`);
    expect(res.status).toBe(405);
  });

  it('requires application/json', async () => {
    const res = await fetch(`${running.url}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain' },
      body: '{}',
    });
    expect(res.status).toBe(415);
  });

  it('rejects invalid JSON with 400', async () => {
    const res = await fetch(`${running.url}/api/scan`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{not json',
    });
    expect(res.status).toBe(400);
  });

  it('rejects unknown modes with 400', async () => {
    const res = await postScan({ mode: 'rootkit', target: '.' });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toContain('Unknown mode');
  });

  it('rejects bodies over 64 KiB with 413', async () => {
    const res = await postScan({ mode: 'all', target: 'x'.repeat(70 * 1024) });
    expect(res.status).toBe(413);
  });

  it('rejects cross-origin browser calls with 403', async () => {
    const res = await postScan({ mode: 'all' }, { Origin: 'https://evil.example' });
    expect(res.status).toBe(403);
  });

  it('rejects a non-loopback Host header (DNS rebinding guard)', async () => {
    const res = await rawRequest(running.port, '/api/health', 'GET', {
      host: `evil.example:${running.port}`,
    });
    expect(res.status).toBe(403);
    expect(res.body).toContain('Host not allowed');
  });
});

describe('local server: folder picker', () => {
  it('lists filesystem roots when no path is given', async () => {
    const res = await fetch(`${running.url}/api/browse`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as { path: string | null; parent: string | null; entries: { name: string; path: string }[] };
    expect(body.path).toBeNull();
    expect(Array.isArray(body.entries)).toBe(true);
    expect(body.entries.length).toBeGreaterThan(0);
  });

  it('lists only subdirectories of a requested folder', async () => {
    fs.mkdirSync(path.join(workDir, 'subfolder'), { recursive: true });
    fs.writeFileSync(path.join(workDir, 'file.txt'), 'x');
    const res = await fetch(`${running.url}/api/browse?path=${encodeURIComponent(workDir)}`);
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      path: string;
      parent: string | null;
      entries: { name: string; path: string }[];
    };
    expect(body.path).toBe(workDir);
    expect(body.parent).not.toBeNull();
    expect(body.entries.map((e) => e.name)).toContain('subfolder');
    expect(body.entries.map((e) => e.name)).not.toContain('file.txt');
  });

  it('rejects a file path with 400', async () => {
    const file = path.join(workDir, 'file.txt');
    const res = await fetch(`${running.url}/api/browse?path=${encodeURIComponent(file)}`);
    expect(res.status).toBe(400);
  });

  it('rejects a missing folder with 404', async () => {
    const missing = path.join(workDir, 'does-not-exist');
    const res = await fetch(`${running.url}/api/browse?path=${encodeURIComponent(missing)}`);
    expect(res.status).toBe(404);
  });

  it('rejects non-GET methods with 405', async () => {
    const res = await fetch(`${running.url}/api/browse`, { method: 'POST' });
    expect(res.status).toBe(405);
  });
});

describe('local server: scans', () => {
  it('scans the working directory without writing a SARIF file', async () => {
    const res = await postScan({ mode: 'all' });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      findings: unknown[];
      skipped: { module: string; reason: string }[];
      target: string;
    };
    expect(body.findings).toEqual([]);
    expect(body.skipped.length).toBeGreaterThan(0);
    expect(body.target).toBe(workDir);
    expect(fs.existsSync(path.join(workDir, SARIF_NAME))).toBe(false);
  });

  it('reports provenance for a local scan without inventing a commit', async () => {
    const res = await postScan({ mode: 'all' });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      sca?: unknown;
      provenance: {
        origin: string;
        source: string;
        commit: string | null;
        ref: string | null;
        scannedAt: string;
        scope: {
          workingTree: boolean;
          gitHistory: boolean;
          history: { attempted: boolean; gitRepository: boolean } | null;
          manifests: string[];
        };
        vulnerabilityData: unknown;
      };
    };
    expect(body.provenance.origin).toBe('local-path');
    expect(body.provenance.source).toBe(workDir);
    expect(body.provenance.commit).toBeNull();
    expect(body.provenance.ref).toBeNull();
    expect(body.provenance.scannedAt).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    expect(body.provenance.scope.workingTree).toBe(true);
    expect(body.provenance.scope.history).toMatchObject({
      attempted: true,
      gitRepository: false,
    });
    // SCA was skipped (no manifest), so there is no grouped view and no
    // vulnerability-data claim.
    expect(body.sca).toBeUndefined();
    expect(body.provenance.vulnerabilityData).toBeNull();
  });

  it('flags a public Terraform bucket through the iac mode', async () => {
    const iacDir = fs.mkdtempSync(path.join(os.tmpdir(), 'seginfo-server-iac-'));
    fs.writeFileSync(
      path.join(iacDir, 'main.tf'),
      'resource "aws_s3_bucket" "public" {\n  bucket = "demo"\n  acl    = "public-read"\n}\n',
    );
    try {
      const res = await postScan({ mode: 'iac', target: iacDir });
      expect(res.status).toBe(200);
      const body = (await res.json()) as { findings: { ruleId: string; level: string }[] };
      expect(body.findings.length).toBeGreaterThan(0);
      expect(body.findings.some((f) => f.ruleId.startsWith('iac/'))).toBe(true);
      expect(fs.existsSync(path.join(iacDir, SARIF_NAME))).toBe(false);
    } finally {
      fs.rmSync(iacDir, { recursive: true, force: true });
    }
  });

  it('flags source sinks through the sast mode', async () => {
    const sastDir = fs.mkdtempSync(path.join(os.tmpdir(), 'seginfo-server-sast-'));
    fs.writeFileSync(path.join(sastDir, 'app.js'), 'el.innerHTML = userInput;\n');
    try {
      const res = await postScan({ mode: 'sast', target: sastDir });
      expect(res.status).toBe(200);
      const body = (await res.json()) as { findings: { ruleId: string }[] };
      expect(body.findings.some((f) => f.ruleId === 'sast/xss-innerhtml')).toBe(true);
    } finally {
      fs.rmSync(sastDir, { recursive: true, force: true });
    }
  });

  it('triages test-path findings as likely examples (without hiding them)', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'seginfo-server-triage-'));
    fs.mkdirSync(path.join(dir, 'tests'), { recursive: true });
    fs.writeFileSync(path.join(dir, 'tests', 'app.js'), 'el.innerHTML = userInput;\n');
    try {
      const res = await postScan({ mode: 'sast', target: dir });
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        findings: { properties?: { triage?: { bucket: string } } }[];
        triage: {
          summary: { likelyExample: number; total: number };
          groups: { bucket: string; reason: string; why: string; fix: string; nextStep: string }[];
        };
      };
      expect(body.triage.summary.total).toBe(1);
      expect(body.triage.summary.likelyExample).toBe(1);
      expect(body.triage.groups[0].bucket).toBe('likely-example');
      expect(body.triage.groups[0].reason).toContain('tests');
      expect(body.triage.groups[0].why).toContain('sink HTML');
      expect(body.triage.groups[0].fix).toContain('textContent');
      expect(body.triage.groups[0].nextStep).toContain('tests');
      expect(body.findings[0].properties?.triage?.bucket).toBe('likely-example');
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it('requires a repository URL for the repo mode', async () => {
    const res = await postScan({ mode: 'repo', target: '' });
    expect(res.status).toBe(400);
  });

  it('clones a repository, ignores its config, scans it and always cleans up', async () => {
    const cloneRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'seginfo-clone-'));
    const repoDir = path.join(cloneRoot, 'repo');
    fs.mkdirSync(repoDir, { recursive: true });
    fs.writeFileSync(
      path.join(repoDir, 'main.tf'),
      'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n',
    );
    // A cloned repository must not be able to disable modules via its config.
    fs.writeFileSync(
      path.join(repoDir, 'secure-scan.config.json'),
      JSON.stringify({ modules: ['leakscan'] }),
    );

    let cleaned = false;
    const repoServer = await startServer({
      port: 0,
      clone: async () => ({
        dir: repoDir,
        cleanup: () => {
          cleaned = true;
          fs.rmSync(cloneRoot, { recursive: true, force: true });
        },
      }),
    });

    try {
      const res = await fetch(`${repoServer.url}/api/scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode: 'repo', target: 'owner/repo' }),
      });
      expect(res.status).toBe(200);
      const body = (await res.json()) as {
        mode: string;
        findings: { ruleId: string }[];
        triage: { summary: { total: number } };
        provenance: { origin: string; source: string; commit: string | null };
      };
      expect(body.mode).toBe('repo');
      expect(body.findings.some((f) => f.ruleId === 'iac/s3-public-acl')).toBe(true);
      expect(body.triage.summary.total).toBeGreaterThan(0);
      // A temporary clone is labelled as a cloned repository, never as a
      // local working tree, and no commit is invented for a plain directory.
      expect(body.provenance.origin).toBe('repository-clone');
      expect(body.provenance.source).toBe('owner/repo');
      expect(body.provenance.commit).toBeNull();
      expect(cleaned).toBe(true);
      expect(fs.existsSync(repoDir)).toBe(false);
    } finally {
      await repoServer.close();
      fs.rmSync(cloneRoot, { recursive: true, force: true });
    }
  });

  it('scans a live URL with the web mode', async () => {
    const res = await postScan({ mode: 'web', target: `http://127.0.0.1:${headerPort}` });
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      findings: { ruleId: string; file: string }[];
      elapsedMs: number;
    };
    expect(body.findings.some((f) => f.ruleId === 'web/missing-csp')).toBe(true);
    expect(body.findings.every((f) => f.file.startsWith('http://127.0.0.1'))).toBe(true);
    expect(body.elapsedMs).toBeGreaterThanOrEqual(0);
  });

  it('rejects unsupported URL schemes with 400', async () => {
    const res = await postScan({ mode: 'web', target: 'file:///etc/passwd' });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toContain('Unsupported URL scheme');
  });

  it('requires a target URL for web mode', async () => {
    const res = await postScan({ mode: 'web', target: '' });
    expect(res.status).toBe(400);
  });

  it('rejects a file where a directory is required (mode all)', async () => {
    const file = path.join(workDir, 'not-a-dir.txt');
    fs.writeFileSync(file, 'x');
    const res = await postScan({ mode: 'all', target: file });
    expect(res.status).toBe(400);
    expect(((await res.json()) as { error: string }).error).toContain('must be a directory');
  });
});
