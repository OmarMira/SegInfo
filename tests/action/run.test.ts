import { describe, expect, it } from 'vitest';
import { runAction, type ActionEnvironment } from '../../src/action/run.js';
import type { OrchestratorResult } from '../../src/orchestrator/orchestrator.js';
import { triageFindings } from '../../src/triage/triage.js';

function fakeResult(overrides: Partial<OrchestratorResult> = {}): OrchestratorResult {
  return {
    exitCode: 0,
    totalFindings: 0,
    findings: [],
    skipped: [],
    failures: [],
    outputPath: '/tmp/seginfo.sarif',
    triage: triageFindings([]),
    ...overrides,
  };
}

function baseEnv(overrides: Partial<ActionEnvironment> = {}): ActionEnvironment {
  return {
    token: 'ghs_token_value',
    repository: 'acme/widgets',
    sha: 'abc123',
    ref: 'refs/heads/main',
    ...overrides,
  };
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  });
}

describe('runAction', () => {
  it('returns the orchestrator exit code and reports upload + PR comment outcomes', async () => {
    const calls: string[] = [];
    const fetchImpl = async (url: string) => {
      calls.push(url);
      if (url.includes('code-scanning/sarifs')) return jsonResponse({}, 201);
      if (url.includes('/comments?per_page=')) return jsonResponse([]);
      return jsonResponse({ id: 1 }, 201);
    };
    const orchestrator = async () => fakeResult({ exitCode: 1, totalFindings: 2 });

    const result = await runAction(
      baseEnv({ eventPayload: { pull_request: { number: 7 } } }),
      { fetchImpl, orchestrator, readSarif: () => '{"version":"2.1.0"}' },
    );

    expect(result.exitCode).toBe(1); // scan verdict survives the reporting steps
    expect(result.uploaded).toBe(true);
    expect(result.commentAction).toBe('created');
    expect(result.warnings).toEqual([]);
    expect(calls.some((u) => u.includes('code-scanning/sarifs'))).toBe(true);
    expect(calls.some((u) => u.includes('/issues/7/comments'))).toBe(true);
  });

  it('keeps the scan exit code when the SARIF upload fails, with a visible warning', async () => {
    const fetchImpl = async (url: string) => {
      if (url.includes('code-scanning/sarifs')) return jsonResponse({ message: 'nope' }, 500);
      return jsonResponse([]);
    };
    const orchestrator = async () => fakeResult({ exitCode: 0 });

    const result = await runAction(baseEnv(), {
      fetchImpl,
      orchestrator,
      readSarif: () => '{"version":"2.1.0"}',
    });

    expect(result.exitCode).toBe(0);
    expect(result.uploaded).toBe(false);
    expect(result.warnings).toHaveLength(1);
    expect(result.warnings[0]).toMatch(/upload/i);
    expect(result.warnings[0]).toContain('500');
  });

  it('skips reporting entirely when no token is configured (no network calls)', async () => {
    const calls: string[] = [];
    const fetchImpl = async (url: string) => {
      calls.push(url);
      return jsonResponse({});
    };
    const orchestrator = async () => fakeResult();

    const result = await runAction(baseEnv({ token: undefined }), { fetchImpl, orchestrator });

    expect(result.uploaded).toBe(false);
    expect(result.commentAction).toBe('skipped');
    expect(calls).toHaveLength(0);
    expect(result.warnings).toEqual([]);
  });

  it('skips the PR comment on non-PR events but still uploads the SARIF', async () => {
    const fetchImpl = async (url: string) =>
      url.includes('code-scanning/sarifs') ? jsonResponse({}, 201) : jsonResponse([]);
    const orchestrator = async () => fakeResult();

    const result = await runAction(baseEnv({ eventPayload: { push: {} } }), {
      fetchImpl,
      orchestrator,
      readSarif: () => '{"version":"2.1.0"}',
    });

    expect(result.uploaded).toBe(true);
    expect(result.commentAction).toBe('skipped');
    expect(result.warnings).toEqual([]);
  });

  it('warns instead of crashing when the PR comment fails', async () => {
    const fetchImpl = async (url: string) => {
      if (url.includes('code-scanning/sarifs')) return jsonResponse({}, 201);
      if (url.includes('/comments?per_page=')) return jsonResponse({ message: 'boom' }, 403);
      return jsonResponse({});
    };
    const orchestrator = async () => fakeResult();

    const result = await runAction(
      baseEnv({ eventPayload: { pull_request: { number: 3 } } }),
      { fetchImpl, orchestrator, readSarif: () => '{"version":"2.1.0"}' },
    );

    expect(result.exitCode).toBe(0);
    expect(result.commentAction).toBe('skipped');
    expect(result.warnings.some((w) => /comment/i.test(w))).toBe(true);
  });

  it('passes the scan target and config through to the orchestrator', async () => {
    let received: { target?: string; configPath?: string } = {};
    const orchestrator = async (target?: string, options?: { configPath?: string }) => {
      received = { target, configPath: options?.configPath };
      return fakeResult();
    };

    await runAction(
      baseEnv({ files: 'src', configPath: 'cfg.json', token: undefined }),
      { orchestrator },
    );

    expect(received).toEqual({ target: 'src', configPath: 'cfg.json' });
  });

  it('skips the upload when repository context is incomplete', async () => {
    let calls = 0;
    const fetchImpl = async () => {
      calls += 1;
      return jsonResponse({});
    };
    const orchestrator = async () => fakeResult();

    const result = await runAction(baseEnv({ repository: undefined }), { fetchImpl, orchestrator });

    expect(result.uploaded).toBe(false);
    expect(calls).toBe(0);
  });
});
