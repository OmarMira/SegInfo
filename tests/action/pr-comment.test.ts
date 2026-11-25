import { describe, expect, it } from 'vitest';
import {
  PR_MARKER,
  buildPrComment,
  findBotComment,
  upsertPrComment,
} from '../../src/action/pr-comment.js';
import type { OrchestratorResult } from '../../src/orchestrator/orchestrator.js';

function makeResult(overrides: Partial<OrchestratorResult> = {}): OrchestratorResult {
  return {
    exitCode: 1,
    totalFindings: 1,
    findings: [
      {
        ruleId: 'leakscan/aws-access-key',
        message: 'Potential secret (aws-access-key) found in working-tree',
        file: 'src/config.ts',
        line: 2,
        column: 1,
        level: 'warning',
      },
    ],
    skipped: [{ module: 'iac', reason: 'No Terraform or Kubernetes files found under /x' }],
    failures: [],
    outputPath: '/tmp/out.sarif',
    ...overrides,
  };
}

describe('buildPrComment', () => {
  it('carries the marker, counts, findings with location and skips', () => {
    const body = buildPrComment(makeResult());
    expect(body).toContain(PR_MARKER);
    expect(body).toContain('1 finding');
    expect(body).toContain('leakscan/aws-access-key');
    expect(body).toContain('`src/config.ts:2`');
    expect(body).toContain('iac');
    expect(body).toContain('skipped');
    expect(body).toContain('No Terraform or Kubernetes files');
  });

  it('reports module failures prominently', () => {
    const body = buildPrComment(
      makeResult({
        totalFindings: 0,
        findings: [],
        skipped: [],
        failures: [{ module: 'sca', message: 'OSV query failed: fetch failed' }],
        exitCode: 1,
      }),
    );
    expect(body).toContain('failed');
    expect(body).toContain('OSV query failed');
    expect(body).toContain('exit 1');
  });

  it('sanitizes backticks out of file paths and truncates long messages', () => {
    const body = buildPrComment(
      makeResult({
        findings: [
          {
            ruleId: 'x/y',
            message: 'm'.repeat(500),
            file: 'we`ird/pa`th.ts',
            line: 9,
            column: 1,
            level: 'error',
          },
        ],
      }),
    );
    expect(body).not.toContain('we`ird');
    expect(body).toContain('`we\'ird/pa\'th.ts:9`');
    expect(body).toContain('…'); // truncated
    expect(body).not.toContain('m'.repeat(300));
  });

  it('caps the number of listed findings', () => {
    const findings = Array.from({ length: 40 }, (_, i) => ({
      ruleId: `r/${i}`,
      message: `msg ${i}`,
      file: `f${i}.ts`,
      line: i + 1,
      column: 1,
      level: 'warning' as const,
    }));
    const body = buildPrComment(makeResult({ findings, totalFindings: 40 }));
    expect(body).toContain('more');
    expect(body).not.toContain('f39.ts');
  });
});

describe('findBotComment', () => {
  it('finds the existing comment carrying the marker', () => {
    const id = findBotComment([
      { id: 1, body: 'unrelated', user: { login: 'x' } },
      { id: 7, body: `hello\n${PR_MARKER}\nreport`, user: { login: 'github-actions[bot]' } },
    ]);
    expect(id).toBe(7);
  });

  it('returns null when no marked comment exists', () => {
    expect(findBotComment([{ id: 1, body: 'hi', user: { login: 'x' } }])).toBeNull();
    expect(findBotComment([])).toBeNull();
  });
});

describe('upsertPrComment', () => {
  const token = 'ghs_test_token_value';

  it('creates a comment when none exists', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const fetchImpl = async (url: string, init?: RequestInit) => {
      calls.push({ url, init });
      if (url.includes('/comments?per_page=')) return new Response('[]', { status: 200 });
      return new Response(JSON.stringify({ id: 99 }), { status: 201 });
    };

    const action = await upsertPrComment(
      { repo: 'acme/widgets', prNumber: 12, token, body: PR_MARKER },
      fetchImpl,
    );

    expect(action).toBe('created');
    expect(calls[0].url).toBe(
      'https://api.github.com/repos/acme/widgets/issues/12/comments?per_page=100',
    );
    expect(calls[0].init?.method).toBe('GET');
    expect(calls[1].url).toBe('https://api.github.com/repos/acme/widgets/issues/12/comments');
    expect(calls[1].init?.method).toBe('POST');
    const headers = calls[1].init?.headers as Record<string, string>;
    expect(headers.authorization).toBe(`Bearer ${token}`);
    expect(String(calls[1].init?.body)).toBe(JSON.stringify({ body: PR_MARKER }));
    expect(String(calls[1].init?.body)).not.toContain(token);
  });

  it('updates the existing marked comment instead of duplicating it', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const fetchImpl = async (url: string, init?: RequestInit) => {
      calls.push({ url, init });
      if (url.includes('/comments?per_page=')) {
        return new Response(JSON.stringify([{ id: 55, body: PR_MARKER, user: { login: 'bot' } }]), {
          status: 200,
        });
      }
      return new Response(JSON.stringify({ id: 55 }), { status: 200 });
    };

    const action = await upsertPrComment(
      { repo: 'acme/widgets', prNumber: 12, token, body: `${PR_MARKER} v2` },
      fetchImpl,
    );

    expect(action).toBe('updated');
    expect(calls[1].url).toBe('https://api.github.com/repos/acme/widgets/issues/comments/55');
    expect(calls[1].init?.method).toBe('PATCH');
  });

  it('throws when the comment list request fails (never fakes success)', async () => {
    const fetchImpl = async () => new Response('{"message":"rate limited"}', { status: 429 });
    await expect(
      upsertPrComment({ repo: 'a/b', prNumber: 1, token, body: 'x' }, fetchImpl),
    ).rejects.toThrow(/429/);
  });
});
