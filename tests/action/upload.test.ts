import { describe, expect, it } from 'vitest';
import { gunzipSync } from 'node:zlib';
import { buildUploadBody, encodeSarif, uploadSarif } from '../../src/action/upload.js';

describe('encodeSarif', () => {
  it('round-trips the SARIF document through gzip + base64', () => {
    const sarif = JSON.stringify({ version: '2.1.0', runs: [{ tool: {} }] });
    const decoded = gunzipSync(Buffer.from(encodeSarif(sarif), 'base64')).toString('utf8');
    expect(decoded).toBe(sarif);
  });
});

describe('buildUploadBody', () => {
  it('produces the code-scanning API payload with commit, ref and tool name', () => {
    const body = buildUploadBody({
      repo: 'acme/widgets',
      commitSha: 'abc123',
      ref: 'refs/heads/main',
      sarif: '{"version":"2.1.0"}',
      toolName: 'secure-scan',
    });
    expect(body.commit_sha).toBe('abc123');
    expect(body.ref).toBe('refs/heads/main');
    expect(body.tool_name).toBe('secure-scan');
    expect(gunzipSync(Buffer.from(body.sarif, 'base64')).toString('utf8')).toBe(
      '{"version":"2.1.0"}',
    );
    // repo is part of the URL, never the body
    expect(JSON.stringify(body)).not.toContain('acme/widgets');
  });

  it('omits the ref when it is empty', () => {
    const body = buildUploadBody({ repo: 'a/b', commitSha: 'x', ref: '', sarif: '{}' });
    expect(body).not.toHaveProperty('ref');
  });
});

describe('uploadSarif', () => {
  const token = 'ghs_test_token_value';

  it('POSTs the payload to the repository code-scanning endpoint with auth', async () => {
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const fetchImpl = async (url: string, init?: RequestInit) => {
      calls.push({ url, init });
      return new Response('{}', { status: 201 });
    };

    await uploadSarif(
      { repo: 'acme/widgets', commitSha: 'abc', ref: 'refs/heads/main', sarif: '{"v":1}' },
      token,
      fetchImpl,
    );

    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe('https://api.github.com/repos/acme/widgets/code-scanning/sarifs');
    expect(calls[0].init?.method).toBe('POST');
    const headers = calls[0].init?.headers as Record<string, string>;
    expect(headers.authorization).toBe(`Bearer ${token}`);
    expect(headers['user-agent']).toBe('seginfo-secure-scan');
    // token must travel in headers only, never in the body
    expect(String(calls[0].init?.body)).not.toContain(token);
  });

  it('throws a descriptive error on API failure (never fakes success)', async () => {
    const fetchImpl = async () =>
      new Response(JSON.stringify({ message: 'Resource not accessible by token' }), {
        status: 403,
      });
    await expect(
      uploadSarif({ repo: 'a/b', commitSha: 'x', ref: '', sarif: '{}' }, token, fetchImpl),
    ).rejects.toThrow(/403.*Resource not accessible/s);
  });
});
