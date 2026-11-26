import { describe, expect, it } from 'vitest';
import { normalizeRepoUrl } from '../../src/server/repo.js';

describe('repository URL validation', () => {
  it('accepts owner/repo shorthand as a GitHub URL', () => {
    expect(normalizeRepoUrl('vercel/next.js')).toBe('https://github.com/vercel/next.js');
  });

  it('accepts https URLs on supported hosts', () => {
    expect(normalizeRepoUrl('https://github.com/owner/repo')).toBe('https://github.com/owner/repo');
    expect(normalizeRepoUrl('https://gitlab.com/owner/repo.git')).toBe('https://gitlab.com/owner/repo.git');
    expect(normalizeRepoUrl('https://bitbucket.org/owner/repo')).toBe(
      'https://bitbucket.org/owner/repo',
    );
  });

  it('rejects non-https, ssh and local schemes', () => {
    expect(() => normalizeRepoUrl('http://github.com/owner/repo')).toThrow(/https/);
    expect(() => normalizeRepoUrl('ssh://git@github.com/owner/repo')).toThrow(/https/);
    expect(() => normalizeRepoUrl('git@github.com:owner/repo.git')).toThrow(/Invalid/);
    expect(() => normalizeRepoUrl('file:///C:/repos/app')).toThrow(/https/);
  });

  it('rejects unsupported hosts', () => {
    expect(() => normalizeRepoUrl('https://evil.example/owner/repo')).toThrow(/Unsupported repository host/);
  });

  it('rejects credentials and query strings', () => {
    expect(() => normalizeRepoUrl('https://user:pass@github.com/owner/repo')).toThrow(/Credentials/);
    expect(() => normalizeRepoUrl('https://github.com/owner/repo?token=abc')).toThrow(/Query strings/);
  });

  it('rejects URLs without an owner and repository', () => {
    expect(() => normalizeRepoUrl('https://github.com/owner')).toThrow(/owner and a repository/);
  });
});
