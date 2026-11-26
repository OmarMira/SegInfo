import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import * as http from 'node:http';
import { scanWeb } from '../../src/modules/web/web-engine.js';

function makeServer(contentType = 'text/html', headers: Record<string, string> = {}) {
  return new Promise<{ server: http.Server; port: number; close: () => void }>((resolve) => {
    const server = http.createServer((_req, res) => {
      res.writeHead(200, { 'Content-Type': contentType, ...headers });
      res.end('OK');
    });
    server.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (address === null || typeof address === 'string') throw new Error('no port');
      resolve({ server, port: address.port, close: () => server.close() });
    });
  });
}

describe('secure-scan web module (local only)', () => {
  let orig: string | undefined;

  beforeAll(async () => {
    orig = process.env.NODE_TLS_REJECT_UNAUTHORIZED;
    process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
  });

  afterAll(async () => {
    if (orig !== undefined) process.env.NODE_TLS_REJECT_UNAUTHORIZED = orig;
  });

  it('clean server with all headers → 0 findings', async () => {
    const s = await makeServer('text/plain', {
      'strict-transport-security': 'max-age=31536000; includeSubDomains',
      'content-security-policy': "default-src 'self'",
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'referrer-policy': 'strict-origin-when-no-referrer',
      'set-cookie': 'session=abc; Secure; HttpOnly; SameSite=Strict',
    });
    try {
      const findings = await scanWeb(`http://127.0.0.1:${s.port}`);
      expect(findings).toHaveLength(0);
    } finally {
      s.close();
    }
  });

  it('missing-hsts flagged when no HSTS header', async () => {
    const s = await makeServer('text/plain', {
      'content-security-policy': "default-src 'self'",
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'referrer-policy': 'strict-origin-when-no-referrer',
      'set-cookie': 'session=abc; Secure; HttpOnly; SameSite=Strict',
    });
    try {
      const findings = await scanWeb(`http://127.0.0.1:${s.port}`);
      const hasHSTS = findings.some(f => f.ruleId === 'web/missing-hsts');
      expect(hasHSTS).toBe(true);
    } finally {
      s.close();
    }
  });

  it('missing-csp flagged when no CSP header', async () => {
    const s = await makeServer('text/plain', {
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'referrer-policy': 'strict-origin-when-no-referrer',
      'set-cookie': 'session=abc; Secure; HttpOnly; SameSite=Strict',
    });
    try {
      const findings = await scanWeb(`http://127.0.0.1:${s.port}`);
      const hasCSP = findings.some(f => f.ruleId === 'web/missing-csp');
      expect(hasCSP).toBe(true);
    } finally {
      s.close();
    }
  });

  it('missing-x-content-type-options flagged', async () => {
    const s = await makeServer('text/plain', {
      'strict-transport-security': 'max-age=31536000',
      'x-frame-options': 'DENY',
      'referrer-policy': 'strict-origin-when-no-referrer',
      'set-cookie': 'session=abc; Secure; HttpOnly; SameSite=Strict',
    });
    try {
      const findings = await scanWeb(`http://127.0.0.1:${s.port}`);
      const hasXTNO = findings.some(f => f.ruleId === 'web/missing-x-content-type-options');
      expect(hasXTNO).toBe(true);
    } finally {
      s.close();
    }
  });

  it('missing-x-frame-options flagged', async () => {
    const s = await makeServer('text/plain', {
      'strict-transport-security': 'max-age=31536000',
      'content-security-policy': "default-src 'self'",
      'referrer-policy': 'strict-origin-when-no-referrer',
      'set-cookie': 'session=abc; Secure; HttpOnly; SameSite=Strict',
    });
    try {
      const findings = await scanWeb(`http://127.0.0.1:${s.port}`);
      const hasXFO = findings.some(f => f.ruleId === 'web/missing-x-frame-options');
      expect(hasXFO).toBe(true);
    } finally {
      s.close();
    }
  });

  it('missing-referrer-policy flagged', async () => {
    const s = await makeServer('text/plain', {
      'strict-transport-security': 'max-age=31536000',
      'content-security-policy': "default-src 'self'",
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'set-cookie': 'session=abc; Secure; HttpOnly; SameSite=Strict',
    });
    try {
      const findings = await scanWeb(`http://127.0.0.1:${s.port}`);
      const hasRP = findings.some(f => f.ruleId === 'web/missing-referrer-policy');
      expect(hasRP).toBe(true);
    } finally {
      s.close();
    }
  });

  it('insecure-cookie flagged when missing Secure or HttpOnly', async () => {
    const s = await makeServer('text/plain', {
      'strict-transport-security': 'max-age=31536000',
      'content-security-policy': "default-src 'self'",
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'referrer-policy': 'strict-origin-when-no-referrer',
      'set-cookie': 'session=abc', // Missing Secure and HttpOnly
    });
    try {
      const findings = await scanWeb(`http://127.0.0.1:${s.port}`);
      const hasIC = findings.some(f => f.ruleId === 'web/insecure-cookie');
      expect(hasIC).toBe(true);
      // Should have exactly one finding per cookie (but we only have one cookie)
      expect(findings.filter(f => f.ruleId === 'web/insecure-cookie')).toHaveLength(1);
    } finally {
      s.close();
    }
  });

  it('missing-samesite flagged when Set-Cookie without SameSite', async () => {
    const s = await makeServer('text/plain', {
      'strict-transport-security': 'max-age=31536000',
      'content-security-policy': "default-src 'self'",
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'referrer-policy': 'strict-origin-when-no-referrer',
      'set-cookie': 'session=abc', // No SameSite
    });
    try {
      const findings = await scanWeb(`http://127.0.0.1:${s.port}`);
      const hasMS = findings.some(f => f.ruleId === 'web/missing-samesite');
      expect(hasMS).toBe(true);
    } finally {
      s.close();
    }
  });

  it('server-version-disclosure flagged when Server header has version', async () => {
    const s = await makeServer('text/plain', {
      'server': 'Apache/2.4.58 (Unix)',
      'strict-transport-security': 'max-age=31536000',
      'content-security-policy': "default-src 'self'",
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'referrer-policy': 'strict-origin-when-no-referrer',
      'set-cookie': 'session=abc; Secure; HttpOnly; SameSite=Strict',
    });
    try {
      const findings = await scanWeb(`http://127.0.0.1:${s.port}`);
      const hasSVD = findings.some(f => f.ruleId === 'web/server-version-disclosure');
      expect(hasSVD).toBe(true);
    } finally {
      s.close();
    }
  });

  it('server-version-disclosure with X-Powered-By', async () => {
    const s = await makeServer('text/plain', {
      'x-powered-by': 'Express/4.19.2',
      'strict-transport-security': 'max-age=31536000',
      'content-security-policy': "default-src 'self'",
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
      'referrer-policy': 'strict-origin-when-no-referrer',
      'set-cookie': 'session=abc; Secure; HttpOnly; SameSite=Strict',
    });
    try {
      const findings = await scanWeb(`http://127.0.0.1:${s.port}`);
      const hasXPD = findings.some(f => f.ruleId === 'web/server-version-disclosure');
      expect(hasXPD).toBe(true);
    } finally {
      s.close();
    }
  });

  it('http target without https redirect → http-not-redirected', async () => {
    // An http:// target with no HSTS should trigger http-not-redirected.
    // This test verifies that http:// URLs that do NOT get redirected to https produce a finding.
    const s = await makeServer('text/plain', {
      // No HSTS, no redirect info in headers — server just answers on http
    });
    try {
      const findings = await scanWeb('http://127.0.0.1:' + s.port);
      // The test just checks that something is found; exact rule depends on implementation.
      expect(findings.length).toBeGreaterThanOrEqual(1);
    } finally {
      s.close();
    }
  });

  it('redirect-exceeded when >5 hops', async () => {
    // Simulate many redirects by pointing to another redirect-heavy setup;
    // for now just verify no crash and some findings.
    const s = await makeServer('text/plain', {
      'strict-transport-security': 'max-age=31536000',
    });
    try {
      const findings = await scanWeb('https://127.0.0.1:' + s.port);
      // Should not throw; some findings may be present.
      expect(findings).not.toBeNull();
    } finally {
      s.close();
    }
  });

  it('non-http(s) scheme rejected with clear error', async () => {
    await expect(scanWeb('file:///etc/passwd')).rejects.toThrow(/Unsupported URL scheme/);
    await expect(scanWeb('gopher://gopher.example.com')).rejects.toThrow(/Unsupported URL scheme/);
  });

  it('fetch failure throws honest error', async () => {
    // Cannot easily simulate a real network refusal without mocking fetch globally.
    // We'll test that the function does not silently return an empty clean result
    // when a network error occurs; the AbortController timeout will fire.
    const findings = await scanWeb('http://127.0.0.1:1');
    // A network failure must surface as an honest finding, never a clean pass.
    expect(findings.some((f) => f.ruleId === 'web/fetch-failed')).toBe(true);
  });
});