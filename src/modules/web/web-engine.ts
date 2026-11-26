import type { Finding } from '../../report/sarif.js';

const TIMEOUT_MS = 10_000;
const MAX_REDIRECTS = 5;
const USER_AGENT = 'seginfo-secure-scan';

export interface ScanOptions {
  urls?: string[];
}

/** Turns a user-supplied target into an absolute http(s) URL string. */
export function normalizeTargetUrl(input: string): string {
  const raw = input.trim();
  if (raw.length === 0) throw new Error('Empty URL');
  // Accept "example.com" / "localhost:3000" as https URLs, but never guess
  // for strings that already carry an explicit (possibly unsupported) scheme.
  const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(raw) ? raw : `https://${raw}`;
  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    throw new Error(`Invalid URL: ${input}`);
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error(`Unsupported URL scheme: ${parsed.protocol}`);
  }
  return parsed.href;
}

function headerMap(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [key, value] of headers.entries()) out[key.toLowerCase()] = value;
  return out;
}

function setCookieHeaders(headers: Headers): string[] {
  const getSetCookie = (headers as Headers & { getSetCookie?: () => string[] }).getSetCookie;
  if (typeof getSetCookie === 'function') return getSetCookie.call(headers);
  const raw = headers.get('set-cookie');
  return raw ? [raw] : [];
}

/** Check a fetched response's headers and return findings (values never echoed). */
export function analyzeHeaders(
  url: string,
  finalUrl: string,
  headers: Headers,
  redirectChain: string[],
): Finding[] {
  const findings: Finding[] = [];
  const lower = headerMap(headers);
  const at = (ruleId: string, message: string, level: Finding['level'], properties?: Record<string, unknown>): Finding => ({
    ruleId,
    message,
    file: url,
    line: 1,
    column: 1,
    level,
    ...(properties ? { properties } : {}),
  });

  const isHttps = finalUrl.toLowerCase().startsWith('https://');
  const hasHsts = Boolean(lower['strict-transport-security']);
  const csp = lower['content-security-policy'];

  // A plain-HTTP site that never upgrades is the root cause behind HSTS/CSP
  // workarounds; report it explicitly instead of only listing missing headers.
  if (!isHttps && !hasHsts) {
    findings.push(
      at(
        'web/http-not-redirected',
        'Site is served over plain HTTP and does not redirect to HTTPS.',
        'error',
      ),
    );
  }

  if (!isHttps && !hasHsts) {
    findings.push(
      at(
        'web/missing-hsts',
        'Site does not serve Strict-Transport-Security (HSTS).',
        'warning',
      ),
    );
  }

  if (!csp) {
    findings.push(
      at('web/missing-csp', 'Site is missing a Content-Security-Policy header.', 'warning'),
    );
  }

  if (!lower['x-content-type-options']) {
    findings.push(
      at(
        'web/missing-x-content-type-options',
        'Site is missing the X-Content-Type-Options: nosniff header.',
        'warning',
      ),
    );
  }

  const hasFrameAncestors = Boolean(csp && /frame-ancestors/i.test(csp));
  if (!lower['x-frame-options'] && !hasFrameAncestors) {
    findings.push(
      at(
        'web/missing-x-frame-options',
        'Site is missing X-Frame-Options or a CSP frame-ancestors directive.',
        'warning',
      ),
    );
  }

  if (!lower['referrer-policy']) {
    findings.push(
      at('web/missing-referrer-policy', 'Site is missing a Referrer-Policy header.', 'note'),
    );
  }

  for (const cookie of setCookieHeaders(headers)) {
    const cookieLower = cookie.toLowerCase();
    // Only inspect the attribute list; the cookie value is never read/echoed.
    const attributes = cookieLower.includes(';') ? cookieLower.slice(cookieLower.indexOf(';')) : '';
    const missingSecure = !/(^|;)\s*secure\s*(;|$)/.test(attributes);
    const missingHttpOnly = !/(^|;)\s*httponly\s*(;|$)/.test(attributes);
    if (missingSecure || missingHttpOnly) {
      findings.push(
        at('web/insecure-cookie', 'Cookie is missing the Secure and/or HttpOnly flag.', 'warning', {
          missingSecure,
          missingHttpOnly,
        }),
      );
    }
    if (!/(^|;)\s*samesite\s*=/i.test(attributes)) {
      findings.push(
        at('web/missing-samesite', 'Cookie is missing the SameSite attribute.', 'note'),
      );
    }
  }

  for (const [header, value] of Object.entries(lower)) {
    if (header !== 'server' && header !== 'x-powered-by') continue;
    const match = value.match(/\d+\.\d+(?:\.\d+)?/);
    if (!match) continue;
    const snippet = value.slice(0, 60).replace(/[\r\n]/g, ' ');
    findings.push(
      at(
        'web/server-version-disclosure',
        `Response header discloses a software version (${header}).`,
        'note',
        { header, versionSnippet: snippet },
      ),
    );
  }

  if (redirectChain.length > MAX_REDIRECTS + 1) {
    findings.push(
      at(
        'web/redirect-loop-or-exceeded',
        `Redirect chain exceeded ${MAX_REDIRECTS} hops; possible redirect loop.`,
        'warning',
      ),
    );
  }

  return findings;
}

interface FetchOutcome {
  finalUrl: string;
  headers: Headers | null;
  redirectChain: string[];
  error?: string;
}

async function fetchWithRedirects(startUrl: string): Promise<FetchOutcome> {
  const redirectChain: string[] = [startUrl];
  let currentUrl = startUrl;

  for (let hop = 0; hop <= MAX_REDIRECTS; hop++) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), TIMEOUT_MS);
    let response: Response;
    try {
      response = await fetch(currentUrl, {
        method: 'GET',
        redirect: 'manual',
        signal: controller.signal,
        headers: { 'User-Agent': USER_AGENT },
      });
    } catch (error) {
      return {
        finalUrl: currentUrl,
        headers: null,
        redirectChain,
        error: error instanceof Error ? error.message : String(error),
      };
    } finally {
      clearTimeout(timeout);
    }

    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get('location');
      if (!location) {
        return { finalUrl: currentUrl, headers: response.headers, redirectChain };
      }
      if (hop === MAX_REDIRECTS) {
        // One hop past the limit: report the chain as exceeded.
        redirectChain.push(new URL(location, currentUrl).href);
        return { finalUrl: currentUrl, headers: response.headers, redirectChain };
      }
      currentUrl = new URL(location, currentUrl).href;
      redirectChain.push(currentUrl);
      continue;
    }

    return { finalUrl: currentUrl, headers: response.headers, redirectChain };
  }

  return { finalUrl: currentUrl, headers: null, redirectChain };
}

/**
 * Scan one or more live URLs for missing security headers, weak cookie flags,
 * version disclosure and redirect problems.
 *
 * Only http(s) targets are accepted; every other scheme is rejected before any
 * network access happens.
 */
export async function scanWeb(target?: string, options: ScanOptions = {}): Promise<Finding[]> {
  const inputs = target ? [target] : (options.urls ?? []);
  if (inputs.length === 0) {
    throw new Error('No URLs to scan: pass --files <url> or set "urls" in the config');
  }

  const urls = inputs.map(normalizeTargetUrl);
  const findings: Finding[] = [];

  for (const url of urls) {
    const outcome = await fetchWithRedirects(url);

    if (outcome.error || !outcome.headers) {
      findings.push({
        ruleId: 'web/fetch-failed',
        message: `Failed to fetch ${new URL(url).origin}: ${outcome.error ?? 'no response'}`,
        file: url,
        line: 1,
        column: 1,
        level: 'error',
      });
      continue;
    }

    findings.push(...analyzeHeaders(url, outcome.finalUrl, outcome.headers, outcome.redirectChain));
  }

  return findings;
}
