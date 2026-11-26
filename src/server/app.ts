import * as http from 'node:http';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { AddressInfo } from 'node:net';
import { scanWeb } from '../modules/web/web-engine.js';
import { scanRepo } from '../modules/leakscan/leak-scan-engine.js';
import { toFindings } from '../modules/leakscan/normalize.js';
import { scanDependencies } from '../modules/sca/sca-engine.js';
import { scanIac } from '../modules/iac/iac-engine.js';
import { scanSast } from '../modules/sast/sast-engine.js';
import { runOrchestrator } from '../orchestrator/orchestrator.js';
import { DEFAULT_CONFIG } from '../orchestrator/config.js';
import {
  triageFindings,
  type TriageBucket,
  type TriageResult,
  type TriageSummary,
} from '../triage/triage.js';
import { cloneRepository, type CloneImpl } from './repo.js';
import type { Finding } from '../report/sarif.js';
import { NothingToScanError } from '../util/errors.js';
import { UI_HTML } from './ui.js';

export const SCAN_MODES = ['all', 'leakscan', 'sca', 'iac', 'sast', 'web', 'repo'] as const;
export type ScanMode = (typeof SCAN_MODES)[number];

const DEFAULT_PORT = 4310;
const DEFAULT_HOST = '127.0.0.1';
const MAX_BODY_BYTES = 64 * 1024;
const LOOPBACK_HOSTS = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);

export interface ServerOptions {
  host?: string;
  port?: number;
  /** Base directory for relative targets and module resolution. */
  cwd?: string;
  /** Injected cloner (tests); defaults to a real shallow `git clone`. */
  clone?: CloneImpl;
}

export interface RunningServer {
  server: http.Server;
  host: string;
  port: number;
  url: string;
  close: () => Promise<void>;
}

export interface ScanRequest {
  mode?: ScanMode;
  target?: string;
  config?: string;
}

export interface TriageGroupView {
  key: string;
  ruleId: string;
  file: string;
  message: string;
  level: Finding['level'];
  bucket: TriageBucket;
  reason: string;
  why: string;
  evidence: string[];
  fix: string;
  nextStep: string;
  count: number;
  lines: number[];
}

export interface TriageView {
  summary: TriageSummary;
  groups: TriageGroupView[];
}

export interface ScanResponse {
  mode: ScanMode;
  target: string;
  findings: Finding[];
  skipped: { module: string; reason: string }[];
  failures: { module: string; message: string }[];
  elapsedMs: number;
  triage: TriageView;
}

function serializeTriage(result: TriageResult): TriageView {
  return {
    summary: result.summary,
    groups: result.groups.map((group) => ({
      key: group.key,
      ruleId: group.ruleId,
      file: group.file,
      message: group.message,
      level: group.level,
      bucket: group.bucket,
      reason: group.reason,
      why: group.why,
      evidence: group.evidence,
      fix: group.fix,
      nextStep: group.nextStep,
      count: group.count,
      lines: group.lines,
    })),
  };
}

class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

function isLoopback(host: string): boolean {
  return LOOPBACK_HOSTS.has(host.toLowerCase());
}

/** Hostnames the server answers to; a wildcard bind still only trusts loopback. */
function allowedHostnames(boundHost: string): Set<string> {
  const allowed = new Set(LOOPBACK_HOSTS);
  if (!['0.0.0.0', '::', ''].includes(boundHost)) allowed.add(boundHost.toLowerCase());
  return allowed;
}

function hostnameOf(hostHeader: string): string {
  try {
    return new URL(`http://${hostHeader}`).hostname.toLowerCase();
  } catch {
    return '';
  }
}

/** DNS-rebinding guard: only loopback names (plus the explicit bind host). */
function assertAllowedHost(req: http.IncomingMessage, allowed: Set<string>): void {
  const hostHeader = req.headers.host;
  if (!hostHeader) throw new HttpError(403, 'Missing Host header');
  if (!allowed.has(hostnameOf(hostHeader))) {
    throw new HttpError(403, `Host not allowed: ${hostHeader}`);
  }
}

/** CSRF guard for browser callers: any Origin must match the request Host. */
function assertSameOrigin(req: http.IncomingMessage): void {
  const origin = req.headers.origin;
  if (!origin) return;
  let originHost: string;
  try {
    originHost = new URL(origin).host.toLowerCase();
  } catch {
    throw new HttpError(403, 'Invalid Origin header');
  }
  if (originHost !== (req.headers.host ?? '').toLowerCase()) {
    throw new HttpError(403, `Cross-origin request rejected: ${origin}`);
  }
}

function readJsonBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    let settled = false;
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => {
      if (settled) return;
      size += chunk.length;
      if (size > MAX_BODY_BYTES) {
        settled = true;
        req.pause();
        reject(new HttpError(413, `Request body exceeds ${MAX_BODY_BYTES} bytes`));
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (settled) return;
      settled = true;
      resolve(Buffer.concat(chunks).toString('utf8'));
    });
    req.on('error', (error) => {
      if (settled) return;
      settled = true;
      reject(error);
    });
  });
}

function parseScanRequest(raw: string): ScanRequest {
  let data: unknown;
  try {
    data = JSON.parse(raw || '{}');
  } catch {
    throw new HttpError(400, 'Invalid JSON body');
  }
  if (typeof data !== 'object' || data === null || Array.isArray(data)) {
    throw new HttpError(400, 'Body must be a JSON object');
  }
  const { mode, target, config } = data as Record<string, unknown>;
  if (mode !== undefined && !SCAN_MODES.includes(mode as ScanMode)) {
    throw new HttpError(400, `Unknown mode: ${String(mode)}`);
  }
  if (target !== undefined && typeof target !== 'string') {
    throw new HttpError(400, 'target must be a string');
  }
  if (typeof target === 'string' && target.length > 4096) {
    throw new HttpError(400, 'target is too long');
  }
  if (config !== undefined && typeof config !== 'string') {
    throw new HttpError(400, 'config must be a path string');
  }
  return { mode: mode as ScanMode | undefined, target, config };
}

async function runSingleModule(mode: Exclude<ScanMode, 'all' | 'web' | 'repo'>, target: string | undefined, cwd: string) {
  switch (mode) {
    case 'leakscan':
      return toFindings(await scanRepo(target, { cwd }));
    case 'sca':
      return scanDependencies(target, { cwd });
    case 'iac':
      return scanIac(target, { cwd });
    case 'sast':
      return scanSast(target, { cwd });
  }
}

async function executeScan(request: ScanRequest, options: ServerOptions): Promise<ScanResponse> {
  const cwd = options.cwd ?? process.cwd();
  const mode = request.mode ?? 'all';
  const target = request.target?.trim() ?? '';
  const started = Date.now();

  try {
    if (mode === 'web') {
      if (!target) throw new HttpError(400, 'La URL de destino es obligatoria para el modo "web"');
      const findings = await scanWeb(target);
      return {
        mode,
        target,
        findings,
        skipped: [],
        failures: [],
        elapsedMs: Date.now() - started,
        triage: serializeTriage(triageFindings(findings)),
      };
    }

    if (mode === 'repo') {
      if (!target) throw new HttpError(400, 'La URL del repositorio es obligatoria para el modo "repo"');
      const clone = options.clone ?? cloneRepository;
      const handle = await clone(target);
      try {
        const result = await runOrchestrator(undefined, {
          cwd: handle.dir,
          // A cloned repository must not control the scan: ignore any
          // config file it ships and use the default module set.
          config: {
            ...DEFAULT_CONFIG,
            modules: [...DEFAULT_CONFIG.modules],
            ignore: [...DEFAULT_CONFIG.ignore],
          },
          writeReport: false,
        });
        return {
          mode,
          target,
          findings: result.findings,
          skipped: result.skipped,
          failures: result.failures,
          elapsedMs: Date.now() - started,
          triage: serializeTriage(result.triage),
        };
      } finally {
        handle.cleanup();
      }
    }

    if (mode === 'all') {
      const result = await runOrchestrator(target || undefined, {
        cwd,
        configPath: request.config,
        writeReport: false,
      });
      return {
        mode,
        target: target || cwd,
        findings: result.findings,
        skipped: result.skipped,
        failures: result.failures,
        elapsedMs: Date.now() - started,
        triage: serializeTriage(result.triage),
      };
    }

    try {
      const findings = await runSingleModule(mode, target || undefined, cwd);
      return {
        mode,
        target: target || cwd,
        findings,
        skipped: [],
        failures: [],
        elapsedMs: Date.now() - started,
        triage: serializeTriage(triageFindings(findings)),
      };
    } catch (error) {
      if (error instanceof NothingToScanError) {
        return {
          mode,
          target: target || cwd,
          findings: [],
          skipped: [{ module: mode, reason: error.message }],
          failures: [],
          elapsedMs: Date.now() - started,
          triage: serializeTriage(triageFindings([])),
        };
      }
      throw error;
    }
  } catch (error) {
    // Everything the engines throw here is caused by the requested target or
    // config, so surface it as a 400 instead of a server fault.
    if (error instanceof HttpError) throw error;
    throw new HttpError(400, error instanceof Error ? error.message : String(error));
  }
}

export interface BrowseEntry {
  name: string;
  path: string;
}

export interface BrowseResult {
  /** Current directory, or null when listing filesystem roots (drives). */
  path: string | null;
  parent: string | null;
  entries: BrowseEntry[];
}

function listRoots(): BrowseEntry[] {
  if (process.platform !== 'win32') return [{ name: '/', path: '/' }];
  const roots: BrowseEntry[] = [];
  for (const letter of 'ABCDEFGHIJKLMNOPQRSTUVWXYZ') {
    const root = `${letter}:\\`;
    try {
      if (fs.statSync(root).isDirectory()) roots.push({ name: root, path: root });
    } catch {
      /* drive not present */
    }
  }
  return roots;
}

/** Lists directories only (never file contents) for the UI folder picker. */
export function browseDirectory(requested?: string | null): BrowseResult {
  if (!requested || requested.trim() === '') {
    return { path: null, parent: null, entries: listRoots() };
  }
  if (requested.length > 4096) throw new HttpError(400, 'La ruta es demasiado larga');
  const resolved = path.resolve(requested);

  let stat: fs.Stats;
  try {
    stat = fs.statSync(resolved);
  } catch {
    throw new HttpError(404, `No se encontró la carpeta: ${resolved}`);
  }
  if (!stat.isDirectory()) throw new HttpError(400, `No es una carpeta: ${resolved}`);

  let dirents: fs.Dirent[];
  try {
    dirents = fs.readdirSync(resolved, { withFileTypes: true });
  } catch {
    throw new HttpError(403, `No se puede leer la carpeta: ${resolved}`);
  }

  const entries = dirents
    .filter((entry) => entry.isDirectory())
    .map((entry) => ({ name: entry.name, path: path.join(resolved, entry.name) }))
    .sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }))
    .slice(0, 1000);

  const parent = path.dirname(resolved);
  return { path: resolved, parent: parent === resolved ? null : parent, entries };
}

function sendJson(res: http.ServerResponse, status: number, payload: unknown): void {
  const body = JSON.stringify(payload, null, 2);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(body),
  });
  res.end(body);
}

function applySecurityHeaders(res: http.ServerResponse): void {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Cache-Control', 'no-store');
}

function sendHtml(res: http.ServerResponse, html: string): void {
  res.writeHead(200, {
    'Content-Type': 'text/html; charset=utf-8',
    'Content-Length': Buffer.byteLength(html),
    'Content-Security-Policy':
      "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
  });
  res.end(html);
}

export function createScanServer(options: ServerOptions = {}): http.Server {
  const boundHost = options.host ?? DEFAULT_HOST;
  const allowed = allowedHostnames(boundHost);

  const handler = async (req: http.IncomingMessage, res: http.ServerResponse): Promise<void> => {
    applySecurityHeaders(res);
    try {
      assertAllowedHost(req, allowed);
      const url = new URL(req.url ?? '/', `http://${req.headers.host}`);

      if (url.pathname === '/' || url.pathname === '/index.html') {
        if (req.method !== 'GET' && req.method !== 'HEAD') throw new HttpError(405, 'Method not allowed');
        sendHtml(res, UI_HTML);
        return;
      }

      if (url.pathname === '/favicon.ico') {
        res.writeHead(204).end();
        return;
      }

      if (url.pathname === '/api/health') {
        if (req.method !== 'GET') throw new HttpError(405, 'Method not allowed');
        sendJson(res, 200, { ok: true, name: 'seginfo-secure-scan', modes: SCAN_MODES });
        return;
      }

      if (url.pathname === '/api/browse') {
        if (req.method !== 'GET') throw new HttpError(405, 'Method not allowed');
        sendJson(res, 200, browseDirectory(url.searchParams.get('path')));
        return;
      }

      if (url.pathname === '/api/scan') {
        if (req.method !== 'POST') throw new HttpError(405, 'Method not allowed');
        assertSameOrigin(req);
        const contentType = (req.headers['content-type'] ?? '').toLowerCase();
        if (!contentType.startsWith('application/json')) {
          throw new HttpError(415, 'Content-Type must be application/json');
        }
        const body = await readJsonBody(req);
        const scanRequest = parseScanRequest(body);
        const result = await executeScan(scanRequest, options);
        sendJson(res, 200, result);
        return;
      }

      throw new HttpError(404, 'Not found');
    } catch (error) {
      const status = error instanceof HttpError ? error.status : 500;
      const message = error instanceof Error ? error.message : String(error);
      if (status === 413) res.setHeader('Connection', 'close');
      if (!res.headersSent) sendJson(res, status, { error: message });
      else res.destroy();
    }
  };

  return http.createServer((req, res) => {
    void handler(req, res);
  });
}

export function startServer(options: ServerOptions = {}): Promise<RunningServer> {
  const host = options.host ?? DEFAULT_HOST;
  const port = options.port ?? DEFAULT_PORT;
  const server = createScanServer({ ...options, host, port });

  return new Promise<RunningServer>((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => {
      server.removeListener('error', reject);
      const address = server.address() as AddressInfo;
      const displayHost = isLoopback(host) ? host : '127.0.0.1';
      resolve({
        server,
        host,
        port: address.port,
        url: `http://${displayHost}:${address.port}`,
        close: () =>
          new Promise<void>((done, fail) => {
            server.close((error) => (error ? fail(error) : done()));
          }),
      });
    });
  });
}
