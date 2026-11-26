import { spawn } from 'node:child_process';
import { startServer, type RunningServer } from './app.js';

export interface ServeCliOptions {
  port?: string;
  host?: string;
  /** Commander sets this to false for `--no-open`. */
  open?: boolean;
}

function parsePort(value: string | undefined): number {
  if (value === undefined) return 4310;
  const port = Number.parseInt(value, 10);
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new Error(`Invalid port: ${value}`);
  }
  return port;
}

function openBrowser(url: string): void {
  const [command, args] =
    process.platform === 'win32'
      ? ['cmd', ['/c', 'start', '', url]]
      : process.platform === 'darwin'
        ? ['open', [url]]
        : ['xdg-open', [url]];

  try {
    const child = spawn(command, args, { detached: true, stdio: 'ignore' });
    child.on('error', () => {
      /* Opening a browser is a convenience; never fail the server for it. */
    });
    child.unref();
  } catch {
    /* ignore */
  }
}

/**
 * Starts the local UI/API server and keeps the process alive until Ctrl+C.
 * Prints the URL so the user can open it manually with `--no-open`.
 */
export async function runServeCli(options: ServeCliOptions = {}): Promise<RunningServer> {
  const port = parsePort(options.port);
  const host = options.host ?? '127.0.0.1';
  const running = await startServer({ host, port });

  console.log(`🔐 secure-scan local UI: ${running.url}`);
  if (host !== '127.0.0.1' && host !== 'localhost' && host !== '::1') {
    console.warn(
      `⚠️  Bound to ${host}: scans are reachable from other machines on this network. ` +
        'Only do this on a trusted network.',
    );
  }

  if (options.open !== false) openBrowser(running.url);

  const shutdown = (): void => {
    console.log('\nStopping server...');
    void running.close().finally(() => process.exit(0));
  };
  process.once('SIGINT', shutdown);
  process.once('SIGTERM', shutdown);

  return running;
}
