#!/usr/bin/env node
import { Command } from 'commander';
import { runScan } from './modules/leakscan/cli.js';
import { runSca } from './modules/sca/cli.js';
import { runIac } from './modules/iac/cli.js';
import { runSast } from './modules/sast/cli.js';
import { runWeb } from './modules/web/cli.js';
import { runOrchestratorCli } from './orchestrator/cli.js';
import { runServeCli } from './server/cli.js';

const program = new Command();

program
  .name('secure-scan')
  .description('Modular security scanner: SCA + Secrets + IaC + SAST + live URLs')
  .version('0.1.0')
  .option('-m, --mode <mode>', 'mode: all | leakscan | sca | iac | sast | web', 'all')
  .option(
    '-f, --files <files>',
    'scan target: directory (mode all), or file/glob/URL (single-module modes)',
  )
  .option('-c, --config <path>', 'path to secure-scan config file (mode all)')
  .action(async (options) => {
    try {
      const mode = options.mode || 'all';
      if (mode === 'all') {
        await runOrchestratorCli(options.files, { configPath: options.config });
      } else if (mode === 'leakscan') {
        await runScan(options.files);
      } else if (mode === 'sca') {
        await runSca(options.files);
      } else if (mode === 'iac') {
        await runIac(options.files);
      } else if (mode === 'sast') {
        await runSast(options.files);
      } else if (mode === 'web') {
        await runWeb(options.files);
      } else {
        throw new Error(`Unknown mode: ${mode}`);
      }
    } catch (error) {
      console.error('❌ Error:', error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

program
  .command('serve')
  .description('Start the local web UI and JSON API (loopback only by default)')
  .option('-p, --port <port>', 'port to listen on', '4310')
  .option('--host <host>', 'host to bind', '127.0.0.1')
  .option('--no-open', 'do not open the browser automatically')
  .action(async (options: { port?: string; host?: string; open?: boolean }) => {
    try {
      await runServeCli(options);
    } catch (error) {
      console.error('❌ Error:', error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

program.parse();
