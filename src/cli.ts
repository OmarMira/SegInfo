#!/usr/bin/env node
import { Command } from 'commander';
import { runScan } from './modules/leakscan/cli.js';
import { runSca } from './modules/sca/cli.js';
import { runIac } from './modules/iac/cli.js';
import { runOrchestratorCli } from './orchestrator/cli.js';

const program = new Command();

program
  .name('secure-scan')
  .description('Modular security scanner: SCA + Secrets + IaC')
  .version('0.1.0')
  .option('-m, --mode <mode>', 'mode: all | leakscan | sca | iac', 'all')
  .option(
    '-f, --files <files>',
    'scan target: directory (mode all), or file/glob (single-module modes)',
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
      } else {
        throw new Error(`Unknown mode: ${mode}`);
      }
    } catch (error) {
      console.error('❌ Error:', error instanceof Error ? error.message : String(error));
      process.exit(1);
    }
  });

program.parse();
