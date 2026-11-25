import { runOrchestrator } from './orchestrator.js';

/**
 * CLI wrapper for mode `all`: prints a per-module summary, the skipped and
 * failed modules, and exits with the orchestrator's honest exit code.
 */
export async function runOrchestratorCli(
  target: string | undefined,
  options: { configPath?: string } = {},
): Promise<void> {
  try {
    const result = await runOrchestrator(target, { configPath: options.configPath });

    console.log(`🔐 secure-scan (all modules) — ${result.totalFindings} finding(s)`);
    for (const f of result.findings) {
      console.log(`  • ${f.file}:${f.line} — ${f.ruleId}: ${f.message}`);
    }
    for (const s of result.skipped) {
      console.log(`  ⊘ ${s.module}: skipped — ${s.reason}`);
    }
    for (const failure of result.failures) {
      console.error(`  ✖ ${failure.module} failed: ${failure.message}`);
    }
    console.log(`✅ SARIF report generated: ${result.outputPath}`);
    if (result.failures.length > 0) {
      console.error(
        `❌ ${result.failures.length} module(s) failed — results are incomplete (exit ${result.exitCode}).`,
      );
    }
    process.exit(result.exitCode);
  } catch (error) {
    console.error('❌ Error:', error instanceof Error ? error.message : String(error));
    process.exit(1);
  }
}
