import { runOrchestrator } from './orchestrator.js';
import { formatTriageSummary, type TriageBucket } from '../triage/triage.js';

const BUCKET_SYMBOL: Record<TriageBucket, string> = {
  confirmed: '✔',
  review: '?',
  'likely-example': '~',
};

/**
 * CLI wrapper for mode `all`: prints a triage summary (confirmed / review /
 * likely example), deduplicated problem groups, skipped/failed modules, and
 * exits with the orchestrator's honest exit code.
 */
export async function runOrchestratorCli(
  target: string | undefined,
  options: { configPath?: string } = {},
): Promise<void> {
  try {
    const result = await runOrchestrator(target, { configPath: options.configPath });

    console.log(`🔐 secure-scan (all modules) — ${result.totalFindings} finding(s)`);
    console.log(`📊 Triage: ${formatTriageSummary(result.triage.summary)}`);
    for (const group of result.triage.groups) {
      const extra = group.lines.length > 1 ? ` (+${group.lines.length - 1} more)` : '';
      console.log(
        `  ${BUCKET_SYMBOL[group.bucket]} [${group.bucket}] ${group.ruleId} ×${group.count} — ` +
          `${group.file}:${group.lines[0]}${extra} — ${group.message}`,
      );
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
