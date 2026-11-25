#!/usr/bin/env node
import { readActionEnv, runAction } from './run.js';

async function main(): Promise<void> {
  const result = await runAction(readActionEnv(process.env));

  console.log(`🔐 secure-scan (all modules) — ${result.scan.totalFindings} finding(s)`);
  for (const f of result.scan.findings) {
    console.log(`  • ${f.file}:${f.line} — ${f.ruleId}: ${f.message}`);
  }
  for (const s of result.scan.skipped) {
    console.log(`  ⊘ ${s.module}: skipped — ${s.reason}`);
  }
  for (const failure of result.scan.failures) {
    console.error(`  ✖ ${failure.module} failed: ${failure.message}`);
  }

  for (const warning of result.warnings) console.warn(`⚠️ ${warning}`);
  console.log(
    result.uploaded
      ? '✅ SARIF uploaded to the Security tab'
      : 'ℹ️ SARIF upload skipped (missing token or repository context)',
  );
  console.log(
    result.commentAction === 'created'
      ? '✅ PR comment posted'
      : result.commentAction === 'updated'
        ? '✅ PR comment updated'
        : 'ℹ️ PR comment skipped (not a pull request event)',
  );
  console.log(`📄 SARIF report: ${result.scan.outputPath}`);

  process.exit(result.exitCode);
}

main().catch((error) => {
  console.error('❌ Error:', error instanceof Error ? error.message : String(error));
  process.exit(1);
});
