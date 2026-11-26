import { scanWeb } from './web-engine.js';
import { writeSarif } from '../../report/sarif.js';

export async function runWeb(files?: string): Promise<void> {
  const findings = await scanWeb(files);
  if (findings.length === 0) {
    console.log('✅ No web security findings detected.');
    process.exitCode = 0;
    return;
  }
  console.log(`🔐 secure-scan (web) — ${findings.length} finding(s)`);
  for (const f of findings) {
    console.log(`  • ${f.file}:${f.line} — ${f.ruleId}: ${f.message}`);
  }
  const outputPath = writeSarif('web', findings);
  console.log(`✅ SARIF report generated: ${outputPath}`);
  process.exitCode = 1;
}
