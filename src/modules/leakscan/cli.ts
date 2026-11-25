import { scanRepo } from './leak-scan-engine.js';
import { toFindings } from './normalize.js';
import { writeSarif, type Finding } from '../../report/sarif.js';

export async function runScan(files: string | undefined): Promise<void> {
  const findings: Finding[] = toFindings(await scanRepo(files || undefined));
  if (findings.length === 0) {
    console.log('✅ No secrets detected in the repository.');
    process.exit(0);
  }
  console.log('🔍 Detected potential secrets:');
  for (const f of findings) {
    console.log(`  • ${f.file}:${f.line} — ${f.ruleId} (${f.message})`);
  }
  const outputPath = writeSarif('leakscan', findings);
  console.log(`✅ SARIF report generated: ${outputPath}`);
  process.exit(1); // non-zero exit if secrets found
}
