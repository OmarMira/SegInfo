import { scanIac } from './iac-engine.js';
import { writeSarif } from '../../report/sarif.js';

export async function runIac(target: string | undefined): Promise<void> {
  const findings = await scanIac(target);
  if (findings.length === 0) {
    console.log('✅ No IaC misconfigurations found.');
    process.exit(0);
  }
  console.log('🔍 Detected IaC misconfigurations:');
  for (const f of findings) {
    console.log(`  • ${f.file}:${f.line} — ${f.ruleId}: ${f.message}`);
  }
  const outputPath = writeSarif('iac', findings);
  console.log(`✅ SARIF report generated: ${outputPath}`);
  process.exit(1); // non-zero exit if findings exist
}
