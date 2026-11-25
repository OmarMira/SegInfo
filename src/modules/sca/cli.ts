import { scanDependencies } from './sca-engine.js';
import { writeSarif } from '../../report/sarif.js';

export async function runSca(files: string | undefined): Promise<void> {
  const findings = await scanDependencies(files || undefined);
  if (findings.length === 0) {
    console.log('✅ No vulnerable dependencies found.');
    process.exit(0);
  }
  for (const f of findings) {
    console.log(`  • ${f.file}:${f.line} — ${f.ruleId}: ${f.message}`);
  }
  const outputPath = writeSarif('sca', findings);
  console.log(`✅ SARIF report generated: ${outputPath}`);
  process.exit(1);
}
