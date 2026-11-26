import { scanSast } from './sast-engine.js';
import { writeSarif } from '../../report/sarif.js';

export async function runSast(files?: string): Promise<void> {
  const findings = await scanSast(files);
  if (findings.length === 0) {
    console.log('✅ No SAST findings detected.');
    process.exitCode = 0;
    return;
  }
  console.log(`🔐 secure-scan (sast) — ${findings.length} finding(s)`);
  for (const f of findings) {
    console.log(`  • ${f.file}:${f.line} — ${f.ruleId}: ${f.message}`);
  }
  const outputPath = writeSarif('sast', findings);
  console.log(`✅ SARIF report generated: ${outputPath}`);
  process.exitCode = 1;
}
