import { scanRepo } from './leak-scan-engine.js';
import { writeSarif, type Finding } from '../../report/sarif.js';

export async function runScan(files: string | undefined): Promise<void> {
  const raw = await scanRepo(files || undefined);
  const findings: Finding[] = raw.map((f) => ({
    ruleId: `leakscan/${f.type}`,
    message: `Potential secret (${f.type}) found in ${f.source}`,
    file: f.file,
    line: f.line,
    column: 1,
    level: 'warning',
    properties: {
      entropy: f.entropy,
      type: f.type,
      source: f.source,
      ...(f.commit ? { commit: f.commit } : {}),
    },
  }));
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
