import * as fs from 'node:fs';
import * as path from 'node:path';

// Simple entropy calculation
function calcEntropy(text: string): number {
  const freq = new Map<string, number>();
  for (const ch of text) {
    freq.set(ch, (freq.get(ch) || 0) + 1);
  }
  let entropy = 0;
  const len = text.length;
  for (const count of freq.values()) {
    const p = count / len;
    if (p > 0) entropy -= p * Math.log2(p);
  }
  return Math.round(entropy * 100) / 100; // 2 decimals
}

// Git history extraction (simplified: reads from .git/refs or packed-refs)
// For a real scanner we'd use git CLI or libgit2, but we'll walk the working tree + .git
async function* walkGitHistory(root: string): AsyncGenerator<string[]> {
  // Yield file paths with content from git history + working tree
  const entries = await fs.promises.readdir(root, { recursive: true, withFileTypes: true });
  for (const entry of entries) {
    if (entry.isDirectory()) continue;
    const full = path.join(root, entry.name);
    if (entry.name.endsWith('.js') || entry.name.endsWith('.ts') || entry.name.endsWith('.py') || entry.name.endsWith('.json') || entry.name.endsWith('.yaml') || entry.name.endsWith('.yml') || entry.name.endsWith('.env')) {
      try {
        const content = await fs.promises.readFile(full, 'utf-8');
        yield [full, content];
      } catch {
        // skip unreadable
      }
    }
  }
}

// Known secret patterns (regex + type labels)
const SECRET_PATTERNS = [
  // AWS keys
  { pattern: /AKIA[0-9A-Z]{16}/, type: 'aws-access-key' },
  { pattern: /[0-9a-zA-Z/+=]{39,}/, type: 'possible-aws-secret' }, // simplified
  // GitHub tokens
  { pattern: /gh[pousr]?[0-9A-Za-z]{36,}/, type: 'github-token' },
  // Generic API keys
  { pattern: /[a-zA-Z0-9]{32,}=/, type: 'api-key-hash' },
  { pattern: /eyJhbGciOiJIUzI1NiJ9[^\s]+/, type: 'jwt-token' },
  // Database URLs with credentials
  { pattern: /postgres?:\/\/[^\s]+:[^\s]@/, type: 'db-url-credentials' },
  // Generic secrets-looking strings high entropy
  { pattern: /[A-Za-z0-9]{20,}/, type: 'high-entropy-string', condition: (s: string) => calcEntropy(s) > 4.0 },
];

export async function scanRepo(root?: string): Promise<Array<{ file: string; line: number; type: string; entropy: number }>> {
  const searchRoot = root || process.cwd();
  const results: Array<{ file: string; line: number; type: string; entropy: number }> = [];

  for await (const [file, content] of walkGitHistory(searchRoot)) {
    const lines = content.split('\n');
    for (let li = 0; li < lines.length; li++) {
      const line = lines[li];
      for (const { pattern, type, condition } of SECRET_PATTERNS) {
        if (pattern.test(line)) {
          // Apply condition if present
          if (condition && !condition(line)) continue;
          // Truncate long lines for entropy calc but use full for pattern match
          const entropy = calcEntropy(line);
          results.push({ file, line: li + 1, type, entropy });
          // Break after first match per line to avoid duplicates
          break;
        }
      }
    }
  }
  // Deduplicate by file:line
  const seen = new Set<string>();
  return results.filter(r => {
    const key = `${r.file}:${r.line}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}