import type { Finding } from '../../report/sarif.js';

/**
 * High-signal, line-oriented SAST rules for JavaScript/TypeScript and Python.
 *
 * These are deliberately shallow (no AST, no data flow): they flag dangerous
 * sinks only when the argument is visibly built from a non-literal value, and
 * they never echo matched source text (findings may be pasted into reports).
 */

export type SastLanguage = 'js' | 'py';

const IDENTIFIER = /[A-Za-z_$][A-Za-z0-9_$]*/;
const KEYWORDS = /\b(?:true|false|null|undefined|None|True|False|elif|else)\b/g;

const SENSITIVE_NAME =
  /\b(?:token|password|passwd|secret|api[_-]?key|apikey|nonce|salt|otp|session|credential)\w*/i;

/** Removes a line comment, respecting string literals (`` ` ``, `'`, `"`). */
export function stripComment(line: string, language: SastLanguage): string {
  let quote: string | null = null;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (quote) {
      if (ch === '\\') {
        i++;
        continue;
      }
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      quote = ch;
      continue;
    }
    if (language === 'py' && ch === '#') return line.slice(0, i);
    if (language === 'js' && ch === '/' && line[i + 1] === '/') return line.slice(0, i);
  }
  return line;
}

/** Text of the first call argument, stopping at a top-level comma or close. */
function firstArgument(tail: string): string {
  let depth = 0;
  let quote: string | null = null;
  let out = '';
  for (let i = 0; i < tail.length; i++) {
    const ch = tail[i];
    if (quote) {
      if (ch === '\\') {
        out += ch + (tail[i + 1] ?? '');
        i++;
        continue;
      }
      out += ch;
      if (ch === quote) quote = null;
      continue;
    }
    if (ch === '"' || ch === "'" || ch === '`') {
      quote = ch;
      out += ch;
      continue;
    }
    if (ch === '(' || ch === '[' || ch === '{') {
      depth++;
      out += ch;
      continue;
    }
    if (ch === ')' || ch === ']' || ch === '}') {
      if (depth === 0) break;
      depth--;
      out += ch;
      continue;
    }
    if (ch === ',' && depth === 0) break;
    out += ch;
  }
  return out;
}

function hasIdentifier(code: string): boolean {
  return IDENTIFIER.test(code.replace(KEYWORDS, ' '));
}

/**
 * True when an expression is not a pure literal: it references an identifier
 * or interpolates one. `${1 + 2}` and `'fixed text'` are static.
 */
function isDynamicExpression(expression: string): boolean {
  const interpolations: string[] = [];
  const interpolation = /\$\{([^}]*)\}/g;
  let match: RegExpExecArray | null;
  while ((match = interpolation.exec(expression)) !== null) interpolations.push(match[1]);

  const withoutStrings = expression.replace(/'[^']*'|"[^"]*"|`[^`]*`/g, ' ');
  const withoutNumbers = withoutStrings.replace(/\b\d+(?:\.\d+)?\b/g, ' ');
  return hasIdentifier(withoutNumbers) || hasIdentifier(interpolations.join(' '));
}

function lineHasIdentifierOutsideStrings(line: string): boolean {
  return hasIdentifier(line.replace(/'[^']*'|"[^"]*"|`[^`]*`/g, ' '));
}

function finding(
  ruleId: string,
  message: string,
  file: string,
  line: number,
  level: Finding['level'],
  properties: Record<string, unknown>,
): Finding {
  return { ruleId, message, file, line, column: 1, level, properties };
}

const SQL_CALL = /\.(?:query|execute|raw|exec_sql)\s*\(/i;
const INNER_HTML = /\.innerHTML\s*=\s*/;
const HTML_SINK = /\b(?:document\.write|insertAdjacentHTML)\s*\(/;
const COMMAND_CALL = /\b(?:execSync|exec|spawnSync|spawn|os\.system)\s*\(/;
const SUBPROCESS_CALL = /\bsubprocess\.\w+\s*\(/;
const EVAL_CALL = /(?:\beval|new\s+Function)\s*\(/;
const WEAK_HASH = /(?:createHash|createHmac)\s*\(\s*['"](?:md5|sha1)['"]/i;
const WEAK_HASH_PY = /\bhashlib\.(?:md5|sha1)\s*\(/i;
const INSECURE_RANDOM_JS = /\bMath\.random\s*\(/;
const INSECURE_RANDOM_PY = /\brandom\.(?:randint|randrange|choice|random|sample)\s*\(/;

function scanLine(
  line: string,
  language: SastLanguage,
  file: string,
  lineNumber: number,
): Finding[] {
  const hits: Finding[] = [];
  const tailAfter = (match: RegExpExecArray): string =>
    line.slice((match.index ?? 0) + match[0].length);

  const sql = SQL_CALL.exec(line);
  if (sql && isDynamicExpression(firstArgument(tailAfter(sql)))) {
    hits.push(
      finding(
        'sast/sql-injection',
        'Possible SQL injection: a dynamic value is concatenated into a query.',
        file,
        lineNumber,
        'error',
        { language },
      ),
    );
  }

  const innerHtml = INNER_HTML.exec(line);
  if (innerHtml) {
    if (isDynamicExpression(tailAfter(innerHtml))) {
      hits.push(
        finding(
          'sast/xss-innerhtml',
          'Possible XSS: untrusted data is written to an HTML sink.',
          file,
          lineNumber,
          'warning',
          { sink: 'innerHTML', language },
        ),
      );
    }
  }

  const htmlSink = HTML_SINK.exec(line);
  if (htmlSink) {
    const args = tailAfter(htmlSink);
    if (lineHasIdentifierOutsideStrings(args) || isDynamicExpression(firstArgument(args))) {
      hits.push(
        finding(
          'sast/xss-innerhtml',
          'Possible XSS: untrusted data is written to an HTML sink.',
          file,
          lineNumber,
          'warning',
          { sink: htmlSink[0].replace(/\s*\($/, ''), language },
        ),
      );
    }
  }

  const command = COMMAND_CALL.exec(line);
  if (command && isDynamicExpression(firstArgument(tailAfter(command)))) {
    hits.push(
      finding(
        'sast/command-injection',
        'Possible command injection: a dynamic value reaches a shell/exec sink.',
        file,
        lineNumber,
        'warning',
        { language },
      ),
    );
  }

  const subprocess = SUBPROCESS_CALL.exec(line);
  if (subprocess && /shell\s*=\s*True/.test(line)) {
    const args = tailAfter(subprocess);
    if (lineHasIdentifierOutsideStrings(args)) {
      hits.push(
        finding(
          'sast/command-injection',
          'Possible command injection: a dynamic value reaches a shell/exec sink.',
          file,
          lineNumber,
          'warning',
          { language },
        ),
      );
    }
  }

  const evalCall = EVAL_CALL.exec(line);
  if (evalCall && isDynamicExpression(firstArgument(tailAfter(evalCall)))) {
    hits.push(
      finding(
        'sast/eval-usage',
        'Dynamic code evaluation can execute attacker-controlled code.',
        file,
        lineNumber,
        'warning',
        { language },
      ),
    );
  }

  if (WEAK_HASH.test(line) || (language === 'py' && WEAK_HASH_PY.test(line))) {
    hits.push(
      finding(
        'sast/weak-hash',
        'Weak hash algorithm (MD5/SHA-1) used for cryptographic purposes.',
        file,
        lineNumber,
        'warning',
        { language },
      ),
    );
  }

  const insecureRandom =
    (language === 'js' && INSECURE_RANDOM_JS.test(line)) ||
    (language === 'py' && INSECURE_RANDOM_PY.test(line));
  if (insecureRandom && SENSITIVE_NAME.test(line)) {
    hits.push(
      finding(
        'sast/insecure-random',
        'Insecure randomness used for a sensitive value (token/password/secret).',
        file,
        lineNumber,
        'note',
        { language },
      ),
    );
  }

  // A single sink can match two rules on one line; keep one finding per rule.
  const seen = new Set<string>();
  return hits.filter((hit) => {
    if (seen.has(hit.ruleId)) return false;
    seen.add(hit.ruleId);
    return true;
  });
}

/** Scans source text content and returns findings (line-oriented heuristics). */
export function scanSastContent(
  content: string,
  file: string,
  language: SastLanguage,
): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const code = stripComment(lines[i], language);
    if (code.trim().length === 0) continue;
    findings.push(...scanLine(code, language, file, i + 1));
  }
  return findings;
}
