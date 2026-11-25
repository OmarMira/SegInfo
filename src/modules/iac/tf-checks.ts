import type { Finding } from '../../report/sarif.js';

/**
 * Terraform (HCL) checks — line-oriented block scanner.
 *
 * Not a full HCL parser: it tracks `resource` blocks with brace depth
 * (comments and string literals are stripped before counting), which is
 * enough to scope S3/SG rules and robust against formatted files. Block
 * comments (`/* *\/`) are not stripped — a brace inside one is an accepted
 * MVP limitation.
 */

const RESOURCE_RE = /^\s*resource\s+"([^"]+)"\s+"([^"]+)"\s*\{/;
const PUBLIC_ACL_RE = /\bacl\s*=\s*"(public-read(?:-write)?)"/;
const OPEN_CIDR_RE = /"(?:0\.0\.0\.0\/0|::\/0)"/;
const INGRESS_OPEN_RE = /^\s*ingress\s*\{/;
const SG_RULE_INGRESS_RE = /\btype\s*=\s*"ingress"/;
const FROM_PORT_RE = /\bfrom_port\s*=\s*(\d+)/;
const TO_PORT_RE = /\bto_port\s*=\s*(\d+)/;
const SECRET_RE =
  /^\s*[A-Za-z_]*(?:password|passwd|secret|token|api_key|access_key)[A-Za-z_]*\s*=\s*"([^"]{8,})"/i;
const SENSITIVE_PORTS = [22, 3389];

function stripComment(line: string): string {
  let inString = false;
  for (let i = 0; i < line.length; i++) {
    const ch = line[i];
    if (ch === '"' && line[i - 1] !== '\\') inString = !inString;
    if (!inString && (ch === '#' || (ch === '/' && line[i + 1] === '/'))) {
      return line.slice(0, i);
    }
  }
  return line;
}

function stripStrings(code: string): string {
  return code.replace(/"(?:[^"\\]|\\.)*"/g, '""');
}

function countChar(text: string, char: string): number {
  let n = 0;
  for (let i = 0; i < text.length; i++) if (text[i] === char) n++;
  return n;
}

function covers(from: number | null, to: number | null, port: number): boolean {
  if (from === null || to === null) return false;
  return from <= port && port <= to;
}

export function scanTerraform(content: string, file: string): Finding[] {
  const findings: Finding[] = [];
  const lines = content.split('\n');

  let resource: { type: string; name: string } | null = null;
  let depth = 0;
  let ingressDepth: number | null = null;
  let ingressFrom: number | null = null;
  let ingressTo: number | null = null;
  let ruleIsIngress = false;
  let openReported = false;

  const push = (
    line: number,
    ruleId: string,
    level: Finding['level'],
    message: string,
    properties: Record<string, unknown>,
  ): void => {
    findings.push({ ruleId: `iac/${ruleId}`, message, file, line, column: 1, level, properties });
  };

  const checkSecret = (code: string, line: number): void => {
    const m = SECRET_RE.exec(code);
    if (!m) return;
    const value = m[1];
    if (value.includes('${')) return; // variable/local reference, not a literal
    push(line, 'tf-hardcoded-secret', 'error', 'Hardcoded credential literal in Terraform', {
      check: 'tf-hardcoded-secret',
    });
  };

  for (let i = 0; i < lines.length; i++) {
    const code = stripComment(lines[i]);
    const counting = stripStrings(code);
    const opens = countChar(counting, '{');
    const closes = countChar(counting, '}');

    if (!resource) {
      const m = RESOURCE_RE.exec(code);
      if (m) {
        resource = { type: m[1], name: m[2] };
        depth = opens - closes;
        ingressDepth = null;
        ingressFrom = null;
        ingressTo = null;
        ruleIsIngress = false;
        openReported = false;
        continue;
      }
      checkSecret(code, i + 1);
      continue;
    }

    const resourceLabel = `${resource.type}.${resource.name}`;
    const lineNo = i + 1;

    if (resource.type === 'aws_s3_bucket') {
      const acl = PUBLIC_ACL_RE.exec(code);
      if (acl) {
        push(
          lineNo,
          's3-public-acl',
          'error',
          `S3 bucket ${resourceLabel} is publicly readable (acl = "${acl[1]}")`,
          { resource: resourceLabel, acl: acl[1] },
        );
      }
    }

    if (resource.type === 'aws_security_group_rule' && SG_RULE_INGRESS_RE.test(code)) {
      ruleIsIngress = true;
    }
    const from = FROM_PORT_RE.exec(code);
    if (from) ingressFrom = Number(from[1]);
    const to = TO_PORT_RE.exec(code);
    if (to) ingressTo = Number(to[1]);

    if (INGRESS_OPEN_RE.test(code)) {
      ingressDepth = depth; // depth before this line's brace
      openReported = false; // each ingress block reports its own exposure
    }

    const inIngress =
      ingressDepth !== null ||
      ruleIsIngress ||
      resource.type === 'aws_vpc_security_group_ingress_rule';

    if (inIngress && !openReported && OPEN_CIDR_RE.test(code)) {
      const sensitive =
        covers(ingressFrom, ingressTo, SENSITIVE_PORTS[0]) ||
        covers(ingressFrom, ingressTo, SENSITIVE_PORTS[1]);
      if (sensitive) {
        push(
          lineNo,
          'sg-sensitive-port-open',
          'error',
          `Security group ${resourceLabel} exposes port ${ingressFrom}-${ingressTo} to the internet`,
          { resource: resourceLabel, fromPort: ingressFrom, toPort: ingressTo },
        );
      } else {
        push(
          lineNo,
          'sg-open-to-world',
          'warning',
          `Security group ${resourceLabel} allows ingress from the entire internet`,
          { resource: resourceLabel },
        );
      }
      openReported = true;
    }

    checkSecret(code, lineNo);

    // Apply this line's braces to the depth state.
    depth += opens - closes;
    if (ingressDepth !== null && depth <= ingressDepth) {
      ingressDepth = null;
      ingressFrom = null;
      ingressTo = null;
    }
    if (depth <= 0) {
      resource = null;
      depth = 0;
    }
  }

  return findings;
}
