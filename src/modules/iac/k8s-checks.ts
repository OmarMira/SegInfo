import { loadAll } from 'js-yaml';
import type { Finding } from '../../report/sarif.js';

/**
 * Kubernetes manifest checks (Pod, Deployment, StatefulSet, DaemonSet,
 * ReplicaSet, Job, CronJob). YAML parsing is done by js-yaml; line numbers
 * are recovered by locating the marker text sequentially, one counter per
 * marker so multi-document files stay accurate.
 */

const SECRETISH_ENV = /(PASSWORD|PASSWD|SECRET|TOKEN|PRIVATE_KEY|API_KEY|ACCESS_KEY)/i;
const TEMPLATE_KINDS = new Set([
  'Deployment',
  'StatefulSet',
  'DaemonSet',
  'ReplicaSet',
  'Job',
]);

function asRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function extractPodSpec(doc: Record<string, unknown>): Record<string, unknown> | null {
  const spec = asRecord(doc.spec);
  if (!spec || typeof doc.kind !== 'string') return null;
  if (doc.kind === 'Pod') return spec;
  if (TEMPLATE_KINDS.has(doc.kind)) {
    return asRecord(asRecord(spec.template)?.spec);
  }
  if (doc.kind === 'CronJob') {
    const jobTemplate = asRecord(spec.jobTemplate);
    const jobSpec = asRecord(jobTemplate?.spec);
    return asRecord(asRecord(jobSpec?.template)?.spec);
  }
  return null;
}

export function scanK8s(content: string, file: string): Finding[] {
  let docs: unknown[];
  try {
    docs = loadAll(content);
  } catch (err) {
    const reason = err instanceof Error ? err.message.split('\n')[0] : String(err);
    throw new Error(`Invalid YAML in ${file}: ${reason}`, { cause: err });
  }

  const findings: Finding[] = [];
  const markerCounts = new Map<string, number>();

  const lineOf = (marker: string): number => {
    const seen = markerCounts.get(marker) ?? 0;
    let index = -1;
    for (let i = 0; i <= seen; i++) {
      index = content.indexOf(marker, index + 1);
      if (index < 0) break;
    }
    if (index < 0) return 1;
    markerCounts.set(marker, seen + 1);
    return content.slice(0, index).split('\n').length;
  };

  const push = (
    ruleId: string,
    level: Finding['level'],
    line: number,
    message: string,
    properties: Record<string, unknown>,
  ): void => {
    findings.push({ ruleId: `iac/${ruleId}`, message, file, line, column: 1, level, properties });
  };

  for (const doc of docs) {
    const record = asRecord(doc);
    if (!record) continue;
    const spec = extractPodSpec(record);
    if (!spec) continue;

    if (spec.hostNetwork === true) {
      push(
        'k8s-host-network',
        'warning',
        lineOf('hostNetwork: true'),
        'Pod runs on the host network (hostNetwork: true)',
        { kind: record.kind },
      );
    }

    const containers = [...asArray(spec.containers), ...asArray(spec.initContainers)];
    for (const raw of containers) {
      const container = asRecord(raw);
      if (!container) continue;
      const name = typeof container.name === 'string' ? container.name : '<unnamed>';
      const securityContext = asRecord(container.securityContext);
      if (securityContext?.privileged === true) {
        push(
          'k8s-privileged-container',
          'error',
          lineOf('privileged: true'),
          `Container "${name}" runs privileged (securityContext.privileged: true)`,
          { container: name },
        );
      }
      for (const rawEnv of asArray(container.env)) {
        const env = asRecord(rawEnv);
        if (!env || typeof env.name !== 'string') continue;
        if (!SECRETISH_ENV.test(env.name)) continue;
        if (typeof env.value !== 'string' || env.value.length === 0) continue;
        if (env.valueFrom !== undefined) continue; // sourced from a Secret/ConfigMap
        push(
          'k8s-plaintext-env-secret',
          'error',
          lineOf(`name: ${env.name}`),
          `Env var "${env.name}" carries a plaintext secret value`,
          { envVar: env.name },
        );
      }
    }
  }
  return findings;
}
