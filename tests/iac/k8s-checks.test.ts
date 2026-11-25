import { describe, expect, it } from 'vitest';
import { scanK8s } from '../../src/modules/iac/k8s-checks.js';

describe('scanK8s', () => {
  it('flags a privileged container', () => {
    const content = [
      'apiVersion: v1',
      'kind: Pod',
      'metadata:',
      '  name: bad-pod',
      'spec:',
      '  containers:',
      '    - name: app',
      '      image: nginx',
      '      securityContext:',
      '        privileged: true',
      '',
    ].join('\n');
    const findings = scanK8s(content, 'pod.yaml');
    expect(findings).toHaveLength(1);
    const f = findings[0];
    expect(f.ruleId).toBe('iac/k8s-privileged-container');
    expect(f.level).toBe('error');
    expect(f.file).toBe('pod.yaml');
    expect(f.line).toBe(10);
    expect(f.message).toContain('app');
  });

  it('accepts non-privileged containers', () => {
    const content = [
      'apiVersion: v1',
      'kind: Pod',
      'spec:',
      '  containers:',
      '    - name: app',
      '      image: nginx',
      '      securityContext:',
      '        privileged: false',
    ].join('\n');
    expect(scanK8s(content, 'pod.yaml')).toHaveLength(0);
  });

  it('flags hostNetwork usage', () => {
    const content = [
      'apiVersion: v1',
      'kind: Pod',
      'spec:',
      '  hostNetwork: true',
      '  containers:',
      '    - name: app',
      '      image: nginx',
    ].join('\n');
    const findings = scanK8s(content, 'pod.yaml');
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('iac/k8s-host-network');
    expect(findings[0].level).toBe('warning');
    expect(findings[0].line).toBe(4);
  });

  it('flags plaintext secret-like env values', () => {
    const content = [
      'apiVersion: v1',
      'kind: Deployment',
      'spec:',
      '  template:',
      '    spec:',
      '      containers:',
      '        - name: api',
      '          image: api:1',
      '          env:',
      '            - name: DB_PASSWORD',
      '              value: "hunter2secret99"',
    ].join('\n');
    const findings = scanK8s(content, 'deploy.yaml');
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('iac/k8s-plaintext-env-secret');
    expect(findings[0].level).toBe('error');
    expect(findings[0].line).toBe(10);
    expect(findings[0].message).toContain('DB_PASSWORD');
    expect(findings[0].message).not.toContain('hunter2secret99');
  });

  it('ignores valueFrom secret refs and non-sensitive env names', () => {
    const content = [
      'apiVersion: v1',
      'kind: Pod',
      'spec:',
      '  containers:',
      '    - name: api',
      '      env:',
      '        - name: DB_PASSWORD',
      '          valueFrom:',
      '            secretKeyRef:',
      '              name: db',
      '              key: password',
      '        - name: LOG_LEVEL',
      '          value: "debug"',
    ].join('\n');
    expect(scanK8s(content, 'pod.yaml')).toHaveLength(0);
  });

  it('handles multiple documents and reports correct lines per doc', () => {
    const content = [
      'apiVersion: v1',
      'kind: Pod',
      'spec:',
      '  containers:',
      '    - name: one',
      '      securityContext:',
      '        privileged: true',
      '---',
      'apiVersion: v1',
      'kind: Pod',
      'spec:',
      '  containers:',
      '    - name: two',
      '      securityContext:',
      '        privileged: true',
    ].join('\n');
    const findings = scanK8s(content, 'pods.yaml');
    expect(findings).toHaveLength(2);
    expect(findings[0].line).toBe(7);
    expect(findings[1].line).toBe(15);
  });

  it('throws on invalid YAML', () => {
    expect(() => scanK8s('kind: Pod\n  broken: [unclosed\n', 'bad.yaml')).toThrow(/Invalid YAML/);
  });
});
