import { describe, expect, it } from 'vitest';
import { scanTerraform } from '../../src/modules/iac/tf-checks.js';

describe('scanTerraform', () => {
  it('flags a public S3 bucket ACL', () => {
    const content = [
      'resource "aws_s3_bucket" "data" {',
      '  bucket = "company-data"',
      '  acl    = "public-read"',
      '}',
    ].join('\n');
    const findings = scanTerraform(content, 'main.tf');
    expect(findings).toHaveLength(1);
    const f = findings[0];
    expect(f.ruleId).toBe('iac/s3-public-acl');
    expect(f.level).toBe('error');
    expect(f.file).toBe('main.tf');
    expect(f.line).toBe(3);
    expect(f.message).toContain('aws_s3_bucket.data');
  });

  it('accepts private bucket ACLs', () => {
    const content = ['resource "aws_s3_bucket" "data" {', '  acl = "private"', '}'].join('\n');
    expect(scanTerraform(content, 'main.tf')).toHaveLength(0);
  });

  it('flags an ingress security group open to the world', () => {
    const content = [
      'resource "aws_security_group" "web" {',
      '  ingress {',
      '    from_port   = 443',
      '    to_port     = 443',
      '    cidr_blocks = ["0.0.0.0/0"]',
      '  }',
      '}',
    ].join('\n');
    const findings = scanTerraform(content, 'sg.tf');
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('iac/sg-open-to-world');
    expect(findings[0].level).toBe('warning');
    expect(findings[0].line).toBe(5);
  });

  it('escalates when SSH/RDP ports are open to the world', () => {
    const content = [
      'resource "aws_security_group" "mgmt" {',
      '  ingress {',
      '    from_port   = 22',
      '    to_port     = 22',
      '    cidr_blocks = ["0.0.0.0/0"]',
      '  }',
      '}',
    ].join('\n');
    const findings = scanTerraform(content, 'sg.tf');
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('iac/sg-sensitive-port-open');
    expect(findings[0].level).toBe('error');
  });

  it('flags aws_security_group_rule with type ingress and world cidr', () => {
    const content = [
      'resource "aws_security_group_rule" "rdp" {',
      '  type        = "ingress"',
      '  from_port   = 3389',
      '  to_port     = 3389',
      '  cidr_blocks = ["0.0.0.0/0"]',
      '}',
    ].join('\n');
    const findings = scanTerraform(content, 'rule.tf');
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('iac/sg-sensitive-port-open');
  });

  it('ignores restricted CIDR ranges', () => {
    const content = [
      'resource "aws_security_group" "internal" {',
      '  ingress {',
      '    from_port   = 443',
      '    to_port     = 443',
      '    cidr_blocks = ["10.0.0.0/16"]',
      '  }',
      '}',
    ].join('\n');
    expect(scanTerraform(content, 'sg.tf')).toHaveLength(0);
  });

  it('flags hardcoded secrets but not variable references', () => {
    const content = [
      'resource "aws_db_instance" "db" {',
      '  password        = "Sup3rSecretPassw0rd"',
      '  password_again  = var.db_password',
      '  token           = "${local.auth_token}"',
      '}',
    ].join('\n');
    const findings = scanTerraform(content, 'db.tf');
    expect(findings).toHaveLength(1);
    expect(findings[0].ruleId).toBe('iac/tf-hardcoded-secret');
    expect(findings[0].level).toBe('error');
    expect(findings[0].line).toBe(2);
    expect(findings[0].message).not.toContain('Sup3rSecretPassw0rd');
  });

  it('ignores comments when matching rules', () => {
    const content = [
      '# acl = "public-read"',
      'resource "aws_s3_bucket" "b" {',
      '  # password = "NotARealSecret123"',
      '  bucket = "b"',
      '}',
    ].join('\n');
    expect(scanTerraform(content, 'main.tf')).toHaveLength(0);
  });
});
