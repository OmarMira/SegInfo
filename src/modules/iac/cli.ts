/**
 * IaC module entry point — Terraform and Kubernetes YAML misconfigurations.
 * TODO(T4): implement .tf and K8s YAML checks (privileged containers,
 * public S3 buckets, open security groups, embedded secrets).
 */
export async function runIac(_files: string | undefined): Promise<void> {
  throw new Error('iac mode is not implemented yet (task T4).');
}
