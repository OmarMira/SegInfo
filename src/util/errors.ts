/**
 * Thrown by a module when the scan target contains nothing it can analyze
 * (e.g. no manifests for SCA, no .tf/.yaml for IaC). The orchestrator treats
 * this as an honest skip — never as a failure and never as a clean result
 * for that module.
 */
export class NothingToScanError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'NothingToScanError';
  }
}
