import type { Finding } from '../../report/sarif.js';

/**
 * SCA engine — resolves lockfiles against OSV / GitHub Advisory Database.
 * TODO(T3): implement package-lock.json + requirements.txt parsing and
 * OSV API queries with an on-disk cache. Stub fails loudly instead of
 * reporting a false "no vulnerabilities found".
 */
export async function scanDependencies(_root?: string): Promise<Finding[]> {
  throw new Error('sca mode is not implemented yet (task T3).');
}
