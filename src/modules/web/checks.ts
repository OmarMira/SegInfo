import type { Finding } from '../../report/sarif.js';
import { scanWeb } from './web-engine.js';

/**
 * Analyze a live URL and return normalized findings.
 *
 * Kept as a named entry point so callers (server, future report adapters) do
 * not depend on the engine's internal fetching details.
 */
export function analyzeWebResponse(baseUrl: string): Promise<Finding[]> {
  return scanWeb(baseUrl);
}
