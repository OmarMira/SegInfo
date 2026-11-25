/**
 * Orchestrator entry point — runs leakscan + sca + iac in parallel and
 * merges their SARIF reports.
 * TODO(T5): implement parallel execution, SARIF merge, severity-based
 * exit codes and config file loading.
 */
export async function runOrchestrator(_files: string | undefined): Promise<void> {
  throw new Error('orchestrator is not implemented yet (task T5).');
}
