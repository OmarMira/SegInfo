# @seginfo/secure-scan

Modular security scanner: **SCA + Secrets + IaC**, with SARIF 2.1.0 output for CI.

## Status

MVP in progress (see `odd/tasks/mvp-secure-scan.md` for the task board).

| Mode | What it does | Status |
|------|--------------|--------|
| `leakscan` | Detects secrets/credentials in the working tree | in progress (T2) |
| `sca` | Flags vulnerable dependencies (OSV / GitHub Advisory) | stub (T3) |
| `iac` | Terraform / Kubernetes misconfigurations | stub (T4) |

## Usage

```bash
npm install
npm run scan -- --mode leakscan            # scan current directory
npm run scan -- --mode leakscan --files .  # scan a specific path
npm test                                    # run the test suite
npm run build && npm run scan:ci            # production build
```

Exit codes: `0` = no findings, `1` = findings reported or error.

Reports are written to `seginfo-secure-scan-results.sarif` (git-ignored).

## Development

- TypeScript strict mode, ESM (`NodeNext`), Node >= 20.
- `npm run lint` / `npm run format` for static checks.
- Modules live under `src/modules/<name>/` and must normalize findings to the
  shared `Finding` type in `src/report/sarif.ts`.
