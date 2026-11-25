# @seginfo/secure-scan

Modular security scanner: **Secrets + SCA + IaC**, with SARIF 2.1.0 output for CI.

## Modes

| Mode | What it does |
|------|--------------|
| `all` (default) | Runs `leakscan` + `sca` + `iac` in parallel, merges one SARIF (one run per module), exit code by severity |
| `leakscan` | Detects secrets/credentials in the working tree **and git history** |
| `sca` | Flags vulnerable dependencies (npm `package-lock.json`, Python `requirements.txt`) against [OSV](https://osv.dev) |
| `iac` | Terraform + Kubernetes misconfigurations (public S3, open security groups, privileged containers, plaintext secrets) |

## Usage

```bash
npm install
npm test                                    # run the test suite

# All modules against the current directory (default mode)
npm run scan

# A specific directory
npm run scan -- --files /path/to/repo

# Single modules (file/glob targets allowed)
npm run scan -- --mode leakscan --files "src/**"
npm run scan -- --mode sca
npm run scan -- --mode iac --files infra/

# Production build
npm run build && node dist/cli.js
```

Exit codes: `0` = clean (at the configured threshold), `1` = findings at/above
`failOn`, **or any module failure** (an outage is never reported as a clean scan).

## Configuration

Place `secure-scan.config.json` in the scanned directory (or pass `--config <path>`):

```json
{
  "modules": ["leakscan", "sca", "iac"],
  "output": "seginfo-secure-scan-results.sarif",
  "failOn": "warning",
  "ignore": ["tests/**"]
}
```

- `modules` — subset to run, in report order.
- `output` — SARIF path, relative to the scanned directory.
- `failOn` — lowest level that fails the run: `error`, `warning` (default) or `note`.
- `ignore` — glob patterns whose findings are excluded from the report.

Modules with nothing to scan (no manifests, no IaC files) are reported as
**skipped with a reason** — never as a clean pass and never as a failure.

## GitHub Action

```yaml
# .github/workflows/secure-scan.yml
name: secure-scan
on: [push, pull_request]
permissions:
  contents: read
  security-events: write   # upload SARIF to the Security tab
  pull-requests: write     # post/update the PR comment
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: seginfo/secure-scan@v1   # or ./ for this repository
        with:
          token: ${{ github.token }}
          # files: '.'                # directory to scan
          # config: ''                # explicit config path
```

The action builds itself (`npm ci` + `npm run build`), runs the orchestrator,
uploads the merged SARIF to the repository's **Security tab** (code scanning
REST API) and posts a summary comment on pull requests (updated in place on
re-runs via the `<!-- seginfo-secure-scan -->` marker). Reporting failures are
printed as warnings and never change the scan's exit code.

## Development

- TypeScript strict mode, ESM (`NodeNext`), Node >= 20.
- `npm run typecheck` / `npm run lint` for static checks.
- Modules live under `src/modules/<name>/` and normalize findings to the
  shared `Finding` type in `src/report/sarif.ts`.
- Test-first: `tests/` mirrors `src/`; run `npm test`.
