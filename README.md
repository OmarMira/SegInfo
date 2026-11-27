# @seginfo/secure-scan

Modular security scanner: **Secrets + SCA + IaC**, with SARIF 2.1.0 output for CI.

## Modes

| Mode | What it does |
|------|--------------|
| `all` (default) | Runs `leakscan` + `sca` + `iac` in parallel, merges one SARIF (one run per module), exit code by severity |
| `leakscan` | Detects secrets/credentials in the working tree **and git history** |
| `sca` | Flags vulnerable dependencies (npm `package-lock.json`, Python `requirements.txt`) against [OSV](https://osv.dev) |
| `iac` | Terraform + Kubernetes misconfigurations (public S3, open security groups, privileged containers, plaintext secrets) |
| `sast` | Source-level patterns: SQL injection, XSS sinks, command injection, `eval`, weak hashes, insecure randomness |
| `web` | Live URL header/cookie audit (HSTS, CSP, X-Frame-Options, Referrer-Policy, cookie flags, version disclosure) |
| `repo` | (local UI/API) Shallow-clones a public Git repository and runs the default modules |
| `serve` | Local web UI + JSON API (see below) |

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
npm run scan -- --mode sast --files "src/**"
npm run scan -- --mode web --files https://example.com

# Local web UI (browser) — loopback only
npm run serve                       # http://127.0.0.1:4310, opens the browser
npm run serve -- --port 8080 --no-open

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

## Local web UI

`secure-scan serve` starts a local-only server with a browser UI, so the scanner
can be used without the CLI:

```bash
npm run serve                     # -> http://127.0.0.1:4310 (opens the browser)
npm run serve -- --port 8080      # custom port
npm run serve -- --no-open        # just print the URL
npm run build && node dist/cli.js serve
```

Pick a mode, choose a folder with the **Browse...** button (or type a path, a
URL for `web`, or `owner/repo` for `repo`) and scan. The page shows a
**provenance block** (where the code came from, ref/commit, when it was
scanned and what was actually covered), a **package table** for vulnerable
dependencies, and the triaged groups with severity, rule, location and message.
Skipped modules and failed modules are listed honestly instead of being
reported as a clean pass.

Hover a row (or focus it with `Tab`) to see why **that specific finding** was
reported and how to fix it: the rule's explanation in Spanish, the evidence the
module captured (secret pattern and entropy, CVE/package/fixed version,
container or header name) and a rule-specific remediation, separate from the
generic triage bucket advice. For a **direct** dependency the fix names the
version to upgrade to and the package-manager command
(`npm install lodash@4.17.21`, `pip install -U "requests>=2.31.0"`); for a
**transitive** one it names the package(s) that introduce it and never suggests
installing it directly. For leaked secrets it lists the rotation step for that
provider. **Limpiar** resets the form, the results and the status for a fresh
scan (it also cancels an in-flight scan).

Mode `repo` shallow-clones a public Git repository into a temp folder, scans it
with the default modules and always deletes the clone afterwards. Only `https`
URLs on GitHub/GitLab/Bitbucket are accepted (no ssh, no credentials). A cloned
repository cannot weaken its own scan: any `secure-scan.config.json` it ships is
ignored. The report labels that copy as a **cloned repository** (not a local
working tree), records its branch and commit, and flags the shallow history as
incomplete.

Browser scans **never write files into the scanned directory** (no SARIF side
effect) — only the CLI writes the report. Use the CLI for CI artifacts.

### Triage

Every finding is classified into exactly one bucket and nothing is hidden:

| Bucket | Meaning |
|--------|---------|
| `confirmed` | Objective external evidence: the CVE is in **CISA KEV** (known exploited). |
| `review` | Needs a human decision, with a rule-family reason (e.g. SAST matches are never data-flow confirmed, secrets may be dead, IaC may not be deployed). |
| `likely-example` | The path looks like tests, fixtures, docs, demos or vendored code. |

Identical findings (same rule, file and message) collapse into one row with a
count and all line numbers, so duplicates no longer drown the real problems.
The bucket is also written to `properties.triage = { bucket, reason }` in every
finding (SARIF and API), so any consumer can explain the classification.

### Dependency graph (SCA)

`sca` findings keep their existing shape and add facts to `properties`, so a
consumer can explain where a vulnerable package comes from:

| Property | Meaning |
|----------|---------|
| `direct` | `true`/`false` for the installed copy the root resolves; `null` when the manifests cannot tell |
| `dev` | `true` when only reachable through dev dependencies; `null` when unknown |
| `introducedBy` | Immediate packages that require it, as `name@version` |
| `paths` | Introduction chains such as `next > undici` (capped for display) |
| `pathsTotal` / `pathsTruncated` | Real chain count and whether `paths` is shorter than it |
| `locations` | Every manifest location that pins `name@version` |
| `advisoryModified` / `advisoryPublished` | Advisory timestamps from OSV; `null` when absent |

Directness is resolved per installed instance, not per name: `a@2.0.0` can be a
direct dependency while a nested `a@1.0.0` is transitive. Python
`requirements.txt` pins keep `direct`/`dev` as `null`, because the file alone
cannot prove them.

### Grouped SCA report

The API adds a package-grouped `sca` view next to the untouched flat
`findings`/`triage` data, and the UI renders it as one row per resolved package
(`name@version`) instead of one row per advisory. Grouping never reduces the
total: `sca.summary` reports **packages**, **distinct advisories** and
**occurrences** separately, and every advisory keeps its id, aliases, severity,
level, `fixedIn`, KEV flag, advisory timestamps and manifest locations.

Each package also carries `direct`/`dev` (only `true` when every resolved
instance agrees), `introducedBy`, the introduction paths and a `fixTarget`: the
smallest published fixed version above the installed one, preferring the same
major and a stable release. The remediation text for a transitive package tells
the reader to update the package that introduces it — it never recommends a
direct install and never promises that updating the parent will change the
resolved version.

### Provenance

Every `POST /api/scan` response includes `provenance`, so a report can state
where the scanned code came from without inventing metadata:

| Field | Meaning |
|-------|---------|
| `origin` | `repository-clone`, `local-path` or `remote-url` |
| `source` | Repository URL, local absolute path or live URL |
| `ref` / `commit` / `dirty` | Checked-out branch, full HEAD sha and uncommitted changes; `null` when unknown or not a repository |
| `scannedAt` | ISO timestamp of the scan start |
| `scope.workingTree` | Whether the current file tree was walked |
| `scope.gitHistory` / `scope.history` | Whether a history pass ran, plus the observed `HistoryCoverage` (`commitsScanned`, `shallow`, `truncated`, `error`) |
| `scope.manifests` | Manifests the SCA module actually read |
| `vulnerabilityData` | `{ source: 'OSV', latestAdvisoryUpdate }`, or `null` when SCA did not run |

`latestAdvisoryUpdate` is the newest advisory `modified` timestamp seen in the
scan; OSV does not publish a feed-wide update date, so none is invented. A
temporary clone is always reported as `repository-clone`, never as a local
working tree, and a shallow clone is flagged as incomplete history.

### JSON API

| Method | Path          | Body                                        |
|--------|---------------|---------------------------------------------|
| `GET`  | `/api/health` | —                                           |
| `GET`  | `/api/browse?path=<dir>` | — (lists subdirectories for the folder picker) |
| `POST` | `/api/scan`   | `{ "mode": "all", "target": "/path/to/repo", "config": "optional.json" }` |

To scan a repository, use `mode: "repo"` with `target` set to `owner/repo` or a
full `https://github.com/owner/repo` URL:

```json
{ "mode": "repo", "target": "octocat/Hello-World" }
```

`POST /api/scan` answers with `{ mode, target, findings, skipped, failures,
elapsedMs, triage, sca?, provenance }`, where `findings` uses the shared
`Finding` shape (`ruleId`, `message`, `file`, `line`, `column`, `level`,
`properties`), `triage` is `{ summary: { total, confirmed, review, likelyExample },
groups: [...] }`, `sca` is present only when the SCA module ran, and
`provenance` is always present (see **Provenance** above).

### Safety defaults

- Binds `127.0.0.1` unless `--host` is passed explicitly (with a warning).
- Rejects requests whose `Host` is not loopback/localhost (DNS-rebinding guard)
  and browser `Origin`s that differ from the request host.
- Requires `Content-Type: application/json`, caps bodies at 64 KiB, sends no
  CORS headers, and serves the UI under a strict CSP.

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
