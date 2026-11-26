# Local web UI (`secure-scan serve`) — browser-based scanning

- Objective: expose the scanner over a loopback-only HTTP server with a single-page UI and JSON API, usable from the user's own PC.
- Branch: `feat/secure-scan-v2` (current working tree). Delivery: `ask-on-risk`. Runner: `npm test` (vitest).
- Test-first: RED -> GREEN per rule where a runnable test exists.

## Specs

**S1** — User (2026-11-25): "podes continuar para hacer un servidor local asi lo puedo usar desde mi pc?"

**S2** — The server must be startable with `secure-scan serve` (and `npm run serve`), listening on `127.0.0.1` by default, and print the URL to open.

**S3** — The browser UI must let the user pick a mode (`all`, `leakscan`, `sca`, `iac`, `sast`, `web`), choose a directory with a folder picker (or type it) or enter a URL, run the scan, and see findings grouped/summarized with rule, file:line, severity and message; skipped modules and failures must be shown honestly.

**S4** — JSON API: `GET /api/health`, `POST /api/scan` with `{ mode, target, config? }` returning `{ findings, skipped, failures, elapsedMs }`.

**S5** — Scans run from the UI must NOT write files into the scanned directory (no SARIF side effect). The CLI keeps writing the SARIF report.

**S6** — Local-only hardening: bind loopback by default, reject requests whose `Host` is not loopback/localhost (DNS-rebinding guard), reject cross-origin `Origin`, require `application/json`, cap request bodies at 64 KiB, and no CORS headers.

## Tasks

| ID | Spec(s) | Route | Status | Commit |
|----|---------|-------|--------|--------|
| T1 | S1-S6 | inline | done | e470ee8 |

## Log

**L1** — (2026-11-25) User verbatim: "podes continuar para hacer un servidor local asi lo puedo usar desde mi pc?"
**L2** — (2026-11-25) Baseline was red before this work: untracked `src/modules/web/*` (T2 of `secure-scan-v2`) did not compile, and `tests/sast` referenced a missing module (T4, unrelated to the server). Decision: finish the web module (needed for URL scans from the UI) and leave SAST untouched/out of scope.
**L3** — (2026-11-25) Implementation: `src/server/{app,cli,ui}.ts` (HTTP server, loopback guards, SPA), `serve` command in `src/cli.ts`, `web` mode wired, `runOrchestrator({ writeReport:false })` so browser scans never write SARIF, README + npm scripts. Evidence: `npx vitest run tests/server tests/web tests/orchestrator tests/cli` → 63/63 pass; `npm run lint` clean; `npm run build` clean; smoke test on `dist/cli.js serve` → health 200, UI 200 (10.4 KB), iac target found `iac/s3-public-acl`, no SARIF written, cross-origin 403.

**L4** — (2026-11-25) User follow-up verbatim: "en la pantalla inicial no puedo seleccionar una carpeta, solo la puedo escribir a mano y me parece muy arcaico eso lo podes controlar y solucionar tambien". Added `GET /api/browse` (directories only, symlinks excluded, 1000-entry cap) plus a modal folder picker with Up/Choose; the text field stays editable. Also wired the SAST mode into the UI/API. Evidence: full suite 196/196, lint/typecheck/build clean. Known red outside scope: `tests/sast` (missing module, T4 pending) is the only remaining typecheck/test failure.
