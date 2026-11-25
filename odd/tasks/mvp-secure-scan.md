# MVP Secure Scan — Análisis de seguridad automatizado modular

- Objetivo: escáner de seguridad modular (secretos + SCA + IaC) con salida SARIF y CI.
- Rama: `feat/mvp-secure-scan`. Delivery: `ask-on-risk`. Runner: `npm test` (vitest).
- Test-first: RED → GREEN → REFACTOR por tarea donde exista test ejecutable.

## Specs

**S1** — "poder cargarle una aplicación o poder cargarle una página o poder cargarle un repositorio y hacer que ese sistema lo analice"

**S2** — "Exclusivamente ciberseguridad, ciberataque o ataques forzosos o órdenes a la IA de los sistemas para para no sé. Para poderlo vulnerar, cosas así"

**S3** — "lo quiero para poder controlar no solamente los sistemas que yo hago, sino para poderlo ofrecer a gente que hace sistemas y que puedan hacer sus pruebas"

**S4** — "Quiero que sea una cosa limitada, quiero que sea una cosa que vaya avanzando. Podemos pensar en algo que si mañana sale otro tipo de ataque, los podamos [controlar]"

**S5** — "arquitectura modular y conectada a fuentes de inteligencia de amenazas"

**S6** — "Primero diseña la arquitectura — crea un prototipo para la vulnerabilidad más común, y conéctalo a fuentes de amenazas para actualizarlo — Luego, pasa a pruebas más complejas y expande el sistema por módulos según las nuevas amenazas que vayan surgiendo"

## Tasks

| ID | Spec(s) | Route | Status | Commit |
|----|---------|-------|--------|--------|
| T1 | S1, S4, S5 | inline | done | febcf9b |
| T2 | S1, S2, S5 | inline | done | 0061a9e |
| T3 | S1, S2, S5 | inline | done | (this commit) |
| T4 | S1, S2, S5 | inline | pending | — |
| T5 | S1, S4, S5 | inline | pending | — |
| T6 | S3, S5 | inline | pending | — |
| T7 | All | inline | pending | — |

## Log

**L1** — User original request (verbatim): "Tengo una idea de una aplicación o de algo de algún sistema. Porque me gusta que fuera un sistema especializado en ciberseguridad. [...] Mi idea es, por ejemplo, poder cargarle una aplicación o poder cargarle una página o poder cargarle un repositorio y hacer que ese sistema lo analice. [...] De la parte de ciberseguridad. Exclusivamente ciberseguridad, ciberataque o ataques forzosos o órdenes a la IA de los sistemas para para no sé. Para poderlo vulnerar, cosas así. [...] En realidad lo quiero para poder controlar no solamente los sistemas que yo hago, sino para poderlo ofrecer a gente que hace sistemas y que puedan hacer sus pruebas. [...] Quiero que sea una cosa limitada, quiero que sea una cosa que vaya avanzando. Podemos pensar en algo que si mañana sale otro tipo de ataque, los podamos [controlar]. [...] arquitectura modular y conectada a fuentes de inteligencia de amenazas. [...] Primero diseña la arquitectura — crea un prototipo para la vulnerabilidad más común, y conéctalo a fuentes de amenazas para actualizarlo — Luego, pasa a pruebas más complejas y expande el sistema por módulos según las nuevas amenazas que vayan surgiendo."

**L2** — (2026-11-24) User: "empieza punto por punto controlando cada uno para que no quede nada pendiente, y cero problemas de seguridad, recorda que es un sistema para controlar seguridad informatica de sistemas" — authorize full implementation of T1–T7, each task verified before the next, security-first posture (the scanner itself must not introduce vulnerabilities).

**L3** — (2026-11-24) Full gap analysis (read-only): build broken (missing tsconfig, broken imports, type mismatch leakscan→sarif), functional bugs (readdir recursive basename path bug, scans .git/node_modules, --files treated as dir, all modules overwrite same SARIF, exit code ignores severity, no git history), zero tests, zero commits. Plan: Fase 0 scaffold → T2 secrets → T3 SCA/OSV → T4 IaC → T5 orchestrator → T6 GitHub Action → T7 verification.

**L4** — (2026-11-24) T1 done (commit febcf9b): tsconfig(+build), ESLint 10 flat config, unified Finding contract, honest not-implemented stubs, npm audit cleaned from 8 vulnerabilities (2 critical) to 0 by upgrading vitest/vite/eslint/zod/glob and removing the nonexistent `sarif` package.

**L5** — (2026-11-24) T2 done: leakscan engine rewritten test-first (24 tests). Fixes: BFS walker with correct nested paths (old readdir-recursive basename bug), skips .git/node_modules/dist, never follows symlinks (malicious-repo escape guard), file-size/line-length/depth/count limits, 13 precise secret patterns (old FP-heavy `39+ chars` pattern removed) + entropy/digit-letter plausibility for keyword matches, blob-boundary validation (kills `gho...`-inside-sha512 FPs), real git-history scan via `git grep -E` batches (execFile, no shell), dedupe prefers working-tree, secrets never printed raw. Self-scan: only test fixtures flagged; package-lock and source clean.

**L6** — (2026-11-24) T3 done (SCA + OSV): lockfile v3/v1 parsers with exact line numbers (O(n) key→line index), requirements.txt pin parser, OSV client (querybatch 500/batch → per-id detail with concurrency 8, cap 200, 15s timeouts, zod validation, injected fetch for tests), severity→SARIF level mapping, remediation from `affected[].ranges[].fixed` filtered by exact package+ecosystem. Network failures throw (never fake a clean scan). Verified live against api.osv.dev: own package-lock reported clean. Lint rule `preserve-caught-error` satisfied via `cause`. 39/39 tests.