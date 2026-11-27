# SCA report grouping, dependency graph and provenance

- Objective: turn the SCA part of the report into a grouped, reproducible presentation that says which package to review, why, where it comes from and how to confirm it was fixed — without losing any finding.
- Branch: `feat/secure-scan-v2`. Delivery: `single-pr` (one coherent delivery). Runner: `npm test` (vitest).

## Specs

**S1** — Grouping (user, 2026-11-26): "Agrupar hallazgos SCA por identidad de paquete, versión y ecosistema." Keep every individual advisory, id, severity, evidence and location. "No modificar ni reducir artificialmente el total real de vulnerabilidades." "Diferenciar cantidad de avisos, paquetes afectados y ocurrencias."

**S2** — Dependencies (user): identify direct vs transitive; show which dependencies introduce a transitive package; distinguish development vs production "cuando el grafo permita determinarlo"; "Si existen múltiples caminos de introducción, conservarlos." "No recomendar instalaciones directas para dependencias transitivas sin verificar la estrategia de actualización." "No prometer que actualizar una dependencia padre corrige automáticamente las hijas: verificar el lockfile resultante."

**S3** — Vocabulary (user): "Diferenciar repositorio clonado, árbol local e historial Git." "No llamar working-tree local a una copia temporal del repositorio remoto."

**S4** — Provenance (user): record source URL, branch or reference used, commit SHA analysed, date and time of the analysis, scan scope including Git history, and the source and update date of the vulnerability data "cuando estén disponibles". "No inventar fechas o metadatos que la fuente no proporcione."

**S5** — Compatibility and limits (user): keep the individual finding format for existing consumers; group in the presentation "sin destruir los datos originales"; do not modify detection rules, severity classification or secret classification; "No realizar comprobaciones externas de credenciales"; do not start points 5 and 6; stop when done.

## Tasks

| ID | Spec(s) | Route | Status | Commit |
|----|---------|-------|--------|--------|
| T1 | S2 | inline | done | `2e067f0` |
| T2 | S1, S5 | inline | pending | — |
| T3 | S3, S4 | inline | pending | — |
| T4 | S1-S5 | inline | pending | — |

## Log

**L1** — (2026-11-26) User verbatim (authorization): "AUTORIZO implementar conjuntamente los puntos 1 a 4 propuestos." Requirements: group SCA by package identity keeping every advisory; direct/transitive with introduction chain and dev/prod; fix the `working-tree` label for cloned repositories; reproducible provenance (repo, branch, SHA, date, scope, vuln data source). "No autorizaría que cambie el motor de detección, las reglas de severidad ni el sistema de clasificación de secretos dentro de esta entrega." Verification fixture: several vulnerabilities of one package, direct and transitive deps, one dependency introduced by several paths, dev and production deps, and one non-SCA secret finding; totals and evidence must stay correct after grouping. Delivery: report modified files, tests run and a before/after comparison. "DETENERSE AL TERMINAR."

**L2** — (2026-11-26) Design decisions: the API keeps `triage.groups` untouched (backward compatible) and adds an additive `sca` view plus `provenance`; the UI renders a package table and excludes `sca/*` from the "other findings" table; package grouping lives in `src/triage/sca-packages.ts`; the dependency graph is built from the npm lockfile resolution rules (`node_modules` nesting) with `package.json` as the authority for direct/dev; the fix target is the smallest published fixed version above the installed one, preferring the same major; OSV does not expose an "updated" date, so only the advisory `modified` timestamp (when present) and the scan timestamp are reported.

**L3** — (2026-11-26) User verbatim (review of the incomplete delivery, no approval granted): "No autorizaría que continúe implementando el resto del reporte sin corregir primero estos problemas." The six defects, verbatim:
- "ERROR 01 — Confunde el nombre del paquete con la instancia instalada … Determina si una dependencia es directa utilizando únicamente su nombre." Solution: "determinar la relación directa o transitiva utilizando la instancia resuelta dentro del grafo, no solamente el nombre del paquete."
- "ERROR 02 — No conserva todos los caminos de introducción … utiliza un único padre por nodo para reconstruir el camino más corto." Solution: "conservar el grafo de relaciones y generar los caminos para la presentación, indicando expresamente cuando la visualización esté limitada."
- "ERROR 03 — Asume que todas las dependencias Python son directas y de producción." Solution: `direct: null, dev: null`.
- "ERROR 04 — Puede perder ubicaciones de paquetes vulnerables … conserva un único: file: string; line: number." Need: "comparar este comportamiento con el parser anterior para determinar si es una regresión nueva o un defecto preexistente."
- "ERROR 05 — Grafo incompleto de dependencias npm … No incorpora devDependencies ni peerDependencies … el parser de lockfiles versión 1: recorre el anidamiento físico, pero no reconstruye las relaciones declaradas mediante requires."
- "ERROR 06 — Confunde ejecución de un módulo con cobertura efectiva … Los metadatos deben reflejar el alcance realmente analizado, no el alcance que se pretendía analizar."
Also: "puedes subir el codigo a este repo publico. https://github.com/OmarMira/SegInfo".

**L4** — (2026-11-26) Corrections applied to the dependency graph only (no detection, severity or secret-classification change):
- ERROR 01: directness now comes from `directKeys` (the exact lock entries the root node resolves), so `paquete-a@2.0.0` direct and nested `paquete-a@1.0.0` transitive are distinguished. `introducedBy` reports `name@version`, not bare names.
- ERROR 02: the full parent graph is kept; `paths` is rendered from it with a display cap, and `pathsTotal`/`pathsTruncated` state the real count and whether the list is shorter. No silent loss.
- ERROR 03: `parseRequirementsTxt` returns `direct: null`, `dev: null`.
- ERROR 04: **preexisting**, not a regression — the previous parser also deduped by `npm:name@version` and kept only the first `line`. Now `locations[]` keeps every manifest location and `file`/`line` remain the primary one.
- ERROR 05: root `devDependencies` and `peerDependencies` create edges; a dependency's own dev/peer deps do not (npm never installs them). Legacy v1 now rebuilds edges from `requires`.
- ERROR 06: `scanRepoDetailed` reports observed `HistoryCoverage` (gitRepository, shallow, commitsScanned, truncated, error). Not yet surfaced in the report — that belongs to T3.
Evidence: `npx tsc --noEmit` clean; `npm run lint` clean; `npm test` 244/244 in 21 files; synthetic 1001-package lockfile parsed in 10 ms with 200 real chains reported as `pathsTotal=200`, `pathsTruncated=true`.
Still pending: T2 (grouped SCA view), T3 (vocabulary + provenance), T4 (verification fixture + before/after comparison).
