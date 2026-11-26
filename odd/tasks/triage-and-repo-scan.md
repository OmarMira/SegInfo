# Triage layer and Git repository scanning

- Objective: turn flat finding lists into decision-ready buckets (confirmed / review / likely example) without hiding anything, and let the local UI scan a public Git repository.
- Branch: `feat/secure-scan-v2`. Delivery: `ask-on-risk`. Runner: `npm test` (vitest).

## Specs

**S1** — User (2026-11-25): "si mejora todo lo que dijiste ademas de agregar el boton de browse como dijiste, tambien seria bueno poder controlar no solo una carpeta del disco si no tambien un repo de github por ejemplo"

**S2** — Triage: every finding falls in exactly one bucket — `confirmed` (objective evidence only: CISA KEV), `review` (needs a human, with a rule-family reason), `likely-example` (path looks like tests, fixtures, docs, demos or vendored code). Findings are never hidden or dropped.

**S3** — Deduplication: identical findings (same rule, file and message) collapse into one group with a count and every line number. Group counts must always add up to the total.

**S4** — Annotation: triage is written to `properties.triage = { bucket, reason }` so SARIF consumers and the UI can explain every classification.

**S5** — Repository scanning from the local UI/API: accept `owner/repo` or an https URL on GitHub/GitLab/Bitbucket, clone shallow (`--depth 1 --single-branch --no-tags`) into a temp dir, run the default modules, always delete the temp dir, and ignore any `secure-scan.config.json` shipped by the cloned repository (an untrusted repo must not control the scan).

**S6** — Reject non-https schemes, unsupported hosts, credentials in the URL, query strings/fragments and URLs without owner+repo, with a clear 400 message.

## Tasks

| ID | Spec(s) | Route | Status | Commit |
|----|---------|-------|--------|--------|
| T1 | S1-S4 | inline | done | c1eb146 |
| T2 | S1, S5-S6 | inline | done | 8a1dd85 |
| T3 | S1 | inline | done | (this commit) |

## Log

**L1** — (2026-11-25) User verbatim: "si mejora todo lo que dijiste ademas de agregar el boton de browse como dijiste, tambien seria bueno poder controlar no solo una carpeta del disco si no tambien un repo de github por ejemplo"
**L2** — (2026-11-25) T1: triage implemented in `src/triage/triage.ts` and wired into the orchestrator (annotates findings before SARIF), CLI `all` output and server responses. Test exception: triage tests were written after the small heuristic module (no RED observed); the full suite 215/215 is green.
**L3** — (2026-11-25) T2: `src/server/repo.ts` (URL allowlist, shallow clone, cleanup, ENOENT/timeout errors) and server `repo` mode with injected cloner for tests. Evidence: `tests/server/repo.test.ts` (URL validation) + server repo test (config ignored, cleanup guaranteed). Live smoke: cloned `octocat/Hello-World` in 925 ms, temp dirs cleaned.
**L4** — (2026-11-25) T3: README documents the triage buckets/grouping, the `repo` mode (clone, cleanup, ignored config) and the `triage` field of `POST /api/scan`. Checks before commit: `npm run lint` clean, `npx tsc --noEmit` clean, `npm test` 215/215, `npm run build` clean, UI inline script `node --check` OK. Risk: item 2 — the local server can clone and scan external repositories; mitigations are the https/host allowlist, argument-array git invocation, temp-dir cleanup and the ignored repo config.
**L5** — (2026-11-25) User verbatim: "tiene textos y cajas de escritura encimados ademas que lo quiero en español al texto" (+ screenshot). Fix: each form field is now its own `.field` block with the label outside the control (3 columns on desktop, single column under 760 px), so labels can never overlap inputs; all UI copy, folder picker, statuses and the browse/repo validation errors are in Spanish, and triage reasons/summary too. Verified with headless Chrome screenshots at 1400 px and 760 px plus a real scan driven over CDP (results table + badges + modal render with no overlap). Finding descriptions from the modules stay in English because they are the same text as the SARIF/CI report.
**L6** — (2026-11-25) User verbatim: "necesito que agregues un boton talvez despues de Escanear, uqe sea \"Limpiar\" para que limpie todo lo que se hizo y deje todo limpio como recien arrancado ... ademas que despues de cada escaneo si sobrevuelo una linea de lo que encontro que me diga en un texto claro en una burbuja porque fue seleccionado porque en todos dice lo mismo". Fix: `Limpiar` resets the form, results and status, aborts an in-flight scan and ignores its late response; hovering or focusing a row shows a tooltip with `why` (rule-specific, Spanish), `evidence` (module properties) and `nextStep`, so rows sharing a bucket no longer show identical text. New `src/triage/explain.ts` builds the explanation; `why`/`evidence`/`nextStep` travel in the API group view and the inline repeated reason was removed from the table. Verified with CDP screenshots: tooltip per row (IAC bucket ACL, privileged container, SAST sink, secret pattern + entropy), Limpiar after a scan and mid-scan (0 rows, empty status), and the 760 px layout with both buttons.
