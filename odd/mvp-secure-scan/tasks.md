# Mirror — MVP Secure Scan (Engram recovery copy of odd/tasks/mvp-secure-scan.md)

Source file: `odd/tasks/mvp-secure-scan.md` (authoritative; refresh this mirror from it).
Status: all tasks done (T1–T7); branch `feat/mvp-secure-scan`, not pushed.

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
| T3 | S1, S2, S5 | inline | done | ec6f208 |
| T4 | S1, S2, S5 | inline | done | 396cf58 |
| T5 | S1, S4, S5 | inline | done | b2a6ad0 |
| T6 | S3, S5 | inline | done | 274e840 |
| T7 | All | inline | done | (see source file Log L10 / git log) |

## Log (summary — full verbatim log in the source file)

- L1: user's original request (verbatim in source).
- L2: user authorizes point-by-point T1–T7 with zero security problems in the scanner itself.
- L3: gap analysis — build broken, functional bugs, zero tests; plan Fase 0 → T7.
- L4: T1 scaffold, audit 8→0 (febcf9b).
- L5: T2 leakscan, 24 tests (0061a9e).
- L6: T3 SCA/OSV, live-verified (ec6f208).
- L7: T4 IaC terraform+k8s, shared walker (396cf58).
- L8: T5 orchestrator parallel+merged SARIF+failOn+zod config (b2a6ad0).
- L9: T6 GitHub Action + honest template-skip message (274e840).
- L10: T7 final verification — 117/117 tests, typecheck/lint/build clean, audit 0, self-scan exit 0, integration e2e 9/9 incl. differential + raw-secret-never-printed checks. Risk: none. Push/PR = user's decision.
