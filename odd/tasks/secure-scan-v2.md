# Secure Scan V2 — filtrado accionable + web + TI + SAST

- Objetivo: completar los 3 gaps restantes de la visión original (sin GitHub): triaje de Sistema1, escaneo de páginas/URLs, fuentes TI extra y módulo SAST.
- Rama: `feat/secure-scan-v2`. Delivery: `ask-on-risk`. Runner: `npm test` (vitest).
- Test-first: RED → GREEN → REFACTOR por tarea donde exista test ejecutable.
- Fuente: continuación de `odd/tasks/mvp-secure-scan.md` (MVP T1–T7, completo, commits febcf9b…37533bf).

## Specs

**S7** — User (2026-11-25): "podemos hacer todos menos el de github por ahora?" — autoriza implementar los 3 ítems pendientes de la lista propuesta, **excluyendo explícitamente** push/PR/entrega GitHub: (a) filtrar el ruido vendorizado del escaneo de Sistema1 y triar las credenciales reales del historial, (b) módulo de escaneo de páginas/URLs, (c) más fuentes de inteligencia de amenazas + módulo SAST.

**S8** — Original S1: "poder cargarle una aplicación o poder cargarle una página o poder cargarle un repositorio" — falta la parte **página**: módulo que analice una URL en vivo (headers de seguridad, cookies, redirect HTTPS). Nota: solo contra destinos autorizados por el usuario o servidores locales de test.

**S9** — Original S5: "arquitectura modular y conectada a fuentes de inteligencia de amenazas" — hoy solo OSV; agregar al menos una fuente TI adicional pública (p. ej. CISA KEV y/o NVD) sin clave obligatoria.

**S10** — Original S4/S6: "si mañana sale otro tipo de ataque, los podamos [controlar]" — demostrar la expansibilidad con un módulo SAST de patrones de alto señal (inyección, XSS, exec, crypto débil) en el mismo patrón que leakscan/sca/iac.

**S7.1** — Triage de Sistema1: los hallazgos vendorizados (site-packages/botocore/pgAdmin) se excluyen vía config `ignore` **sin escribir nada dentro de Sistema1** (config y salida fuera, en Temp); las credenciales del historial git se clasifican real/falso con valores siempre enmascarados.

## Tasks

| ID | Spec(s) | Route | Status | Commit |
|----|---------|-------|--------|--------|
| T1 | S7, S7.1 | inline | done | 586bafe |
| T2 | S8 | inline | done | 068f885 |
| T3 | S9 | inline | done | 8370b8f |
| T4 | S10 | inline | done | e6e4051 |
| T5 | All | inline | done | e470ee8 |

## Log

**L1** — (2026-11-25) User verbatim: "podemos hacer todos menos el de github por ahora?" (contexto: lista de 4 pendientes propuesta por el asistente — 1 push/PR (excluido), 2 filtrar ruido + triar Sistema1, 3 módulo de páginas/URLs, 4 más fuentes TI + SAST).

**L2** — (2026-11-25) T1 done (triaje Sistema1): re-scan con config Temp `ignore: ["**/site-packages/**"]` → 650→269 hallazgos, **0 escrituras en Sistema1** (git status antes/después idéntico). Informe: `C:\Users\PC Omar\Downloads\Sistema1-triage.md`. Resultado: (1) REAL: Gmail app password de 16 letras en `.env.local:13` (nunca commiteada — verificado en todo el historial; recomendar revocación); (2) REAL: 39 CVEs de dependencias (next@16.4.2, undici@7.29.0, etc.); (3) SEGURO: el único `.env` en el historial (a17444b, remoto github.com/OmarMira/Sistema1) contiene solo placeholder `file:/home/z/...`; `.env.local` jamás entró al historial; secrets actuales solo locales y gitignorados; (4) FPs: upload txt = example con placeholders, CI/vitest/tests/fixtures, passwords generados en runtime (randomBytes), docs. Config sugerida para Sistema1 documentada en el informe. Riesgo T1: none (solo lectura + informe fuera del repo escaneado).

**L3** — (2026-11-25) T2 done (`068f885`): módulo `web` con fetch manual de redirects (máx 5), reglas missing-hsts/csp/xcto/xfo/referrer-policy, cookies (Secure/HttpOnly/SameSite, sin eco de valores), version disclosure y http-not-redirected; esquemas no http(s) rechazados antes de red. Evidencia: `npx vitest run tests/web` → 15/15.

**L4** — (2026-11-25) T3 done (`8370b8f`): `enrichFindings` agrega `kev`/`epss` desde CISA KEV y FIRST EPSS; fallo de feed = propiedades omitidas, nunca falla el scan ni inventa datos.

**L5** — (2026-11-25) T4 done (`e6e4051`): SAST por líneas (JS/TS/Python) con reglas sql-injection, xss-innerhtml, command-injection, eval-usage, weak-hash, insecure-random; walker compartido, límite 1 MB, binarios/symlinks fuera, mensajes sin código. Evidencia: `tests/sast` 31 tests, suite completa 196/196.

**L6** — (2026-11-25) T5 done (`e470ee8`): `secure-scan serve` (UI + API), selector de carpetas server-side (`GET /api/browse`, solo directorios), sin escritura de SARIF desde el navegador, README/scripts al día. Evidencia: lint + typecheck + build limpios; 196/196 tests.
