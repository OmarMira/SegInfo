/**
 * Single-page UI served by the local scan server.
 *
 * Everything is inline (no build step, no CDN) and the CSP in `app.ts` only
 * allows same-origin API calls. All dynamic values are inserted with
 * `textContent`, never `innerHTML`.
 */
export const UI_HTML = `<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>SegInfo Secure Scan</title>
<style>
  :root {
    color-scheme: dark;
    --bg: #0b1020;
    --panel: #121a2e;
    --panel-2: #182241;
    --border: #26314f;
    --text: #e6ebf5;
    --muted: #93a0bd;
    --accent: #5b8cff;
    --error: #ff5c7a;
    --warning: #ffb020;
    --note: #4cc9f0;
    --ok: #35d07f;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: radial-gradient(1200px 600px at 10% -10%, #17224a 0%, var(--bg) 55%);
    color: var(--text);
    font: 15px/1.5 ui-sans-serif, system-ui, "Segoe UI", Roboto, sans-serif;
    min-height: 100vh;
  }
  main { max-width: 1080px; margin: 0 auto; padding: 32px 20px 64px; }
  header h1 { font-size: 24px; margin: 0 0 4px; letter-spacing: -0.02em; }
  header p { margin: 0 0 24px; color: var(--muted); }
  .card {
    background: linear-gradient(180deg, var(--panel) 0%, var(--panel-2) 100%);
    border: 1px solid var(--border);
    border-radius: 14px;
    padding: 18px;
  }
  form.scan-form {
    display: grid;
    grid-template-columns: minmax(180px, 230px) minmax(0, 1fr) auto;
    gap: 16px;
    align-items: end;
  }
  .field { display: flex; flex-direction: column; gap: 8px; min-width: 0; }
  .field > label {
    display: block;
    font-size: 12px;
    font-weight: 600;
    line-height: 1.2;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--muted);
    margin: 0;
  }
  select, input, button {
    font: inherit;
    border-radius: 10px;
    border: 1px solid var(--border);
    background: #0d1428;
    color: var(--text);
    padding: 10px 12px;
    min-height: 42px;
  }
  select:focus, input:focus, button:focus { outline: 2px solid var(--accent); outline-offset: 1px; }
  button {
    background: var(--accent);
    border-color: transparent;
    color: #071026;
    font-weight: 650;
    cursor: pointer;
    padding-inline: 20px;
  }
  button:disabled { opacity: 0.6; cursor: progress; }
  .hint { grid-column: 1 / -1; margin: 0; color: var(--muted); font-size: 13px; }
  .picker { display: flex; gap: 8px; align-items: center; min-width: 0; }
  .picker input { flex: 1 1 auto; min-width: 0; }
  .picker button { flex: 0 0 auto; width: auto; padding-inline: 14px; }
  .field-submit { min-width: 0; }
  .field-submit button { width: auto; }
  @media (max-width: 760px) {
    form.scan-form { grid-template-columns: 1fr; gap: 12px; }
    .field-submit button { width: 100%; }
  }
  button.secondary { background: #1b2544; color: var(--text); border-color: var(--border); }
  .modal { position: fixed; inset: 0; background: rgba(4, 8, 18, 0.72); display: flex; align-items: center; justify-content: center; padding: 20px; z-index: 10; }
  .modal[hidden] { display: none; }
  .modal-card { width: min(640px, 100%); max-height: 82vh; display: flex; flex-direction: column; background: var(--panel); border: 1px solid var(--border); border-radius: 14px; padding: 16px; gap: 10px; }
  .modal-card header { display: flex; align-items: center; justify-content: space-between; gap: 12px; }
  .modal-card header strong { font-size: 16px; }
  .modal-card header button { background: transparent; color: var(--muted); border-color: transparent; min-height: 32px; padding: 0 10px; width: auto; }
  .crumbs { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12.5px; color: var(--accent); word-break: break-all; min-height: 18px; }
  .dir-list { overflow: auto; border: 1px solid var(--border); border-radius: 10px; padding: 6px; min-height: 180px; flex: 1; display: flex; flex-direction: column; gap: 2px; }
  .dir-item { background: transparent; border-color: transparent; text-align: left; color: var(--text); font-weight: 500; padding: 8px 10px; min-height: 36px; }
  .dir-item:hover { background: rgba(91, 140, 255, 0.12); }
  .modal-card footer { display: flex; gap: 10px; align-items: center; justify-content: flex-end; }
  .modal-card footer span { margin-right: auto; color: var(--error); font-size: 13px; }
  #status { margin: 18px 0 8px; min-height: 22px; color: var(--muted); }
  #status.error { color: var(--error); }
  .summary { display: flex; flex-wrap: wrap; gap: 10px; margin: 10px 0 18px; }
  .chip { border: 1px solid var(--border); border-radius: 999px; padding: 5px 12px; font-size: 13px; color: var(--muted); }
  .chip b { color: var(--text); margin-left: 6px; }
  table { width: 100%; border-collapse: collapse; font-size: 14px; }
  th, td { text-align: left; padding: 10px 8px; border-bottom: 1px solid var(--border); vertical-align: top; }
  th { font-size: 11px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); font-weight: 600; }
  tbody tr { cursor: pointer; }
  tbody tr:hover { background: rgba(91, 140, 255, 0.06); }
  .badge { display: inline-block; border-radius: 6px; padding: 2px 8px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; }
  .badge.error { background: rgba(255, 92, 122, 0.16); color: var(--error); }
  .badge.warning { background: rgba(255, 176, 32, 0.16); color: var(--warning); }
  .badge.note { background: rgba(76, 201, 240, 0.16); color: var(--note); }
  .badge.none { background: rgba(147, 160, 189, 0.16); color: var(--muted); }
  .badge.confirmed { background: rgba(53, 208, 127, 0.16); color: var(--ok); }
  .badge.review { background: rgba(255, 176, 32, 0.16); color: var(--warning); }
  .badge.likely-example { background: rgba(147, 160, 189, 0.16); color: var(--muted); }
  .why { color: var(--muted); font-size: 12.5px; display: block; margin-top: 3px; }
  .rule { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12.5px; color: var(--accent); }
  .loc { font-family: ui-monospace, SFMono-Regular, Consolas, monospace; font-size: 12.5px; color: var(--muted); word-break: break-all; }
  .details { background: #0a1124; }
  .details pre { margin: 0; white-space: pre-wrap; word-break: break-word; color: var(--muted); font-size: 12.5px; }
  .notice { margin: 8px 0; padding: 10px 12px; border-radius: 10px; border: 1px solid var(--border); color: var(--muted); font-size: 13.5px; }
  .empty { padding: 28px 8px; text-align: center; color: var(--muted); }
</style>
</head>
<body>
<main>
  <header>
    <h1>SegInfo Secure Scan</h1>
    <p>Escáner local: secretos, dependencias, IaC y cabeceras de URLs en vivo. Se ejecuta solo en tu máquina.</p>
  </header>

  <section class="card">
    <form id="scan-form" class="scan-form">
      <div class="field">
        <label for="mode">Modo</label>
        <select id="mode">
          <option value="all">Todos los módulos</option>
          <option value="leakscan">Secretos (leakscan)</option>
          <option value="sca">Dependencias (SCA)</option>
          <option value="iac">Infraestructura como código (Terraform / K8s)</option>
          <option value="sast">Código fuente (SAST)</option>
          <option value="repo">Repositorio Git (clonar y escanear)</option>
          <option value="web">URL en vivo (web)</option>
        </select>
      </div>
      <div class="field">
        <label for="target">Objetivo</label>
        <div class="picker">
          <input id="target" type="text" autocomplete="off" spellcheck="false" placeholder="Ruta de la carpeta (vacío = carpeta actual)" />
          <button id="browse" class="secondary" type="button">Examinar…</button>
        </div>
      </div>
      <div class="field field-submit">
        <button id="run" type="submit">Escanear</button>
      </div>
      <p class="hint" id="hint">Carpeta a escanear. Déjalo vacío para escanear la carpeta de trabajo del servidor.</p>
    </form>
  </section>

  <div id="status" role="status" aria-live="polite"></div>
  <div class="summary" id="summary"></div>
  <div id="results"></div>
</main>

<div id="browser" class="modal" hidden>
  <div class="modal-card" role="dialog" aria-modal="true" aria-label="Elegir una carpeta">
    <header>
      <strong>Elegir una carpeta</strong>
      <button type="button" id="browser-close" aria-label="Cerrar">&#10005;</button>
    </header>
    <div class="crumbs" id="browser-path"></div>
    <div class="dir-list" id="browser-list"></div>
    <footer>
      <span id="browser-error"></span>
      <button type="button" id="browser-up" class="secondary">Subir</button>
      <button type="button" id="browser-choose">Usar esta carpeta</button>
    </footer>
  </div>
</div>

<script>
(function () {
  var form = document.getElementById('scan-form');
  var modeSelect = document.getElementById('mode');
  var targetInput = document.getElementById('target');
  var runButton = document.getElementById('run');
  var hint = document.getElementById('hint');
  var status = document.getElementById('status');
  var summary = document.getElementById('summary');
  var results = document.getElementById('results');

  var HINTS = {
    all: 'Carpeta a escanear. Déjalo vacío para escanear la carpeta de trabajo del servidor.',
    leakscan: 'Carpeta (o archivo/patrón glob) donde buscar secretos, incluido el historial de git.',
    sca: 'Carpeta que contenga package-lock.json o requirements.txt.',
    iac: 'Carpeta (o archivo/patrón glob) con manifiestos de Terraform o Kubernetes.',
    sast: 'Carpeta (o archivo/patrón glob) con código JavaScript/TypeScript o Python.',
    repo: 'Repositorio público de GitHub/GitLab/Bitbucket: owner/repo o https://github.com/owner/repo. Se clona en una carpeta temporal que se borra al terminar.',
    web: 'URL completa a analizar, por ejemplo https://example.com (escanea solo sitios propios o autorizados).'
  };

  var BUCKET_LABELS = {
    confirmed: 'Confirmado',
    review: 'Revisar',
    'likely-example': 'Probable ejemplo'
  };

  var LEVEL_LABELS = {
    error: 'Error',
    warning: 'Advertencia',
    note: 'Nota',
    none: 'Informativo'
  };

  modeSelect.addEventListener('change', function () {
    var mode = modeSelect.value;
    hint.textContent = HINTS[mode] || '';
    var isUrl = mode === 'web';
    targetInput.placeholder = isUrl
      ? 'https://example.com'
      : mode === 'repo'
        ? 'owner/repo o https://github.com/owner/repo'
        : 'Ruta de la carpeta (vacío = carpeta actual)';
    syncBrowseVisibility();
  });

  var browseButton = document.getElementById('browse');
  var modal = document.getElementById('browser');
  var modalPath = document.getElementById('browser-path');
  var modalList = document.getElementById('browser-list');
  var modalError = document.getElementById('browser-error');
  var modalClose = document.getElementById('browser-close');
  var modalUp = document.getElementById('browser-up');
  var modalChoose = document.getElementById('browser-choose');
  var browsing = null;

  function syncBrowseVisibility() {
    browseButton.hidden = modeSelect.value === 'web' || modeSelect.value === 'repo';
  }

  function loadDirectory(dirPath) {
    modalError.textContent = '';
    var query = dirPath ? '?path=' + encodeURIComponent(dirPath) : '';
    fetch('/api/browse' + query)
      .then(function (response) {
        return response.json().then(function (body) { return { ok: response.ok, body: body }; });
      })
      .then(function (result) {
        if (!result.ok) {
          throw new Error(result.body && result.body.error ? result.body.error : 'No se pudo abrir la carpeta');
        }
        browsing = result.body;
        renderDirectories();
      })
      .catch(function (error) {
        modalError.textContent = error && error.message ? error.message : String(error);
      });
  }

  function renderDirectories() {
    modalPath.textContent = browsing.path || 'Unidades';
    modalList.textContent = '';
    if (browsing.entries.length === 0) {
      modalList.appendChild(el('div', 'notice', 'No hay subcarpetas.'));
    }
    browsing.entries.forEach(function (entry) {
      var button = el('button', 'dir-item', '\\uD83D\\uDCC1  ' + entry.name);
      button.type = 'button';
      button.addEventListener('click', function () { loadDirectory(entry.path); });
      modalList.appendChild(button);
    });
    modalUp.disabled = !browsing.path;
    modalChoose.disabled = !browsing.path;
  }

  function openBrowser() {
    modal.hidden = false;
    loadDirectory(targetInput.value.trim() || null);
  }

  browseButton.addEventListener('click', openBrowser);
  modalClose.addEventListener('click', function () { modal.hidden = true; });
  modal.addEventListener('click', function (event) { if (event.target === modal) modal.hidden = true; });
  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape' && !modal.hidden) modal.hidden = true;
  });
  modalUp.addEventListener('click', function () {
    if (!browsing) return;
    loadDirectory(browsing.parent || null);
  });
  modalChoose.addEventListener('click', function () {
    if (!browsing || !browsing.path) return;
    targetInput.value = browsing.path;
    modal.hidden = true;
  });
  syncBrowseVisibility();

  function el(tag, className, text) {
    var node = document.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined && text !== null) node.textContent = String(text);
    return node;
  }

  function setStatus(message, isError) {
    status.textContent = message || '';
    status.className = isError ? 'error' : '';
  }

  function renderSummary(data) {
    summary.textContent = '';
    var triage = data.triage ? data.triage.summary : null;
    var chips = triage
      ? [
          ['Confirmados', triage.confirmed],
          ['Por revisar', triage.review],
          ['Probables ejemplos', triage.likelyExample],
          ['Total', triage.total],
          ['Tiempo', data.elapsedMs + ' ms']
        ]
      : [['Hallazgos', data.findings.length], ['Tiempo', data.elapsedMs + ' ms']];
    chips.forEach(function (pair) {
      var chip = el('span', 'chip', pair[0]);
      chip.appendChild(el('b', '', pair[1]));
      summary.appendChild(chip);
    });
  }

  function renderNotices(data) {
    results.textContent = '';
    data.skipped.forEach(function (s) {
      results.appendChild(el('div', 'notice', s.module + ' omitido: ' + s.reason));
    });
    data.failures.forEach(function (f) {
      results.appendChild(el('div', 'notice', f.module + ' falló: ' + f.message));
    });
  }

  function renderGroups(groups) {
    var table = el('table');
    var thead = el('thead');
    var headRow = el('tr');
    ['Triaje', 'Nivel', 'Regla', 'Ubicación', 'Problema'].forEach(function (label) {
      headRow.appendChild(el('th', '', label));
    });
    thead.appendChild(headRow);
    table.appendChild(thead);

    var tbody = el('tbody');
    groups.forEach(function (group) {
      var row = el('tr');
      row.appendChild(el('td')).appendChild(
        el('span', 'badge ' + group.bucket, BUCKET_LABELS[group.bucket] || group.bucket),
      );

      var levelCell = row.appendChild(el('td'));
      var level = group.level || 'none';
      levelCell.appendChild(el('span', 'badge ' + level, LEVEL_LABELS[level] || level));

      row.appendChild(el('td')).appendChild(el('span', 'rule', group.ruleId));

      var where = group.file + ':' + group.lines[0] + (group.count > 1 ? '  x' + group.count : '');
      row.appendChild(el('td')).appendChild(el('span', 'loc', where));

      var problem = row.appendChild(el('td'));
      problem.appendChild(document.createTextNode(group.message || ''));
      problem.appendChild(el('span', 'why', group.reason || ''));

      var detailsRow = el('tr', 'details');
      detailsRow.hidden = true;
      var cell = el('td');
      cell.colSpan = 5;
      cell.appendChild(el('pre', '', JSON.stringify({
        triage: group.bucket,
        reason: group.reason,
        ruleId: group.ruleId,
        level: group.level,
        file: group.file,
        lines: group.lines,
        occurrences: group.count,
        message: group.message
      }, null, 2)));
      detailsRow.appendChild(cell);

      row.addEventListener('click', function () { detailsRow.hidden = !detailsRow.hidden; });
      tbody.appendChild(row);
      tbody.appendChild(detailsRow);
    });
    table.appendChild(tbody);
    results.appendChild(table);
  }

  form.addEventListener('submit', function (event) {
    event.preventDefault();
    var mode = modeSelect.value;
    var target = targetInput.value.trim();
    if ((mode === 'web' || mode === 'repo') && !target) {
      setStatus(
        mode === 'web'
          ? 'Introduce una URL para analizar.'
          : 'Introduce un repositorio: owner/repo o su URL.',
        true,
      );
      return;
    }

    runButton.disabled = true;
    summary.textContent = '';
    results.textContent = '';
    setStatus('Escaneando' + (target ? ': ' + target : ' la carpeta de trabajo') + '…', false);

    fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: mode, target: target })
    })
      .then(function (response) {
        return response.json().then(function (body) { return { ok: response.ok, body: body }; });
      })
      .then(function (result) {
        if (!result.ok) throw new Error(result.body && result.body.error ? result.body.error : 'El escaneo falló');
        var data = result.body;
        var groups = data.triage ? data.triage.groups : [];
        renderSummary(data);
        renderNotices(data);
        if (groups.length === 0) {
          results.appendChild(el('div', 'empty', 'No se encontraron hallazgos en este objetivo.'));
        } else {
          renderGroups(groups);
        }
        setStatus('Escaneado ' + data.target + ' en ' + data.elapsedMs + ' ms', false);
      })
      .catch(function (error) {
        setStatus(error && error.message ? error.message : String(error), true);
      })
      .then(function () {
        runButton.disabled = false;
      });
  });
})();
</script>
</body>
</html>`;
