/**
 * Single-page UI served by the local scan server.
 *
 * Everything is inline (no build step, no CDN) and the CSP in `app.ts` only
 * allows same-origin API calls. All dynamic values are inserted with
 * `textContent`, never `innerHTML`.
 */
export const UI_HTML = `<!doctype html>
<html lang="en">
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
  form { display: grid; gap: 12px; grid-template-columns: 190px 1fr auto; align-items: end; }
  label { display: grid; gap: 6px; font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; color: var(--muted); }
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
  .picker { display: flex; gap: 8px; align-items: stretch; }
  .picker input { flex: 1; min-width: 0; }
  .picker button { padding-inline: 14px; }
  button.secondary { background: #1b2544; color: var(--text); border-color: var(--border); }
  .modal { position: fixed; inset: 0; background: rgba(4, 8, 18, 0.72); display: flex; align-items: center; justify-content: center; padding: 20px; z-index: 10; }
  .modal[hidden] { display: none; }
  .modal-card { width: min(640px, 100%); max-height: 82vh; display: flex; flex-direction: column; background: var(--panel); border: 1px solid var(--border); border-radius: 14px; padding: 16px; gap: 10px; }
  .modal-card header { display: flex; align-items: center; justify-content: space-between; }
  .modal-card header button { background: transparent; color: var(--muted); border-color: transparent; min-height: 32px; padding: 0 10px; }
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
    <p>Local scanner - secrets, dependencies, IaC and live URL headers. Runs on your machine only.</p>
  </header>

  <section class="card">
    <form id="scan-form">
      <label>Mode
        <select id="mode">
          <option value="all">All modules</option>
          <option value="leakscan">Secrets (leakscan)</option>
          <option value="sca">Dependencies (sca)</option>
          <option value="iac">IaC (terraform / k8s)</option>
          <option value="sast">Source code (SAST)</option>
          <option value="repo">GitHub / Git repo (clone &amp; scan)</option>
          <option value="web">Live URL (web)</option>
        </select>
      </label>
      <label>Target
        <div class="picker">
          <input id="target" type="text" autocomplete="off" spellcheck="false" placeholder="Directory path (empty = current directory)" />
          <button id="browse" class="secondary" type="button">Browse...</button>
        </div>
      </label>
      <button id="run" type="submit">Scan</button>
      <p class="hint" id="hint">Directory to scan. Leave empty to scan the server's working directory.</p>
    </form>
  </section>

  <div id="status" role="status" aria-live="polite"></div>
  <div class="summary" id="summary"></div>
  <div id="results"></div>
</main>

<div id="browser" class="modal" hidden>
  <div class="modal-card" role="dialog" aria-modal="true" aria-label="Choose a folder">
    <header>
      <strong>Choose a folder</strong>
      <button type="button" id="browser-close" aria-label="Close">&#10005;</button>
    </header>
    <div class="crumbs" id="browser-path"></div>
    <div class="dir-list" id="browser-list"></div>
    <footer>
      <span id="browser-error"></span>
      <button type="button" id="browser-up" class="secondary">Up</button>
      <button type="button" id="browser-choose">Use this folder</button>
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
    all: 'Directory to scan. Leave empty to scan the server\\'s working directory.',
    leakscan: 'Directory (or file/glob) to scan for secrets, including git history.',
    sca: 'Directory containing package-lock.json or requirements.txt.',
    iac: 'Directory (or file/glob) with Terraform or Kubernetes manifests.',
    sast: 'Directory (or file/glob) with JavaScript/TypeScript or Python sources.',
    repo: 'Public GitHub/GitLab/Bitbucket repository: owner/repo or https://github.com/owner/repo. Cloned shallow to a temp folder and deleted after the scan.',
    web: 'Full URL to analyze, for example https://example.com (only scan sites you own or are authorized to test).'
  };

  modeSelect.addEventListener('change', function () {
    var mode = modeSelect.value;
    hint.textContent = HINTS[mode] || '';
    var isUrl = mode === 'web';
    targetInput.placeholder = isUrl
      ? 'https://example.com'
      : mode === 'repo'
        ? 'owner/repo or https://github.com/owner/repo'
        : 'Directory path (empty = current directory)';
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
          throw new Error(result.body && result.body.error ? result.body.error : 'Cannot open folder');
        }
        browsing = result.body;
        renderDirectories();
      })
      .catch(function (error) {
        modalError.textContent = error && error.message ? error.message : String(error);
      });
  }

  function renderDirectories() {
    modalPath.textContent = browsing.path || 'Drives';
    modalList.textContent = '';
    if (browsing.entries.length === 0) {
      modalList.appendChild(el('div', 'notice', 'No subfolders here.'));
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
          ['Confirmed', triage.confirmed],
          ['Review', triage.review],
          ['Likely example', triage.likelyExample],
          ['Total', triage.total],
          ['Time', data.elapsedMs + ' ms']
        ]
      : [['Findings', data.findings.length], ['Time', data.elapsedMs + ' ms']];
    chips.forEach(function (pair) {
      var chip = el('span', 'chip', pair[0]);
      chip.appendChild(el('b', '', pair[1]));
      summary.appendChild(chip);
    });
  }

  function renderNotices(data) {
    results.textContent = '';
    data.skipped.forEach(function (s) {
      results.appendChild(el('div', 'notice', s.module + ' skipped: ' + s.reason));
    });
    data.failures.forEach(function (f) {
      results.appendChild(el('div', 'notice', f.module + ' failed: ' + f.message));
    });
  }

  function renderGroups(groups) {
    var table = el('table');
    var thead = el('thead');
    var headRow = el('tr');
    ['Triage', 'Level', 'Rule', 'Location', 'Problem'].forEach(function (label) {
      headRow.appendChild(el('th', '', label));
    });
    thead.appendChild(headRow);
    table.appendChild(thead);

    var tbody = el('tbody');
    groups.forEach(function (group) {
      var row = el('tr');
      row.appendChild(el('td')).appendChild(el('span', 'badge ' + group.bucket, group.bucket));

      var levelCell = row.appendChild(el('td'));
      levelCell.appendChild(el('span', 'badge ' + (group.level || 'none'), group.level || 'none'));

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
      setStatus(mode === 'web' ? 'Enter a URL to analyze.' : 'Enter a repository URL or owner/repo.', true);
      return;
    }

    runButton.disabled = true;
    summary.textContent = '';
    results.textContent = '';
    setStatus('Scanning' + (target ? ': ' + target : ' the working directory') + ' ...', false);

    fetch('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mode: mode, target: target })
    })
      .then(function (response) {
        return response.json().then(function (body) { return { ok: response.ok, body: body }; });
      })
      .then(function (result) {
        if (!result.ok) throw new Error(result.body && result.body.error ? result.body.error : 'Scan failed');
        var data = result.body;
        var groups = data.triage ? data.triage.groups : [];
        renderSummary(data);
        renderNotices(data);
        if (groups.length === 0) {
          results.appendChild(el('div', 'empty', 'No findings at this target.'));
        } else {
          renderGroups(groups);
        }
        setStatus('Scanned ' + data.target + ' in ' + data.elapsedMs + ' ms', false);
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
