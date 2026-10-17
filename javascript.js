



/* DataLens frontend controller. UI and API requests only; forensic operations remain in Python modules. */
(() => {
  'use strict';

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => Array.from(root.querySelectorAll(selector));

  const state = {
    cases: [],
    evidence: [],
    devices: [],
    selectedDevice: null,
    recoveryCandidates: [],
    recoverySource: '',
    currentPage: 'dashboard',
    analysisRows: [],
    analysisCase: ''
  };

  const pageNames = {
    dashboard: 'Dashboard',
    cases: 'Cases',
    acquire: 'Acquire evidence',
    analysis: 'AI analysis',
    custody: 'Chain of custody',
    recovery: 'File recovery',
    system: 'System checks'
  };

  function byId(id) {
    return document.getElementById(id);
  }

  function value(id, fallback = '') {
    const el = byId(id);
    return el ? String(el.value ?? fallback).trim() : fallback;
  }

  function actorFrom(...ids) {
    for (const id of ids) {
      const found = value(id);
      if (found) return found;
    }
    return value('investigator-name', 'Investigator') || 'Investigator';
  }

  function setText(id, text) {
    const el = byId(id);
    if (el) el.textContent = text == null ? '' : String(text);
  }

  function showMessage(id, message, kind = 'neutral') {
    const el = byId(id);
    if (!el) return;

    el.textContent = message;
    el.className = `inline-message message-${kind}`;
    el.hidden = false;
  }

  function clearMessage(id) {
    const el = byId(id);
    if (el) {
      el.hidden = true;
      el.textContent = '';
    }
  }

  function setBusy(button, busy, busyText = 'Working…') {
    if (!button) return;

    if (busy) {
      button.dataset.originalText = button.textContent;
      button.textContent = busyText;
      button.disabled = true;
      button.setAttribute('aria-busy', 'true');
    } else {
      button.textContent = button.dataset.originalText || button.textContent;
      button.disabled = false;
      button.removeAttribute('aria-busy');
    }
  }

  function formatBytes(bytes) {
    const n = Number(bytes);

    if (!Number.isFinite(n) || n < 0) return 'Unknown';
    if (n === 0) return '0 B';

    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const index = Math.min(
      Math.floor(Math.log(n) / Math.log(1024)),
      units.length - 1
    );

    return `${(n / Math.pow(1024, index)).toFixed(index === 0 ? 0 : 1)} ${units[index]}`;
  }

  function formatDate(input) {
    if (!input) return '—';

    const date = new Date(input);

    return Number.isNaN(date.getTime())
      ? String(input)
      : date.toLocaleString();
  }

  function cellText(value) {
    if (value === null || value === undefined || value === '') return '—';
    if (typeof value === 'object') return JSON.stringify(value);
    return String(value);
  }

  function makeCell(text, options = {}) {
    const td = document.createElement('td');
    td.textContent = cellText(text);

    if (options.mono) td.classList.add('mono');
    if (options.tone) td.classList.add(options.tone);

    return td;
  }

  function renderRows(id, rows, columns, emptyText = 'No records found.') {
    const body = byId(id);
    if (!body) return;

    body.replaceChildren();

    if (!Array.isArray(rows) || rows.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');

      td.colSpan = columns.length;
      td.className = 'empty-cell';
      td.textContent = emptyText;

      tr.appendChild(td);
      body.appendChild(tr);
      return;
    }

    rows.forEach(row => {
      const tr = document.createElement('tr');

      columns.forEach(column => {
        const raw = typeof column.value === 'function'
          ? column.value(row)
          : row[column.key];

        const td = makeCell(raw, { mono: column.mono });

        if (column.tone) {
          const tone = typeof column.tone === 'function'
            ? column.tone(row, raw)
            : column.tone;

          if (tone) td.classList.add(tone);
        }

        tr.appendChild(td);
      });

      body.appendChild(tr);
    });
  }

  async function api(path, options = {}) {
    const response = await fetch(path, {
      method: options.method || 'GET',
      headers: {
        Accept: 'application/json',
        ...(options.body !== undefined
          ? { 'Content-Type': 'application/json' }
          : {}),
        ...(options.headers || {})
      },
      body: options.body !== undefined
        ? JSON.stringify(options.body)
        : undefined,
      cache: 'no-store'
    });

    const type = response.headers.get('content-type') || '';
    const data = type.includes('application/json')
      ? await response.json()
      : await response.text();

    if (!response.ok) {
      throw new Error(
        (data && data.error) || `Request failed (${response.status}).`
      );
    }

    return data;
  }

  function downloadReport(downloadUrl) {
  if (!downloadUrl) {
    throw new Error('The server did not provide a report download URL.');
  }

  try {
    const url = new URL(downloadUrl, window.location.origin);

    // Only allow downloads from the local DataLens service.
    if (url.origin !== window.location.origin) {
      throw new Error('Report downloads must use the local DataLens service.');
    }

    const link = document.createElement('a');
    link.href = url.href;
    link.style.display = 'none';

    document.body.appendChild(link);
    link.click();
    link.remove();
  } catch (error) {
    throw new Error(`Could not download report: ${error.message}`);
  }
}

function globalMessage(message, kind = 'neutral') {
    const el = byId('global-message');
    if (!el) return;

    el.textContent = message;
    el.className = `global-message message-${kind}`;
    el.hidden = false;
  }

  function clearGlobalMessage() {
    const el = byId('global-message');

    if (el) {
      el.hidden = true;
      el.textContent = '';
    }
  }

  function navigate(page, updateHash = true) {
    if (!pageNames[page]) page = 'dashboard';

    state.currentPage = page;

    $$('[data-page-panel]').forEach(panel => {
      const active = panel.dataset.pagePanel === page;
      panel.classList.toggle('active', active);
      panel.hidden = !active;
    });

    $$('[data-page]').forEach(button => {
      const active = button.dataset.page === page;

      button.classList.toggle('active', active);

      if (active) {
        button.setAttribute('aria-current', 'page');
      } else {
        button.removeAttribute('aria-current');
      }
    });

    setText('breadcrumb-current', pageNames[page]);

    const sidebar = byId('sidebar');
    const mobileButton = byId('mobile-menu-button');

    if (sidebar) sidebar.classList.remove('sidebar-open');
    if (mobileButton) mobileButton.setAttribute('aria-expanded', 'false');

    if (updateHash && location.hash !== `#${page}`) {
      history.replaceState(null, '', `#${page}`);
    }

    clearGlobalMessage();
    refreshPage(page).catch(error => globalMessage(error.message, 'error'));
  }

  async function loadCases() {
    const data = await api('/api/cases');
    state.cases = Array.isArray(data.cases) ? data.cases : [];

    const caseSelectIds = [
      'selected-case',
      'acquire-case',
      'analysis-case',
      'custody-case',
      'recovery-case'
    ];

    caseSelectIds.forEach(id => {
      const select = byId(id);
      if (!select) return;

      const previous = select.value ||
        (id === 'selected-case'
          ? localStorage.getItem('datalens-selected-case') || ''
          : '');

      select.replaceChildren();

      const placeholder = document.createElement('option');
      placeholder.value = '';
      placeholder.textContent = state.cases.length
        ? 'Choose a case…'
        : 'Create a case first…';

      select.appendChild(placeholder);

      state.cases.forEach(item => {
        const option = document.createElement('option');
        option.value = item.case_id || '';
        option.textContent =
          `${item.case_name || 'Untitled case'} · ${item.case_id || ''}`;

        select.appendChild(option);
      });

      const preferred = state.cases.some(
        item => item.case_id === previous
      )
        ? previous
        : (state.cases[0]?.case_id || '');

      select.value = preferred;

      if (preferred && id === 'selected-case') {
        localStorage.setItem('datalens-selected-case', preferred);
      }
    });

    setText(
      'case-register-count',
      `${state.cases.length} case${state.cases.length === 1 ? '' : 's'}`
    );

    renderRows(
      'cases-table-body',
      state.cases,
      [
        { key: 'case_name' },
        { key: 'case_id', mono: true },
        { key: 'status' },
        { key: 'created_at', value: r => formatDate(r.created_at) },
        { key: 'description' }
      ],
      'No cases yet. Create your first case using the form.'
    );

    const selected = value('selected-case');
    const selectedCase = state.cases.find(
      item => item.case_id === selected
    );

    setText(
      'selected-case-summary',
      selectedCase
        ? `${selectedCase.case_name || 'Untitled case'} · ${selectedCase.status || 'Status not reported'}`
        : 'No case selected.'
    );
  }
    async function loadDashboard() {
    const data = await api('/api/dashboard');

    setText('metric-cases', data.cases_count ?? 0);
    setText('metric-evidence', data.evidence_count ?? 0);
    setText('metric-analyses', data.saved_analyses_count ?? 0);
    setText(
      'metric-vault',
      data.vault_usage_display || formatBytes(data.vault_usage_bytes)
    );

    setText(
      'metric-vault-note',
      `of ${formatBytes(data.vault_limit_bytes)} configured capacity`
    );

    const percent = data.vault_limit_bytes
      ? Math.min(
          100,
          (Number(data.vault_usage_bytes || 0) /
            Number(data.vault_limit_bytes)) * 100
        )
      : 0;

    const progress = byId('vault-progress');

    if (progress) {
      progress.style.width = `${percent.toFixed(2)}%`;
    }

    setText(
      'dashboard-updated',
      `Updated ${formatDate(data.generated_at)}`
    );

    renderRows(
      'dashboard-recent-cases',
      data.recent_cases || [],
      [
        { key: 'case_name' },
        { key: 'case_id', mono: true },
        { key: 'created_at', value: r => formatDate(r.created_at) },
        { key: 'status' }
      ],
      'No cases have been created yet.'
    );

    renderRows(
      'dashboard-recent-evidence',
      data.recent_evidence || [],
      [
        { key: 'file_name' },
        { key: 'evidence_id', mono: true },
        {
          key: 'sha256',
          mono: true,
          value: r => r.sha256
            ? `${String(r.sha256).slice(0, 20)}…`
            : '—'
        },
        { key: 'acquired_at', value: r => formatDate(r.acquired_at) }
      ],
      'No evidence has been registered yet.'
    );
  }

  async function loadEvidence(caseId) {
    if (!caseId) {
      state.evidence = [];
      return [];
    }

    const data = await api(
      `/api/evidence?case_id=${encodeURIComponent(caseId)}`
    );

    state.evidence = Array.isArray(data.evidence)
      ? data.evidence
      : [];

    return state.evidence;
  }

  async function refreshCasesPage() {
    await loadCases();
  }

  async function createCase(event) {
    event.preventDefault();
    clearMessage('create-case-message');

    const button = $('#create-case-form button[type="submit"]');

    const payload = {
      case_name: value('case-name'),
      description: value('case-description'),
      actor: actorFrom('investigator-name')
    };

    if (!payload.case_name) {
      showMessage(
        'create-case-message',
        'Enter a case name.',
        'error'
      );
      return;
    }

    setBusy(button, true, 'Creating case…');

    try {
      const result = await api('/api/cases', {
        method: 'POST',
        body: payload
      });

      const created = result.case || {};

      await loadCases();

      if (created.case_id) {
        [
          'selected-case',
          'acquire-case',
          'analysis-case',
          'custody-case',
          'recovery-case'
        ].forEach(id => {
          const el = byId(id);
          if (el) el.value = created.case_id;
        });

        localStorage.setItem(
          'datalens-selected-case',
          created.case_id
        );
      }

      setText(
        'selected-case-summary',
        `${created.case_name || payload.case_name} · ${created.status || 'Created'}`
      );

      showMessage(
        'create-case-message',
        `Case created successfully: ${created.case_name || payload.case_name}.`,
        'success'
      );

      byId('create-case-form').reset();

      const investigator = byId('investigator-name');
      if (investigator) investigator.value = payload.actor;

      await loadDashboard();
    } catch (error) {
      showMessage(
        'create-case-message',
        error.message,
        'error'
      );
    } finally {
      setBusy(button, false);
    }
  }

  function syncCaseSelection(sourceId) {
    const source = byId(sourceId);
    if (!source) return;

    const caseId = source.value;

    if (caseId) {
      localStorage.setItem('datalens-selected-case', caseId);
    }

    if (sourceId === 'selected-case') {
      setText(
        'selected-case-summary',
        state.cases.find(item => item.case_id === caseId)?.case_name ||
          'No case selected.'
      );
    }

    [
      'selected-case',
      'acquire-case',
      'analysis-case',
      'custody-case',
      'recovery-case'
    ].forEach(id => {
      const target = byId(id);

      if (
        target &&
        target !== source &&
        caseId &&
        Array.from(target.options).some(option => option.value === caseId)
      ) {
        target.value = caseId;
      }
    });

    if (state.currentPage === 'acquire') {
      refreshAcquiredEvidence().catch(showError);
    }

    if (state.currentPage === 'analysis') {
      loadAnalysis().catch(showError);
    }

    if (state.currentPage === 'custody') {
      loadCustody().catch(showError);
    }
  }

  async function refreshAcquiredEvidence() {
    const caseId = value('acquire-case');
    const rows = await loadEvidence(caseId);

    renderRows(
      'acquired-evidence-body',
      rows,
      [
        { key: 'file_name' },
        { key: 'evidence_id', mono: true },
        { key: 'size_bytes', value: r => formatBytes(r.size_bytes) },
        { key: 'sha256', mono: true },
        { key: 'acquired_at', value: r => formatDate(r.acquired_at) }
      ],
      'No evidence registered in this case yet.'
    );
  }
    async function detectDevices() {
    const container = byId('device-list');
    const button = byId('detect-devices');

    if (container) {
      container.textContent = 'Detecting mounted removable volumes…';
    }

    setBusy(button, true, 'Detecting…');

    try {
      const data = await api('/api/devices');

      state.devices = Array.isArray(data.devices) ? data.devices : [];
      state.selectedDevice = null;

      renderDevices();
    } catch (error) {
      if (container) {
        container.textContent = `Device detection failed: ${error.message}`;
      }

      showMessage('device-message', error.message, 'error');
    } finally {
      setBusy(button, false);
    }
  }

  function renderDevices() {
    const container = byId('device-list');
    if (!container) return;

    container.replaceChildren();

    const controls = byId('device-acquire-controls');
    if (controls) controls.hidden = !state.devices.length;

    const acquireButton = byId('acquire-device');
    if (acquireButton) acquireButton.disabled = true;

    if (!state.devices.length) {
      const empty = document.createElement('div');
      empty.className = 'empty-state';

      const strong = document.createElement('strong');
      strong.textContent = 'No mounted removable volumes detected';

      const p = document.createElement('p');
      p.textContent =
        'You can acquire individual files using the upload panel.';

      empty.append(strong, p);
      container.appendChild(empty);
      return;
    }

    state.devices.forEach((device, index) => {
      const mountpoint =
        device.mountpoint ||
        device.mount_point ||
        device.path ||
        device.drive_letter ||
        '';

      const name =
        device.name ||
        device.model ||
        device.device ||
        mountpoint ||
        `Device ${index + 1}`;

      const card = document.createElement('button');
      card.type = 'button';
      card.className = 'device-card';
      card.setAttribute('aria-pressed', 'false');

      const title = document.createElement('strong');
      title.textContent = name;

      const meta = document.createElement('span');
      meta.className = 'device-card-meta';
      meta.textContent =
        `${mountpoint || 'No mount point'} · ${formatBytes(device.size_bytes ?? device.size)} · ${device.filesystem || device.fstype || 'Filesystem unknown'}`;

      const detail = document.createElement('small');
      detail.textContent =
        `Removable: ${cellText(device.removable ?? 'Not reported')} · Type: ${cellText(device.transport || device.type || device.device_type || 'Not reported')}`;

      card.append(title, meta, detail);

      card.addEventListener('click', () => {
        state.selectedDevice = {
          ...device,
          _mountpoint: mountpoint,
          _displayName: name
        };

        $$('.device-card', container).forEach(item => {
          item.classList.remove('selected');
          item.setAttribute('aria-pressed', 'false');
        });

        card.classList.add('selected');
        card.setAttribute('aria-pressed', 'true');

        if (controls) controls.hidden = false;

        updateAcquireButton();
      });

      container.appendChild(card);
    });

    if (controls) controls.hidden = false;
  }

  function updateAcquireButton() {
    const button = byId('acquire-device');

    if (button) {
      button.disabled = !(
        state.selectedDevice &&
        state.selectedDevice._mountpoint &&
        byId('device-authorized')?.checked &&
        value('acquire-case')
      );
    }
  }

  async function acquireDevice() {
    const device = state.selectedDevice;
    const caseId = value('acquire-case');

    if (
      !device ||
      !device._mountpoint ||
      !caseId ||
      !byId('device-authorized')?.checked
    ) {
      showMessage(
        'device-message',
        'Choose a mounted volume, select a case, and confirm authorization.',
        'error'
      );
      return;
    }

    const button = byId('acquire-device');
    setBusy(button, true, 'Acquiring files…');
    clearMessage('device-message');

    try {
      const result = await api('/api/acquire/device', {
        method: 'POST',
        body: {
          case_id: caseId,
          mountpoint: device._mountpoint,
          authorized: true,
          actor: actorFrom('acquire-investigator', 'investigator-name')
        }
      });

      showMessage(
        'device-message',
        `Acquisition finished: ${result.successful ?? 0} succeeded; ${result.failed ?? 0} failed.`,
        (result.failed || 0) ? 'error' : 'success'
      );

      await refreshAcquiredEvidence();
      await loadDashboard();
    } catch (error) {
      showMessage('device-message', error.message, 'error');
    } finally {
      setBusy(button, false);
      updateAcquireButton();
    }
  }

  function fileToBase64(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();

      reader.onload = () => {
        const result = String(reader.result || '');
        const comma = result.indexOf(',');

        resolve(comma >= 0 ? result.slice(comma + 1) : result);
      };

      reader.onerror = () => reject(
        new Error(`Could not read ${file.name}.`)
      );

      reader.readAsDataURL(file);
    });
  }

  function renderUploadList() {
    const files = Array.from(byId('evidence-files')?.files || []);
    const list = byId('selected-upload-list');

    if (list) {
      list.replaceChildren();

      files.forEach(file => {
        const item = document.createElement('div');
        item.className = 'selected-file-row';

        const name = document.createElement('span');
        name.textContent = file.name;

        const size = document.createElement('small');
        size.textContent = formatBytes(file.size);

        item.append(name, size);
        list.appendChild(item);
      });
    }

    const button = byId('upload-evidence-button');

    if (button) {
      button.disabled = !files.length || !value('acquire-case');
    }
  }

  async function uploadEvidence(event) {
    event.preventDefault();

    const files = Array.from(byId('evidence-files')?.files || []);
    const caseId = value('acquire-case');

    if (!caseId || !files.length) {
      showMessage(
        'upload-message',
        'Select a case and at least one file.',
        'error'
      );
      return;
    }

    const button = byId('upload-evidence-button');
    setBusy(button, true, 'Reading files…');
    clearMessage('upload-message');

    try {
      const encodedFiles = [];

      for (const file of files) {
        encodedFiles.push({
          name: file.name,
          data_base64: await fileToBase64(file)
        });
      }

      if (
        encodedFiles.reduce(
          (total, item) => total + item.data_base64.length,
          0
        ) > 500 * 1024 * 1024
      ) {
        throw new Error(
          'Selected uploads are too large for the current local API request limit. Acquire fewer or smaller files at a time.'
        );
      }

      const result = await api('/api/acquire/upload', {
        method: 'POST',
        body: {
          case_id: caseId,
          actor: actorFrom('acquire-investigator', 'investigator-name'),
          files: encodedFiles
        }
      });

      showMessage(
        'upload-message',
        `Acquisition finished: ${result.successful || 0} succeeded; ${result.failed || 0} failed.`,
        result.failed ? 'error' : 'success'
      );

      if (result.results?.some(item => !item.ok)) {
        const errors = result.results
          .filter(item => !item.ok)
          .map(item => `${item.file_name}: ${item.error}`)
          .join(' | ');

        showMessage(
          'upload-message',
          `Acquisition finished: ${result.successful || 0} succeeded; ${result.failed || 0} failed. ${errors}`,
          'error'
        );
      }

      byId('evidence-files').value = '';
      renderUploadList();

      await refreshAcquiredEvidence();
      await loadDashboard();
    } catch (error) {
      showMessage('upload-message', error.message, 'error');
    } finally {
      setBusy(button, false);
      renderUploadList();
    }
  }
    function renderAnalysisResults(rows) {
    renderRows(
      'analysis-results-body',
      rows,
      [
        { key: 'file_name' },
        { key: 'risk_level', tone: row => {
          const risk = String(row.risk_level || '').toLowerCase();
          if (risk === 'high' || risk === 'critical') return 'text-danger';
          if (risk === 'low') return 'text-success';
          return '';
        }},
        { key: 'anomaly_score' },
        { key: 'prediction' },
        { key: 'details' }
      ],
      'No analysis results are available for this case yet.'
    );
  }

  async function loadAnalysis() {
    const caseId = value('analysis-case');
    if (!caseId) {
      state.analysisRows = [];
      state.analysisCase = '';
      renderAnalysisResults([]);
      return;
    }

    const data = await api(
      `/api/analysis?case_id=${encodeURIComponent(caseId)}`
    );

    state.analysisRows = Array.isArray(data.results)
      ? data.results
      : [];

    state.analysisCase = caseId;
    renderAnalysisResults(state.analysisRows);
  }

  async function runAnalysis() {
    const caseId = value('analysis-case');

    if (!caseId) {
      showMessage('analysis-message', 'Select a case first.', 'error');
      return;
    }

    const button = byId('run-analysis');
    setBusy(button, true, 'Analyzing…');
    clearMessage('analysis-message');

    try {
      const result = await api('/api/analyze', {
        method: 'POST',
        body: {
          case_id: caseId,
          actor: actorFrom('analysis-investigator', 'investigator-name')
        }
      });

      showMessage(
        'analysis-message',
        result.message || 'Analysis completed.',
        'success'
      );

      await loadAnalysis();
      await loadDashboard();
    } catch (error) {
      showMessage('analysis-message', error.message, 'error');
    } finally {
      setBusy(button, false);
    }
  }

  function exportAnalysis(format) {
    const rows = state.analysisRows;

    if (!rows.length) {
      showMessage(
        'analysis-message',
        'There are no analysis results to export.',
        'error'
      );
      return;
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const caseId = state.analysisCase || 'case';

    let content;
    let type;
    let extension;

    if (format === 'json') {
      content = JSON.stringify(rows, null, 2);
      type = 'application/json;charset=utf-8';
      extension = 'json';
    } else {
      const columns = Array.from(
        new Set(rows.flatMap(row => Object.keys(row)))
      );

      const escapeCSV = value => {
        const text = value === null || value === undefined
          ? ''
          : typeof value === 'object'
            ? JSON.stringify(value)
            : String(value);

        return `"${text.replace(/"/g, '""')}"`;
      };

      content = [
        columns.map(escapeCSV).join(','),
        ...rows.map(row =>
          columns.map(column => escapeCSV(row[column])).join(',')
        )
      ].join('\r\n');

      type = 'text/csv;charset=utf-8';
      extension = 'csv';
    }

    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');

    link.href = url;
    link.download = `datalens-analysis-${caseId}-${timestamp}.${extension}`;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  }
  async function loadCustody() {
    const caseId = value('custody-case');
    const evidenceSelect = byId('verify-evidence');
    const reportSelect = byId('report-evidence');

    if (!caseId) {
      setText('custody-evidence-count', '0');
      setText('custody-events-count', '0');
      setText('custody-chain-status', '—');
      renderRows('custody-evidence-body', [], [
        { key: 'file_name' }, { key: 'evidence_id' }, { key: 'sha256' },
        { key: 'acquired_at' }, { key: 'status' }
      ], 'Select a case to view evidence.');
      renderRows('custody-events-body', [], [
        { key: 'timestamp' }, { key: 'actor' }, { key: 'action' },
        { key: 'evidence_id' }, { key: 'details' }
      ], 'Select a case to view custody history.');
      [evidenceSelect, reportSelect].forEach(select => {
        if (!select) return;
        select.replaceChildren();
        const option = document.createElement('option');
        option.value = '';
        option.textContent = 'Select evidence…';
        select.appendChild(option);
      });
      return;
    }

    const data = await api(`/api/custody?case_id=${encodeURIComponent(caseId)}`);
    const evidence = Array.isArray(data.evidence) ? data.evidence : [];
    const events = Array.isArray(data.events) ? data.events :
      (Array.isArray(data.records) ? data.records : []);
    const integrity = data.integrity && typeof data.integrity === 'object'
      ? data.integrity : {};

    setText('custody-evidence-count', evidence.length);
    setText('custody-events-count', events.length);
    setText('custody-chain-status', integrity.valid === true ? 'VALID' :
      integrity.valid === false ? 'CHECK FAILED' : 'UNKNOWN');

    renderRows('custody-evidence-body', evidence, [
      { key: 'file_name' },
      { key: 'evidence_id', mono: true },
      { key: 'sha256', mono: true },
      { key: 'acquired_at', value: row => formatDate(row.acquired_at) },
      { key: 'status' }
    ], 'No evidence is registered in this case.');

    renderRows('custody-events-body', events, [
      { key: 'timestamp', value: row => formatDate(row.timestamp) },
      { key: 'actor' },
      { key: 'action' },
      { key: 'evidence_id', mono: true },
      { key: 'details', value: row => row.details ?? row.details_json ?? '' }
    ], 'No custody events are recorded for this case.');

    [evidenceSelect, reportSelect].forEach(select => {
      if (!select) return;
      const previous = select.value;
      select.replaceChildren();
      const placeholder = document.createElement('option');
      placeholder.value = '';
      placeholder.textContent = evidence.length ? 'Select evidence…' : 'No evidence in this case';
      select.appendChild(placeholder);
      evidence.forEach(item => {
        const option = document.createElement('option');
        option.value = item.evidence_id || '';
        option.textContent = `${item.file_name || 'Evidence file'} · ${item.evidence_id || ''}`;
        select.appendChild(option);
      });
      select.value = evidence.some(item => item.evidence_id === previous) ? previous : '';
    });
    clearMessage('verify-message');
    clearMessage('report-message');
  }

  async function verifyEvidence() {
    const evidenceId = value('verify-evidence');
    const actor = actorFrom('custody-investigator', 'investigator-name');
    if (!evidenceId) {
      showMessage('verify-message', 'Select an evidence item first.', 'error');
      return;
    }
    const button = byId('verify-evidence-button');
    setBusy(button, true, 'Verifying…');
    clearMessage('verify-message');
    try {
      const result = await api('/api/verify', {
        method: 'POST', body: { evidence_id: evidenceId, actor }
      });
      const outcome = result.outcome && typeof result.outcome === 'object'
        ? result.outcome : result;
      const status = String(outcome.status || result.status || '').toUpperCase();
      const verified = status === 'VERIFIED' || result.verified === true ||
        result.valid === true || result.integrity_ok === true;
      const message = outcome.message || result.message ||
        (status === 'VERIFIED' ? 'SHA-256 verification passed: stored content matches the recorded hash.' :
        status === 'MISMATCH' ? 'Integrity check failed: the stored file does not match its recorded SHA-256 hash.' :
        status === 'MISSING' ? 'Integrity check failed: the stored evidence file is missing.' :
        `Verification result: ${status || 'UNKNOWN'}.`);
      showMessage('verify-message', message, verified ? 'success' : 'error');
      await loadCustody();
    } catch (error) {
      showMessage('verify-message', error.message || String(error), 'error');
    } finally {
      setBusy(button, false);
    }
  }

  async function verifyCustody() {
    const caseId = value('custody-case');

    if (!caseId) {
      showMessage(
        'custody-verification-message',
        'Select a case first.',
        'error'
      );
      return;
    }

    const button = byId('verify-custody-button');
    setBusy(button, true, 'Checking…');
    clearMessage('custody-verification-message');

    try {
      const result = await api('/api/verify', {
        method: 'POST',
        body: {
          case_id: caseId,
          verify_custody: true,
          actor: actorFrom('custody-investigator', 'investigator-name')
        }
      });

      const verified = Boolean(
        result.verified ?? result.valid ?? result.integrity_ok
      );

      showMessage(
        'custody-verification-message',
        result.message ||
          (verified
            ? 'Custody verification passed.'
            : 'Custody verification did not pass. Review the returned result.'),
        verified ? 'success' : 'error'
      );

      await loadCustody();
    } catch (error) {
      showMessage(
        'custody-verification-message',
        error.message,
        'error'
      );
    } finally {
      setBusy(button, false);
    }
  }

  async function generateCaseReport() {
    const caseId = value('custody-case');

    if (!caseId) {
      showMessage('report-message', 'Select a case first.', 'error');
      return;
    }

    const button = byId('generate-case-report');
    setBusy(button, true, 'Generating…');
    clearMessage('report-message');

    try {
      const result = await api('/api/reports/case', {
        method: 'POST',
        body: {
          case_id: caseId,
          actor: actorFrom('custody-investigator', 'investigator-name')
        }
      });

      showMessage(
        'report-message',
        result.message ||
          result.filename ||
          result.path ||
          'Case report generated.',
        'success'
      );

      if (result.download_url) {
        downloadReport(result.download_url);
      }
    } catch (error) {
      showMessage('report-message', error.message, 'error');
    } finally {
      setBusy(button, false);
    }
  }

  async function generateEvidenceReport() {
    const evidenceId = value('report-evidence');

    if (!evidenceId) {
      showMessage(
        'report-message',
        'Select an evidence item first.',
        'error'
      );
      return;
    }

    const button = byId('generate-evidence-report');
    setBusy(button, true, 'Generating…');
    clearMessage('report-message');

    try {
      const result = await api('/api/reports/evidence', {
        method: 'POST',
        body: {
          evidence_id: evidenceId,
          actor: actorFrom('custody-investigator', 'investigator-name')
        }
      });

      showMessage(
        'report-message',
        result.message ||
          result.filename ||
          result.path ||
          'Evidence report generated.',
        'success'
      );

      if (result.download_url) {
        downloadReport(result.download_url);
      }
    } catch (error) {
      showMessage('report-message', error.message, 'error');
    } finally {
      setBusy(button, false);
    }
  }
    async function scanRecovery() {
    const caseId = value('recovery-case');
    const source = value('recovery-source');

    if (!caseId || !source) {
      showMessage(
        'recovery-message',
        'Select a case and provide the recovery source path.',
        'error'
      );
      return;
    }

    const button = byId('scan-recovery');
    setBusy(button, true, 'Scanning…');
    clearMessage('recovery-message');

    try {
      const result = await api('/api/recovery/scan', {
        method: 'POST',
        body: {
          case_id: caseId,
          source_path: source,
          actor: actorFrom('recovery-investigator', 'investigator-name')
        }
      });

      state.recoveryCandidates = Array.isArray(result.candidates)
        ? result.candidates
        : [];

      state.recoverySource = result.source_path || source;

      renderRows(
        'recovery-results-body',
        state.recoveryCandidates,
        [
          { key: 'file_name', value: row => row.file_name || row.candidate_id || 'Unknown candidate' },
          { key: 'offset', mono: true },
          { key: 'size_bytes', value: row => formatBytes(row.size_bytes) },
          { key: 'file_type' },
          { key: 'status' }
        ],
        'No recoverable file candidates were found.'
      );

      showMessage(
        'recovery-message',
        result.message ||
          `Scan completed. ${state.recoveryCandidates.length} candidate(s) found.`,
        'success'
      );
    } catch (error) {
      showMessage('recovery-message', error.message, 'error');
    } finally {
      setBusy(button, false);
    }
  }

  async function registerRecoveredFiles() {
    const caseId = value('recovery-case');

    if (!caseId || !state.recoveryCandidates.length) {
      showMessage(
        'recovery-message',
        'Run a recovery scan and select a case first.',
        'error'
      );
      return;
    }

    const button = byId('register-recovered');
    setBusy(button, true, 'Registering…');

    try {
      const result = await api('/api/recovery/register', {
        method: 'POST',
        body: {
          case_id: caseId,
          source_path: state.recoverySource,
          candidates: state.recoveryCandidates,
          actor: actorFrom('recovery-investigator', 'investigator-name')
        }
      });

      showMessage(
        'recovery-message',
        result.message ||
          `Recovery registration completed: ${result.registered ?? 0} item(s).`,
        'success'
      );

      await loadEvidence(caseId);
      await loadDashboard();
    } catch (error) {
      showMessage('recovery-message', error.message, 'error');
    } finally {
      setBusy(button, false);
    }
  }

  async function loadSystemChecks() {
    const button = byId('run-system-checks');

    if (button) setBusy(button, true, 'Checking…');

    try {
      const result = await api('/api/system-checks');

      const checks = Array.isArray(result.checks)
        ? result.checks
        : [];

      renderRows(
        'system-checks-body',
        checks,
        [
          { key: 'Check', value: row => row.Check ?? row.check ?? row.name ?? '—' },
          {
            key: 'Result',
            value: row => {
              const status = row.Status ?? row.status ?? row.result ?? '—';
              const severity = row.Severity ?? row.severity;
              const details = row.Details ?? row.details;
              const parts = [String(status)];
              if (severity) parts.push(`Severity: ${severity}`);
              if (details) parts.push(String(details));
              return parts.join(' — ');
            }
          }
        ],
        'No system-check results are available.'
      );

      const summary = `${checks.length} system check(s) completed.`;
      if (byId('global-message')) {
        globalMessage(result.message || summary, 'success');
      }
    } catch (error) {
      showMessage('system-checks-message', error.message, 'error');
    } finally {
      if (button) setBusy(button, false);
    }
  }

  async function loadDeviceStatus() {
    try {
      const result = await api('/api/devices');
      state.devices = Array.isArray(result.devices) ? result.devices : [];

      setText(
        'system-device-count',
        String(state.devices.length)
      );
    } catch (error) {
      setText('system-device-count', 'Unavailable');
    }
  }


async function refreshPage(page) {
  switch (page) {
    case 'dashboard':
      await Promise.all([loadDashboard(), loadCases()]);
      break;

    case 'cases':
      await loadCases();
      break;

    case 'acquire':
      await loadCases();
      await refreshAcquiredEvidence();
      break;

    case 'analysis':
      await loadCases();
      await loadAnalysis();
      break;

    case 'custody':
      await loadCases();
      await loadCustody();
      break;

    case 'recovery':
      await loadCases();
      break;

    case 'system':
      await Promise.all([loadSystemChecks(), loadDeviceStatus()]);
      break;

    default:
      break;
  }
}


  function showError(error, target = 'global-message') {
    const message = error instanceof Error
      ? error.message
      : String(error || 'An unexpected error occurred.');

    if (target === 'global-message') {
      globalMessage(message, 'error');
    } else {
      showMessage(target, message, 'error');
    }
  }

  
async function checkConnection() {
  const status = byId('connection-label');
  const dot = byId('connection-dot');

  function updateStatus(connected) {
    if (status) {
      status.textContent = connected
        ? 'Connected to local service'
        : 'Local service disconnected';
    }

    if (dot) {
      dot.classList.toggle('status-success', connected);
      dot.classList.toggle('status-error', !connected);
    }
  }

  try {
    const result = await api('/api/health');

    const connected = Boolean(result && result.ok === true);
    updateStatus(connected);
    return connected;
  } catch (error) {
    updateStatus(false);
    console.error('DataLens connection check failed:', error);
    return false;
  }
}

  
  async function createBackup() {
    const button = $$('button').find(item =>
      item.textContent.trim().toLowerCase().includes('create backup')
    );
    if (button) setBusy(button, true, 'Creating backup…');
    clearGlobalMessage();
    try {
      const result = await api('/api/backup', { method: 'POST', body: {} });
      if (!result || result.ok !== true || !result.download_url) {
        throw new Error(result?.error || 'The server did not return a backup download link.');
      }
      downloadReport(result.download_url);
      globalMessage(`${result.message || 'Backup created.'} File: ${result.filename}`, 'success');
    } catch (error) {
      globalMessage(`Backup failed: ${error.message}`, 'error');
    } finally {
      if (button) setBusy(button, false);
    }
  }

    function bindEvents() {
    // The current HTML exposes this action by its visible label rather than a stable ID.
    const backupButton = $$('button').find(button =>
      button.textContent.trim().toLowerCase().includes('create backup')
    );
    if (backupButton) {
      backupButton.disabled = false;
      backupButton.removeAttribute('aria-disabled');
      backupButton.title = 'Create and download a local DataLens backup ZIP';
      backupButton.addEventListener('click', event => {
        event.preventDefault();
        createBackup();
      });
    }
    $$('[data-page]').forEach(button => {
      button.addEventListener('click', () => {
        navigate(button.dataset.page);
      });
    });

    byId('create-case-form')?.addEventListener('submit', createCase);

    [
      'selected-case',
      'acquire-case',
      'analysis-case',
      'custody-case',
      'recovery-case'
    ].forEach(id => {
      byId(id)?.addEventListener('change', async () => {
        if (id === 'selected-case') {
          localStorage.setItem('datalens-selected-case', value(id));
        }

        if (id === 'acquire-case') {
          updateAcquireButton();
          await refreshAcquiredEvidence().catch(error => {
            showError(error, 'upload-message');
          });
        }

        if (id === 'analysis-case') {
          await loadAnalysis().catch(error => {
            showError(error, 'analysis-message');
          });
        }

        if (id === 'custody-case') {
          await loadCustody().catch(error => {
            showError(error, 'verify-message');
          });
        }
      });
    });

    byId('detect-devices')?.addEventListener('click', detectDevices);
    byId('acquire-device')?.addEventListener('click', acquireDevice);

    byId('device-authorized')?.addEventListener('change', updateAcquireButton);

    byId('evidence-files')?.addEventListener('change', renderUploadList);

    byId('upload-evidence-form')?.addEventListener('submit', uploadEvidence);

    byId('run-analysis')?.addEventListener('click', runAnalysis);

    byId('export-analysis-csv')?.addEventListener('click', () => {
      exportAnalysis('csv');
    });

    byId('export-analysis-json')?.addEventListener('click', () => {
      exportAnalysis('json');
    });

    byId('verify-evidence-button')?.addEventListener('click', verifyEvidence);
    byId('refresh-custody')?.addEventListener('click', () => loadCustody().catch(error => showMessage('verify-message', error.message, 'error')));

    byId('verify-custody-button')?.addEventListener('click', verifyCustody);

    byId('generate-case-report')?.addEventListener('click', generateCaseReport);

    byId('generate-evidence-report')?.addEventListener('click', generateEvidenceReport);

    byId('scan-recovery')?.addEventListener('click', scanRecovery);

    byId('register-recovered')?.addEventListener('click', registerRecoveredFiles);

    byId('run-system-checks')?.addEventListener('click', loadSystemChecks);

    // Mobile navigation menu
    const menuButton = byId('mobile-menu-button');
    const sidebar = byId('sidebar');

    function closeMobileMenu() {
      if (sidebar) sidebar.classList.remove('sidebar-open');
      document.body.classList.remove('sidebar-menu-open');

      if (menuButton) {
        menuButton.setAttribute('aria-expanded', 'false');
      }
    }

    menuButton?.addEventListener('click', event => {
      event.preventDefault();

      const open = sidebar?.classList.toggle('sidebar-open') || false;

      document.body.classList.toggle('sidebar-menu-open', open);
      menuButton.setAttribute('aria-expanded', String(open));
    });

    document.addEventListener('click', event => {
      if (!sidebar?.classList.contains('sidebar-open')) return;

      if (
        sidebar.contains(event.target) ||
        menuButton?.contains(event.target)
      ) {
        return;
      }

      closeMobileMenu();
    });

    document.addEventListener('keydown', event => {
      if (event.key === 'Escape') closeMobileMenu();
    });
  }

  document.addEventListener('DOMContentLoaded', async () => {
    try {
      bindEvents();

      const investigator = localStorage.getItem('datalens-investigator');

      if (investigator) {
        const input = byId('investigator-name');

        if (input) input.value = investigator;
      }

      byId('investigator-name')?.addEventListener('change', event => {
        localStorage.setItem(
          'datalens-investigator',
          event.target.value.trim()
        );
      });

      await checkConnection();

      const initialPage = location.hash.replace('#', '');

      navigate(
        pageNames[initialPage] ? initialPage : 'dashboard',
        false
      );

      await loadCases();
    } catch (error) {
      showError(error);
    }
  });
})();
