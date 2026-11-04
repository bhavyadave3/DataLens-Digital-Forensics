
/* DataLens frontend controller
   Handles UI and local API requests only.
   Forensic operations remain in the Python modules.
*/

(() => {
  'use strict';

  // ------------------------------------------------------------
  // STATE AND HELPERS
  // ------------------------------------------------------------

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) =>
    Array.from(root.querySelectorAll(selector));

  const state = {
    cases: [],
    evidence: [],
    devices: [],
    selectedDevice: null,
    recoveryCandidates: [],
    recoverySource: '',
    analysisRows: [],
    analysisCase: '',
    currentPage: 'dashboard'
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
    const element = byId(id);
    return element
      ? String(element.value ?? fallback).trim()
      : fallback;
  }

  function actorFrom(...ids) {
    for (const id of ids) {
      const name = value(id);
      if (name) return name;
    }

    return value('investigator-name', 'Investigator') || 'Investigator';
  }

  function setText(id, text) {
    const element = byId(id);
    if (element) {
      element.textContent = text == null ? '' : String(text);
    }
  }

  function showMessage(id, message, kind = 'neutral') {
    const element = byId(id);
    if (!element) return;

    element.textContent = String(message ?? '');
    element.className = `inline-message message-${kind}`;
    element.hidden = false;
  }

  function clearMessage(id) {
    const element = byId(id);

    if (element) {
      element.hidden = true;
      element.textContent = '';
    }
  }

  function globalMessage(message, kind = 'neutral') {
    const element = byId('global-message');
    if (!element) return;

    element.textContent = String(message ?? '');
    element.className = `global-message message-${kind}`;
    element.hidden = false;
  }

  function clearGlobalMessage() {
    const element = byId('global-message');

    if (element) {
      element.hidden = true;
      element.textContent = '';
    }
  }

  function setBusy(button, busy, busyText = 'Working…') {
    if (!button) return;

    if (busy) {
      if (!button.dataset.originalText) {
        button.dataset.originalText = button.textContent;
      }

      button.textContent = busyText;
      button.disabled = true;
      button.setAttribute('aria-busy', 'true');
    } else {
      button.textContent =
        button.dataset.originalText || button.textContent;

      delete button.dataset.originalText;
      button.disabled = false;
      button.removeAttribute('aria-busy');
    }
  }

  function formatBytes(bytes) {
    const number = Number(bytes);

    if (!Number.isFinite(number) || number < 0) return 'Unknown';
    if (number === 0) return '0 B';

    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    const index = Math.min(
      Math.floor(Math.log(number) / Math.log(1024)),
      units.length - 1
    );

    return `${(number / Math.pow(1024, index)).toFixed(
      index === 0 ? 0 : 1
    )} ${units[index]}`;
  }

  function formatDate(input) {
    if (!input) return '—';

    const date = new Date(input);

    return Number.isNaN(date.getTime())
      ? String(input)
      : date.toLocaleString();
  }

  function cellText(input) {
    if (input === null || input === undefined || input === '') {
      return '—';
    }

    if (typeof input === 'object') {
      try {
        return JSON.stringify(input);
      } catch {
        return String(input);
      }
    }

    return String(input);
  }

  function makeCell(content, options = {}) {
    const cell = document.createElement('td');
    cell.textContent = cellText(content);

    if (options.mono) {
      cell.classList.add('mono');
    }

    if (options.tone) {
      cell.classList.add(options.tone);
    }

    return cell;
  }

  function renderRows(
    bodyId,
    rows,
    columns,
    emptyText = 'No records found.'
  ) {
    const body = byId(bodyId);
    if (!body) return;

    body.replaceChildren();

    if (!Array.isArray(rows) || rows.length === 0) {
      const row = document.createElement('tr');
      const cell = document.createElement('td');

      cell.colSpan = Math.max(columns.length, 1);
      cell.className = 'empty-cell';
      cell.textContent = emptyText;

      row.appendChild(cell);
      body.appendChild(row);
      return;
    }

    rows.forEach(item => {
      const row = document.createElement('tr');

      columns.forEach(column => {
        const raw = typeof column.value === 'function'
          ? column.value(item)
          : item[column.key];

        const cell = makeCell(raw, {
          mono: column.mono
        });

        if (column.tone) {
          const tone = typeof column.tone === 'function'
            ? column.tone(item, raw)
            : column.tone;

          if (tone) cell.classList.add(tone);
        }

        row.appendChild(cell);
      });

      body.appendChild(row);
    });
  }

  // ------------------------------------------------------------
  // API HELPER
  // ------------------------------------------------------------

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

    const contentType = response.headers.get('content-type') || '';

    const data = contentType.includes('application/json')
      ? await response.json()
      : await response.text();

    if (!response.ok) {
      const message =
        data && typeof data === 'object' && data.error
          ? data.error
          : `Request failed (${response.status}).`;

      throw new Error(message);
    }

    return data;
  }

  function downloadReport(downloadUrl) {
    if (!downloadUrl) {
      throw new Error('The server did not provide a download URL.');
    }

    const url = new URL(downloadUrl, window.location.origin);

    if (url.origin !== window.location.origin) {
      throw new Error(
        'Downloads must use the local DataLens server.'
      );
    }

    const link = document.createElement('a');
    link.href = url.href;
    link.style.display = 'none';

    document.body.appendChild(link);
    link.click();
    link.remove();
  }

  // ------------------------------------------------------------
  // NAVIGATION
  // ------------------------------------------------------------

  function navigate(page, updateHash = true) {
    if (!pageNames[page]) {
      page = 'dashboard';
    }

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

    byId('sidebar')?.classList.remove('sidebar-open');
    byId('mobile-menu-button')?.setAttribute(
      'aria-expanded',
      'false'
    );

    document.body.classList.remove('sidebar-menu-open');

    if (updateHash && location.hash !== `#${page}`) {
      history.replaceState(null, '', `#${page}`);
    }

    clearGlobalMessage();

    refreshPage(page).catch(error => {
      globalMessage(error.message, 'error');
    });
  }

  async function refreshPage(page) {
    switch (page) {
      case 'dashboard':
        await Promise.all([
          loadDashboard(),
          loadCases()
        ]);
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
        renderRecoveryCandidates(state.recoveryCandidates);
        break;

      case 'system':
        await Promise.all([
          loadSystemChecks(),
          refreshSystemDevices()
        ]);
        break;

      default:
        break;
    }
  }

  // ------------------------------------------------------------
  // CASE MANAGEMENT
  // ------------------------------------------------------------

  async function loadCases() {
    const data = await api('/api/cases');

    state.cases = Array.isArray(data.cases)
      ? data.cases
      : [];

    const selectIds = [
      'selected-case',
      'acquire-case',
      'analysis-case',
      'custody-case',
      'recovery-case'
    ];

    selectIds.forEach(id => {
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
        {
          key: 'created_at',
          value: row => formatDate(row.created_at)
        },
        { key: 'description' }
      ],
      'No cases yet. Create your first case using the form.'
    );

    updateSelectedCaseSummary();
    updateAcquireButton();
    renderUploadList();
  }

  function updateSelectedCaseSummary() {
    const caseId = value('selected-case');

    const selected = state.cases.find(
      item => item.case_id === caseId
    );

    setText(
      'selected-case-summary',
      selected
        ? `${selected.case_name || 'Untitled case'} · ${selected.status || 'Status not reported'}`
        : 'No case selected.'
    );
  }

  function syncCaseSelection(sourceId) {
    const source = byId(sourceId);
    if (!source) return;

    const caseId = source.value;

    if (caseId) {
      localStorage.setItem('datalens-selected-case', caseId);
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
        Array.from(target.options).some(
          option => option.value === caseId
        )
      ) {
        target.value = caseId;
      }
    });

    updateSelectedCaseSummary();
    updateAcquireButton();
    renderUploadList();

    if (state.currentPage === 'acquire') {
      refreshAcquiredEvidence().catch(error => {
        showMessage('upload-message', error.message, 'error');
      });
    }

    if (state.currentPage === 'analysis') {
      loadAnalysis().catch(error => {
        showMessage('analysis-message', error.message, 'error');
      });
    }

    if (state.currentPage === 'custody') {
      loadCustody().catch(error => {
        showMessage('verify-message', error.message, 'error');
      });
    }

    if (state.currentPage === 'recovery') {
      state.recoveryCandidates = [];
      state.recoverySource = '';
      renderRecoveryCandidates([]);
      clearMessage('recovery-message');
    }
  }

  async function createCase(event) {
    event.preventDefault();

    clearMessage('create-case-message');

    const form = byId('create-case-form');
    const button = form?.querySelector('button[type="submit"]');

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
          const select = byId(id);
          if (select) select.value = created.case_id;
        });

        localStorage.setItem(
          'datalens-selected-case',
          created.case_id
        );
      }

      updateSelectedCaseSummary();

      showMessage(
        'create-case-message',
        `Case created successfully: ${created.case_name || payload.case_name}.`,
        'success'
      );

      form?.reset();

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

  // ------------------------------------------------------------
  // DASHBOARD
  // ------------------------------------------------------------

  async function loadDashboard() {
    const data = await api('/api/dashboard');

    setText('metric-cases', data.cases_count ?? 0);
    setText('metric-evidence', data.evidence_count ?? 0);
    setText('metric-analyses', data.saved_analyses_count ?? 0);

    setText(
      'metric-vault',
      data.vault_usage_display ||
        formatBytes(data.vault_usage_bytes)
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
        {
          key: 'created_at',
          value: row => formatDate(row.created_at)
        },
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
          value: row => row.sha256
            ? `${String(row.sha256).slice(0, 20)}…`
            : '—'
        },
        {
          key: 'acquired_at',
          value: row => formatDate(row.acquired_at)
        }
      ],
      'No evidence has been registered yet.'
    );
  }

  // ------------------------------------------------------------
  // EVIDENCE ACQUISITION
  // ------------------------------------------------------------

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

  async function refreshAcquiredEvidence() {
    const caseId = value('acquire-case');
    const rows = await loadEvidence(caseId);

    renderRows(
      'acquired-evidence-body',
      rows,
      [
        { key: 'file_name' },
        { key: 'evidence_id', mono: true },
        {
          key: 'size_bytes',
          value: row => formatBytes(row.size_bytes)
        },
        { key: 'sha256', mono: true },
        {
          key: 'acquired_at',
          value: row => formatDate(row.acquired_at)
        }
      ],
      'No evidence registered in this case yet.'
    );
  }

  async function detectDevices() {
    const container = byId('device-list');
    const button = byId('detect-devices');

    if (container) {
      container.textContent =
        'Detecting mounted removable volumes…';
    }

    setBusy(button, true, 'Detecting…');

    try {
      const data = await api('/api/devices');

      state.devices = Array.isArray(data.devices)
        ? data.devices
        : [];

      state.selectedDevice = null;
      renderDevices();
    } catch (error) {
      if (container) {
        container.textContent =
          `Device detection failed: ${error.message}`;
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
    if (controls) {
      controls.hidden = !state.devices.length;
    }

    const acquireButton = byId('acquire-device');
    if (acquireButton) acquireButton.disabled = true;

    if (!state.devices.length) {
      const empty = document.createElement('div');
      empty.className = 'empty-state';

      const title = document.createElement('strong');
      title.textContent =
        'No mounted removable volumes detected';

      const detail = document.createElement('p');
      detail.textContent =
        'You can acquire individual files using the upload panel.';

      empty.append(title, detail);
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
        `${mountpoint || 'No mount point'} · ` +
        `${formatBytes(device.size_bytes ?? device.size)} · ` +
        `${device.filesystem || device.fstype || 'Filesystem unknown'}`;

      const detail = document.createElement('small');
      detail.textContent =
        `Removable: ${cellText(device.removable ?? 'Not reported')} · ` +
        `Type: ${cellText(device.transport || device.type || 'Not reported')}`;

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
          actor: actorFrom(
            'acquire-investigator',
            'investigator-name'
          )
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

        resolve(
          comma >= 0 ? result.slice(comma + 1) : result
        );
      };

      reader.onerror = () => {
        reject(new Error(`Could not read ${file.name}.`));
      };

      reader.readAsDataURL(file);
    });
  }

  function renderUploadList() {
    const files = Array.from(
      byId('evidence-files')?.files || []
    );

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

    const files = Array.from(
      byId('evidence-files')?.files || []
    );

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

      const totalSize = encodedFiles.reduce(
        (total, item) => total + item.data_base64.length,
        0
      );

      if (totalSize > 500 * 1024 * 1024) {
        throw new Error(
          'Selected uploads are too large for the current local API request limit. Upload fewer or smaller files at a time.'
        );
      }

      const result = await api('/api/acquire/upload', {
        method: 'POST',
        body: {
          case_id: caseId,
          actor: actorFrom(
            'acquire-investigator',
            'investigator-name'
          ),
          files: encodedFiles
        }
      });

      let message =
        `Acquisition finished: ${result.successful || 0} succeeded; ` +
        `${result.failed || 0} failed.`;

      const failures = (result.results || [])
        .filter(item => !item.ok)
        .map(item => `${item.file_name}: ${item.error}`);

      if (failures.length) {
        message += ` ${failures.join(' | ')}`;
      }

      showMessage(
        'upload-message',
        message,
        result.failed ? 'error' : 'success'
      );

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

  // ------------------------------------------------------------
  // ANALYSIS
  // ------------------------------------------------------------

  function parseAnalysisObject(value) {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      return value;
    }

    if (typeof value === 'string' && value.trim()) {
      try {
        const parsed = JSON.parse(value);
        return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
          ? parsed
          : {};
      } catch (error) {
        console.warn('DataLens: could not parse saved analysis JSON.', error);
      }
    }

    return {};
  }

  function firstAnalysisValue(...values) {
    for (const candidate of values) {
      if (
        candidate !== undefined &&
        candidate !== null &&
        candidate !== ''
      ) {
        return candidate;
      }
    }

    return 'Not available';
  }

  function analysisConfidence(value) {
    if (
      value === undefined ||
      value === null ||
      value === '' ||
      value === 'Not available' ||
      value === '—'
    ) {
      return 'N/A';
    }

    if (typeof value === 'number' && Number.isFinite(value)) {
      // Experimental vote fraction, not a calibrated malware probability.
      return value >= 0 && value <= 1
        ? `${(value * 100).toFixed(1)}%`
        : `${value}`;
    }

    return String(value);
  }

  function normalizeAnalysisRecord(result, evidenceById = new Map()) {
    const record = parseAnalysisObject(result);

    const findings = parseAnalysisObject(
      record.findings ??
      record.findings_json ??
      record.findingsJson ??
      record.analysis_findings ??
      record.analysis_result ??
      record.result
    );

    // Support older records that wrap the findings one level deeper.
    const effectiveFindings =
      Object.keys(findings).length === 1 &&
      findings.findings &&
      typeof findings.findings === 'object'
        ? parseAnalysisObject(findings.findings)
        : findings;

    const models = parseAnalysisObject(
      effectiveFindings.ai_models ??
      record.ai_models ??
      record.models
    );

    const randomForest = parseAnalysisObject(
      models.random_forest ??
      models.randomForest ??
      effectiveFindings.random_forest
    );

    const isolationForest = parseAnalysisObject(
      models.isolation_forest ??
      models.isolationForest ??
      effectiveFindings.isolation_forest
    );

    const evidenceId = firstAnalysisValue(
      record.evidence_id,
      record['Evidence ID'],
      record.evidenceId,
      record.id
    );

    const evidenceRecord =
      evidenceById.get(evidenceId) ||
      evidenceById.get(String(evidenceId)) ||
      {};

    const fileName = firstAnalysisValue(
      evidenceRecord.file_name,
      evidenceRecord.filename,
      evidenceRecord.original_name,
      evidenceRecord.relative_name,
      record.file_name,
      record.filename,
      record.file,
      record.File,
      record['File name']
    );

    const severity = firstAnalysisValue(
      effectiveFindings.severity,
      effectiveFindings.risk_level,
      effectiveFindings.rule_severity,
      record.severity,
      record.risk_level,
      record['Rule severity'],
      record.rule_severity,
      record.severity,
      record.risk_level
    );

    const riskScore = firstAnalysisValue(
      effectiveFindings.risk_score,
      effectiveFindings.rule_risk_score,
      record.risk_score,
      record.rule_risk_score,
      record['Rule risk score'],
      record['Risk score'],
      record.risk_score
    );

    const prediction = firstAnalysisValue(
      randomForest.prediction,
      effectiveFindings.random_forest_prediction,
      effectiveFindings.prediction,
      record['Random Forest'],
      record.random_forest_prediction,
      record.prediction,
      record.ml_prediction
    );

    const confidence = analysisConfidence(firstAnalysisValue(
      randomForest.confidence,
      effectiveFindings.confidence,
      record['RF confidence'],
      record.confidence,
      record.model_confidence
    ));

    const anomaly = firstAnalysisValue(
      isolationForest.result,
      effectiveFindings.anomaly_result,
      effectiveFindings.anomaly,
      record['Isolation Forest'],
      record.anomaly_result,
      record.anomaly,
      record.anomaly_detected
    );

    const anomalyScore = firstAnalysisValue(
      isolationForest.decision_score,
      effectiveFindings.anomaly_score,
      record['Isolation score'],
      record.anomaly_score
    );

    const analyzedAt = firstAnalysisValue(
      record.analyzed_at,
      record.created_at,
      record.timestamp
    );

    return {
      ...record,
      evidence_id:
        evidenceId === 'Not available' ? '' : evidenceId,
      file_name:
        fileName === 'Not available'
          ? (evidenceId === 'Not available'
            ? 'Unknown file'
            : `Evidence ${evidenceId}`)
          : fileName,
      severity,
      risk_level: severity,
      risk_score: riskScore,
      random_forest_prediction: prediction,
      confidence,
      anomaly_result: anomaly,
      anomaly_score: anomalyScore,
      risk_factors: Array.isArray(effectiveFindings.risk_factors)
        ? effectiveFindings.risk_factors
        : (Array.isArray(record.risk_factors) ? record.risk_factors : []),
      analysis_method: firstAnalysisValue(
        effectiveFindings.analysis_method,
        record.analysis_method
      ),
      analysis_status: firstAnalysisValue(
        effectiveFindings.analysis_status,
        record.analysis_status,
        'UNKNOWN'
      ),
      detected_format: firstAnalysisValue(
        effectiveFindings.detected_format,
        record.detected_format,
        'UNKNOWN'
      ),
      analyzed_at:
        analyzedAt === 'Not available'
          ? new Date().toISOString()
          : analyzedAt,
      raw_findings: effectiveFindings
    };
  }

  function renderAnalysisResults(rows) {
    const body = byId('analysis-results-body');
    if (!body) return;

    body.replaceChildren();

    if (!Array.isArray(rows) || !rows.length) {
      const row = document.createElement('tr');
      const cell = document.createElement('td');

      cell.colSpan = 7;
      cell.className = 'empty-cell';
      cell.textContent =
        'No saved analysis results are available for this case yet.';

      row.appendChild(cell);
      body.appendChild(row);
      return;
    }

    rows.forEach(item => {
      const row = document.createElement('tr');

      const status = String(item.analysis_status || 'UNKNOWN');
      const risk = String(
        item.risk_level ??
        item.severity ??
        item.rule_severity ??
        'Not available'
      );
      const scoreAvailable =
        item.risk_score !== null &&
        item.risk_score !== undefined &&
        item.risk_score !== '' &&
        Number.isFinite(Number(item.risk_score));

      const prediction = firstAnalysisValue(
        item.random_forest_prediction,
        item.prediction,
        item.ml_prediction
      );

      const confidence = firstAnalysisValue(
        item.confidence,
        item.model_confidence
      );

      const anomaly = firstAnalysisValue(
        item.anomaly_result,
        item.anomaly,
        item.anomaly_detected
      );

      const values = [
        `${item.file_name || item.evidence_id || 'Unknown file'} · ${item.detected_format || 'UNKNOWN'} · ${status}`,
        risk,
        scoreAvailable
          ? `${Math.max(0, Math.min(100, Number(item.risk_score)))}/100`
          : 'Not available',
        prediction,
        confidence,
        anomaly,
        formatDate(item.analyzed_at || item.created_at)
      ];

      values.forEach((entry, index) => {
        const cell = makeCell(entry, {
          mono: index === 0
        });

        if (index === 2) {
          const scoreValue = Number(item.risk_score);
          if (scoreAvailable && scoreValue >= 70) {
            cell.classList.add('text-danger');
          } else if (scoreAvailable && scoreValue >= 40) {
            cell.classList.add('text-warning');
          } else if (scoreAvailable && scoreValue >= 20) {
            cell.classList.add('text-warning');
          } else if (scoreAvailable) {
            cell.classList.add('text-success');
          }
        }

        if (index === 1) {
          const normalized = risk.toLowerCase();

          if (
            normalized.includes('high') ||
            normalized.includes('critical')
          ) {
            cell.classList.add('text-danger');
          } else if (
            normalized.includes('low') ||
            normalized.includes('no indicator')
          ) {
            cell.classList.add('text-success');
          }
        }

        if (index === 5) {
          const normalized = String(anomaly).toLowerCase();

          if (
            normalized === 'true' ||
            normalized.includes('detected') ||
            normalized === 'anomaly'
          ) {
            cell.classList.add('text-danger');
          } else if (
            normalized === 'false' ||
            normalized.includes('not flagged') ||
            normalized.includes('normal') ||
            normalized.includes('clean')
          ) {
            cell.classList.add('text-success');
          }
        }

        row.appendChild(cell);
      });

      row.classList.add('clickable-row');
      row.tabIndex = 0;

      row.addEventListener('click', () => {
        const detail = byId('analysis-detail');
        const pre = byId('analysis-detail-json');

        if (detail) detail.hidden = false;

        if (pre) {
          const details = item.raw_findings || item;
          pre.textContent = JSON.stringify({
            file_name: item.file_name,
            detected_format: item.detected_format,
            analysis_status: status,
            risk_score: scoreAvailable ? Number(item.risk_score) : null,
            severity: risk,
            risk_factors: item.risk_factors || [],
            findings: details.findings || [],
            integrity: details.integrity || 'UNKNOWN',
            analysis_method: item.analysis_method,
            ai_models: details.ai_models || {},
            interpretation: details.interpretation || ''
          }, null, 2);
        }
      });

      body.appendChild(row);
    });
  }

  function updateAnalysisMetrics(evidenceCount, savedCount, resultCount) {
    setText('analysis-evidence-count', evidenceCount);
    setText('analysis-saved-count', savedCount);
    setText('analysis-result-count', resultCount);

    const csvButton = byId('export-analysis-csv');
    const jsonButton = byId('export-analysis-json');

    if (csvButton) csvButton.disabled = resultCount === 0;
    if (jsonButton) jsonButton.disabled = resultCount === 0;
  }

  async function loadAnalysis() {
    const caseId = value('analysis-case');

    if (!caseId) {
      state.analysisRows = [];
      state.analysisCase = '';

      renderAnalysisResults([]);
      updateAnalysisMetrics(0, 0, 0);

      return;
    }

    try {
      // Load saved analysis first. Evidence metadata is supplementary.
      const analysisData = await api(
        `/api/analysis?case_id=${encodeURIComponent(caseId)}`
      );

      let evidence = [];

      try {
        evidence = await loadEvidence(caseId);
      } catch (evidenceError) {
        console.warn(
          'DataLens: evidence metadata could not be loaded for analysis labels.',
          evidenceError
        );
      }

      const evidenceById = new Map();

      (Array.isArray(evidence) ? evidence : []).forEach(item => {
        const id = item.evidence_id ?? item.id;

        if (id !== undefined && id !== null) {
          evidenceById.set(id, item);
          evidenceById.set(String(id), item);
        }
      });

      const savedResults = Array.isArray(analysisData.results)
        ? analysisData.results
        : Array.isArray(analysisData.analyses)
          ? analysisData.analyses
          : [];

      // API returns newest saved rows first. Keep the newest per evidence ID.
      const latestByEvidence = new Map();

      savedResults.forEach(result => {
        const normalized = normalizeAnalysisRecord(
          result,
          evidenceById
        );

        const id =
          normalized.evidence_id ||
          normalized.analysis_id;

        if (id && !latestByEvidence.has(id)) {
          latestByEvidence.set(id, normalized);
        }
      });

      state.analysisRows = Array.from(latestByEvidence.values());
      state.analysisCase = caseId;

      renderAnalysisResults(state.analysisRows);

      updateAnalysisMetrics(
        evidence.length,
        savedResults.length,
        state.analysisRows.length
      );

      const detail = byId('analysis-detail');
      if (detail) detail.hidden = true;

      const csvButton = byId('export-analysis-csv');
      const jsonButton = byId('export-analysis-json');

      if (csvButton) csvButton.disabled = !state.analysisRows.length;
      if (jsonButton) jsonButton.disabled = !state.analysisRows.length;

      clearMessage('analysis-message');

      if (savedResults.length && !state.analysisRows.length) {
        showMessage(
          'analysis-message',
          'The server returned saved analysis records, but none contained an evidence or analysis ID that could be displayed.',
          'error'
        );
      } else if (
        state.analysisRows.length &&
        state.analysisRows.every(row =>
          row.risk_score === 'Not available' &&
          row.severity === 'Not available' &&
          row.random_forest_prediction === 'Not available'
        )
      ) {
        showMessage(
          'analysis-message',
          'Analysis records were found, but the saved findings contain no risk or model fields. The backend analysis output needs checking.',
          'error'
        );
      }
    } catch (error) {
      state.analysisRows = [];

      renderAnalysisResults([]);
      updateAnalysisMetrics(0, 0, 0);

      showMessage(
        'analysis-message',
        `Could not load saved analysis results: ${error.message}`,
        'error'
      );

      throw error;
    }
  }

  async function runAnalysis() {
    const caseId = value('analysis-case');

    if (!caseId) {
      showMessage(
        'analysis-message',
        'Select a case first.',
        'error'
      );
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
          actor: actorFrom(
            'analysis-investigator',
            'investigator-name'
          )
        }
      });

      const analysis = parseAnalysisObject(
        result.analysis ?? result
      );

      const immediateResults = Array.isArray(analysis.results)
        ? analysis.results
        : [];

      // Use the direct analysis response immediately.
      if (immediateResults.length) {
        let evidence = [];

        try {
          evidence = await loadEvidence(caseId);
        } catch (evidenceError) {
          console.warn(
            'DataLens: could not refresh evidence names after analysis.',
            evidenceError
          );
        }

        const evidenceById = new Map();

        evidence.forEach(item => {
          const id = item.evidence_id ?? item.id;

          if (id !== undefined && id !== null) {
            evidenceById.set(id, item);
            evidenceById.set(String(id), item);
          }
        });

        state.analysisRows = immediateResults.map(item =>
          normalizeAnalysisRecord(item, evidenceById)
        );

        state.analysisCase = caseId;

        renderAnalysisResults(state.analysisRows);

        updateAnalysisMetrics(
          analysis.total_evidence ?? evidence.length,
          analysis.analyzed ?? immediateResults.length,
          state.analysisRows.length
        );
      }

      const skipped = Array.isArray(analysis.skipped)
        ? analysis.skipped
        : [];

      const analyzedCount = Number(
        analysis.analyzed ?? immediateResults.length
      );

      const message =
        `Analysis completed for ${analyzedCount} evidence item(s).` +
        (skipped.length
          ? ` ${skipped.length} item(s) were skipped; review the server response and evidence files.`
          : '') +
        ' Results are experimental triage indicators, not a definitive malware verdict.';

      showMessage(
        'analysis-message',
        message,
        skipped.length ? 'error' : 'success'
      );

      // Refresh from saved records. If those records are incomplete,
      // keep the valid direct results returned by the POST request.
      const directRows = state.analysisRows.slice();

      try {
        await loadAnalysis();

        const persistedHasFindings = state.analysisRows.some(row =>
          row.risk_score !== 'Not available' ||
          row.severity !== 'Not available' ||
          row.random_forest_prediction !== 'Not available' ||
          row.anomaly_result !== 'Not available'
        );

        if (
          directRows.length &&
          (!state.analysisRows.length || !persistedHasFindings)
        ) {
          state.analysisRows = directRows;
          state.analysisCase = caseId;

          renderAnalysisResults(state.analysisRows);

          updateAnalysisMetrics(
            analysis.total_evidence ?? directRows.length,
            analysis.analyzed ?? directRows.length,
            directRows.length
          );

          showMessage(
            'analysis-message',
            'Analysis ran successfully. Displaying the direct analysis response because the saved-results endpoint returned incomplete finding fields.',
            'success'
          );
        }
      } catch (refreshError) {
        if (directRows.length) {
          state.analysisRows = directRows;
          state.analysisCase = caseId;

          renderAnalysisResults(state.analysisRows);
        }

        console.warn(
          'DataLens: saved results could not be refreshed after analysis.',
          refreshError
        );
      }

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

    const timestamp = new Date()
      .toISOString()
      .replace(/[:.]/g, '-');

    const caseId = state.analysisCase || 'case';

    let content;
    let mimeType;
    let extension;

    if (format === 'json') {
      content = JSON.stringify(rows, null, 2);
      mimeType = 'application/json;charset=utf-8';
      extension = 'json';
    } else {
      const columns = Array.from(
        new Set(rows.flatMap(row => Object.keys(row)))
      );

      const escapeCSV = input => {
        const text = input === null || input === undefined
          ? ''
          : typeof input === 'object'
            ? JSON.stringify(input)
            : String(input);

        return `"${text.replace(/"/g, '""')}"`;
      };

      content = [
        columns.map(escapeCSV).join(','),
        ...rows.map(row =>
          columns.map(column => escapeCSV(row[column])).join(',')
        )
      ].join('\r\n');

      mimeType = 'text/csv;charset=utf-8';
      extension = 'csv';
    }

    const blob = new Blob([content], { type: mimeType });
    const url = URL.createObjectURL(blob);

    const link = document.createElement('a');
    link.href = url;
    link.download =
      `datalens-analysis-${caseId}-${timestamp}.${extension}`;

    document.body.appendChild(link);
    link.click();
    link.remove();

    window.setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  // ------------------------------------------------------------
  // CHAIN OF CUSTODY AND VERIFICATION
  // ------------------------------------------------------------

  async function loadCustody() {
    const caseId = value('custody-case');

    const evidenceSelect = byId('verify-evidence');
    const reportSelect = byId('report-evidence');

    if (!caseId) {
      setText('custody-evidence-count', '0');
      setText('custody-events-count', '0');
      setText('custody-chain-status', '—');

      renderRows(
        'custody-evidence-body',
        [],
        [
          { key: 'file_name' },
          { key: 'evidence_id' },
          { key: 'sha256' },
          { key: 'acquired_at' },
          { key: 'status' }
        ],
        'Select a case to view evidence.'
      );

      renderRows(
        'custody-events-body',
        [],
        [
          { key: 'timestamp' },
          { key: 'actor' },
          { key: 'action' },
          { key: 'evidence_id' },
          { key: 'details' }
        ],
        'Select a case to view custody history.'
      );

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

    const data = await api(
      `/api/custody?case_id=${encodeURIComponent(caseId)}`
    );

    const evidence = Array.isArray(data.evidence)
      ? data.evidence
      : [];

    const events = Array.isArray(data.events)
      ? data.events
      : Array.isArray(data.records)
        ? data.records
        : [];

    const integrity =
      data.integrity && typeof data.integrity === 'object'
        ? data.integrity
        : {};

    setText('custody-evidence-count', evidence.length);
    setText('custody-events-count', events.length);

    setText(
      'custody-chain-status',
      integrity.valid === true
        ? 'VALID'
        : integrity.valid === false
          ? 'CHECK FAILED'
          : 'UNKNOWN'
    );

    renderRows(
      'custody-evidence-body',
      evidence,
      [
        { key: 'file_name' },
        { key: 'evidence_id', mono: true },
        { key: 'sha256', mono: true },
        {
          key: 'acquired_at',
          value: row => formatDate(row.acquired_at)
        },
        { key: 'status' }
      ],
      'No evidence is registered in this case.'
    );

    renderRows(
      'custody-events-body',
      events,
      [
        {
          key: 'timestamp',
          value: row => formatDate(row.timestamp)
        },
        { key: 'actor' },
        { key: 'action' },
        { key: 'evidence_id', mono: true },
        {
          key: 'details',
          value: row => {
            const details = row.details ?? row.details_json ?? '';
            if (details && typeof details === 'object') {
              return JSON.stringify(details, null, 2);
            }
            if (typeof details === 'string') {
              try {
                return JSON.stringify(JSON.parse(details), null, 2);
              } catch (_) {
                return details;
              }
            }
            return details;
          }
        }
      ],
      'No custody events are recorded for this case.'
    );

    [evidenceSelect, reportSelect].forEach(select => {
      if (!select) return;

      const previous = select.value;
      select.replaceChildren();

      const placeholder = document.createElement('option');
      placeholder.value = '';
      placeholder.textContent = evidence.length
        ? 'Select evidence…'
        : 'No evidence in this case';

      select.appendChild(placeholder);

      evidence.forEach(item => {
        const option = document.createElement('option');

        option.value = item.evidence_id || '';
        option.textContent =
          `${item.file_name || 'Evidence file'} · ${item.evidence_id || ''}`;

        select.appendChild(option);
      });

      select.value = evidence.some(
        item => item.evidence_id === previous
      )
        ? previous
        : '';
    });

    clearMessage('verify-message');
    clearMessage('report-message');
  }

  async function verifyEvidence() {
    const evidenceId = value('verify-evidence');

    if (!evidenceId) {
      showMessage(
        'verify-message',
        'Select an evidence item first.',
        'error'
      );
      return;
    }

    const button = byId('verify-evidence-button');

    setBusy(button, true, 'Verifying…');
    clearMessage('verify-message');

    try {
      const result = await api('/api/verify', {
        method: 'POST',
        body: {
          evidence_id: evidenceId,
          actor: actorFrom(
            'custody-investigator',
            'investigator-name'
          )
        }
      });

      const outcome =
        result.outcome && typeof result.outcome === 'object'
          ? result.outcome
          : result;

      const status = String(
        outcome.status || result.status || ''
      ).toUpperCase();

      const verified =
        result.verified === true ||
        result.valid === true ||
        result.integrity_ok === true;

      const message =
        outcome.message ||
        result.message ||
        (
          verified
            ? 'Evidence verification passed.'
            : `Verification result: ${status || 'NOT VERIFIED'}. Review the result.`
        );

      showMessage(
        'verify-message',
        message,
        verified ? 'success' : 'error'
      );

      await loadCustody();
    } catch (error) {
      showMessage('verify-message', error.message, 'error');
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
          actor: actorFrom(
            'custody-investigator',
            'investigator-name'
          )
        }
      });

      const verified =
        result.verified === true ||
        result.valid === true ||
        result.integrity_ok === true;

      showMessage(
        'custody-verification-message',
        result.message ||
          (
            verified
              ? 'Custody verification passed.'
              : 'Custody verification did not pass. Review the returned result.'
          ),
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

  // ------------------------------------------------------------
  // REPORTS
  // ------------------------------------------------------------

  async function generateCaseReport() {
    const caseId = value('custody-case');

    if (!caseId) {
      showMessage(
        'report-message',
        'Select a case first.',
        'error'
      );
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
          actor: actorFrom(
            'custody-investigator',
            'investigator-name'
          )
        }
      });

      showMessage(
        'report-message',
        result.message ||
          `Case report generated: ${result.filename || 'PDF report'}.`,
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
          actor: actorFrom(
            'custody-investigator',
            'investigator-name'
          )
        }
      });

      showMessage(
        'report-message',
        result.message ||
          `Evidence report generated: ${result.filename || 'PDF report'}.`,
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

  // ------------------------------------------------------------
  // FILE RECOVERY
  // ------------------------------------------------------------

  function renderRecoveryCandidates(candidates) {
    renderRows(
      'recovery-candidates-body',
      candidates,
      [
        {
          key: 'file_name',
          value: row =>
            row.file_name ||
            row.name ||
            row.candidate_id ||
            'Recovered candidate'
        },
        {
          key: 'file_type',
          value: row => row.file_type || row.type || 'Unknown'
        },
        {
          key: 'size_bytes',
          value: row => formatBytes(
            row.size_bytes ?? row.size
          )
        },
        {
          key: 'status',
          value: row => row.status || 'Found'
        },
        {
          key: 'candidate_id',
          value: row =>
            row.candidate_id ||
            row.recovery_id ||
            row.id ||
            '—'
        }
      ],
      'No recovery candidates found. Select an image and run a scan.'
    );
  }

  function clearRecoveryForNewCase() {
    state.recoveryCandidates = [];
    state.recoverySource = '';
    renderRecoveryCandidates([]);
  }

  async function scanRecovery() {
    const caseId = value('recovery-case');
    const file = byId('recovery-image')?.files?.[0];

    if (!caseId) {
      showMessage(
        'recovery-message',
        'Select a case first.',
        'error'
      );
      return;
    }

    if (!file) {
      showMessage(
        'recovery-message',
        'Choose a disk image or source file before starting the recovery scan.',
        'error'
      );
      return;
    }

    const button = byId('scan-recovery');

    setBusy(button, true, 'Scanning…');
    clearMessage('recovery-message');

    try {
      const dataBase64 = await fileToBase64(file);

      const result = await api('/api/recovery/scan', {
        method: 'POST',
        body: {
          case_id: caseId,
          name: file.name,
          data_base64: dataBase64,
          actor: actorFrom(
            'recovery-investigator',
            'investigator-name'
          )
        }
      });

      state.recoveryCandidates = Array.isArray(result.candidates)
        ? result.candidates
        : [];

      state.recoverySource = result.source_path || '';

      renderRecoveryCandidates(state.recoveryCandidates);

      showMessage(
        'recovery-message',
        result.message ||
          `Recovery scan completed. ${state.recoveryCandidates.length} candidate(s) found.`,
        'success'
      );

      await loadDashboard();
    } catch (error) {
      showMessage(
        'recovery-message',
        error.message,
        'error'
      );
    } finally {
      setBusy(button, false);
    }
  }

  async function registerRecovery() {
    const caseId = value('recovery-case');

    if (!caseId) {
      showMessage(
        'recovery-message',
        'Select a case first.',
        'error'
      );
      return;
    }

    if (!state.recoveryCandidates.length) {
      showMessage(
        'recovery-message',
        'Run a recovery scan before registering candidates.',
        'error'
      );
      return;
    }

    const button = byId('register-recovery');

    setBusy(button, true, 'Registering…');

    try {
      const result = await api('/api/recovery/register', {
        method: 'POST',
        body: {
          case_id: caseId,
          source_path: state.recoverySource,
          candidates: state.recoveryCandidates,
          actor: actorFrom(
            'recovery-investigator',
            'investigator-name'
          )
        }
      });

      showMessage(
        'recovery-message',
        result.message ||
          `Recovery registration completed: ${result.registered ?? result.successful ?? 0} item(s).`,
        'success'
      );

      state.recoveryCandidates = [];
      state.recoverySource = '';

      renderRecoveryCandidates([]);

      await refreshAcquiredEvidence();
      await loadDashboard();
    } catch (error) {
      showMessage(
        'recovery-message',
        error.message,
        'error'
      );
    } finally {
      setBusy(button, false);
    }
  }

  // ------------------------------------------------------------
  // SYSTEM CHECKS AND DEVICES
  // ------------------------------------------------------------

  async function loadSystemChecks() {
    const button = byId('run-system-checks');
    const container = byId('system-checks-list');

    setBusy(button, true, 'Checking…');

    if (container) {
      container.textContent = 'Running system checks…';
    }

    try {
      const result = await api('/api/system-checks');

      const checks = Array.isArray(result.checks)
        ? result.checks
        : [];

      if (container) {
        container.replaceChildren();

        if (!checks.length) {
          container.textContent =
            'No system check results are available.';
        } else {
          checks.forEach(check => {
            const item = document.createElement('div');
            item.className = 'system-check-item';

            const title = document.createElement('strong');
            title.textContent =
              check.Check ||
              check.check ||
              check.name ||
              'System check';

            const status = document.createElement('span');
            status.textContent =
              check.Status ||
              check.status ||
              check.Result ||
              check.result ||
              'Unknown';

            const detail = document.createElement('small');
            detail.textContent =
              check.Details ||
              check.details ||
              check.message ||
              '';

            item.append(title, status, detail);
            container.appendChild(item);
          });
        }
      }

      renderRows(
        'system-checks-body',
        checks,
        [
          {
            key: 'check',
            value: row =>
              row.Check || row.check || row.name || '—'
          },
          {
            key: 'result',
            value: row =>
              row.Status ||
              row.status ||
              row.Result ||
              row.result ||
              '—'
          },
          {
            key: 'details',
            value: row =>
              row.Details ||
              row.details ||
              row.message ||
              ''
          }
        ],
        'No system-check results are available.'
      );

      showMessage(
        'system-message',
        `${checks.length} system check(s) completed.`,
        'success'
      );
    } catch (error) {
      if (container) {
        container.textContent =
          `System checks failed: ${error.message}`;
      }

      showMessage('system-message', error.message, 'error');
    } finally {
      setBusy(button, false);
    }
  }

  async function refreshSystemDevices() {
    const body = byId('system-devices-body');

    try {
      const data = await api('/api/devices');

      const devices = Array.isArray(data.devices)
        ? data.devices
        : [];

      state.devices = devices;

      setText('system-device-count', devices.length);

      renderRows(
        'system-devices-body',
        devices,
        [
          {
            key: 'name',
            value: row =>
              row.name || row.model || row.device || 'Unknown'
          },
          {
            key: 'mountpoint',
            value: row =>
              row.mountpoint ||
              row.mount_point ||
              row.path ||
              row.drive_letter ||
              '—'
          },
          {
            key: 'filesystem',
            value: row =>
              row.filesystem || row.fstype || 'Unknown'
          },
          {
            key: 'size_bytes',
            value: row =>
              formatBytes(row.size_bytes ?? row.size)
          }
        ],
        'No devices detected.'
      );

      return devices;
    } catch (error) {
      setText('system-device-count', 'Unavailable');

      if (body) {
        renderRows(
          'system-devices-body',
          [],
          [
            { key: 'name' },
            { key: 'mountpoint' },
            { key: 'filesystem' },
            { key: 'size_bytes' }
          ],
          `Could not load devices: ${error.message}`
        );
      }

      showMessage('system-message', error.message, 'error');
      return [];
    }
  }

  // ------------------------------------------------------------
  // BACKUP
  // ------------------------------------------------------------

  async function createBackup() {
    const button = byId('create-backup');

    setBusy(button, true, 'Creating backup…');
    clearMessage('backup-message');

    try {
      const result = await api('/api/backup', {
        method: 'POST',
        body: {
          actor: actorFrom('investigator-name')
        }
      });

      if (!result.download_url) {
        throw new Error(
          'The server did not return a backup download link.'
        );
      }

      showMessage(
        'backup-message',
        `${result.message || 'Backup created successfully.'} ${result.filename || ''}`,
        'success'
      );

      downloadReport(result.download_url);
    } catch (error) {
      showMessage(
        'backup-message',
        `Backup failed: ${error.message}`,
        'error'
      );
    } finally {
      setBusy(button, false);
    }
  }

  // ------------------------------------------------------------
  // SERVER CONNECTION
  // ------------------------------------------------------------

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
      console.error(
        'DataLens connection check failed:',
        error
      );

      return false;
    }
  }

  // ------------------------------------------------------------
  // EVENT BINDINGS
  // ------------------------------------------------------------

  function bindEvents() {
    // Navigation buttons
    $$('[data-page]').forEach(button => {
      button.addEventListener('click', () => {
        navigate(button.dataset.page);
      });
    });

    // Dashboard shortcuts such as New Case and View Cases
    $$('[data-go-page]').forEach(button => {
      button.addEventListener('click', event => {
        event.preventDefault();
        navigate(button.dataset.goPage);
      });
    });

    // Case creation
    byId('create-case-form')?.addEventListener(
      'submit',
      createCase
    );

    // Case selectors
    [
      'selected-case',
      'acquire-case',
      'analysis-case',
      'custody-case',
      'recovery-case'
    ].forEach(id => {
      byId(id)?.addEventListener('change', () => {
        syncCaseSelection(id);
      });
    });

    // Device detection and acquisition
    byId('detect-devices')?.addEventListener(
      'click',
      detectDevices
    );

    // Support the alternate button ID if used in the HTML.
    byId('inspect-devices')?.addEventListener(
      'click',
      refreshSystemDevices
    );

    byId('acquire-device')?.addEventListener(
      'click',
      acquireDevice
    );

    byId('device-authorized')?.addEventListener(
      'change',
      updateAcquireButton
    );

    // File upload
    byId('evidence-files')?.addEventListener(
      'change',
      renderUploadList
    );

    byId('upload-evidence-form')?.addEventListener(
      'submit',
      uploadEvidence
    );

    // Analysis
    byId('run-analysis')?.addEventListener(
      'click',
      runAnalysis
    );

    byId('refresh-analysis')?.addEventListener(
      'click',
      () => loadAnalysis().catch(error => {
        showMessage('analysis-message', error.message, 'error');
      })
    );

    byId('export-analysis-csv')?.addEventListener(
      'click',
      () => exportAnalysis('csv')
    );

    byId('export-analysis-json')?.addEventListener(
      'click',
      () => exportAnalysis('json')
    );

    // Evidence verification
    byId('verify-evidence-button')?.addEventListener(
      'click',
      verifyEvidence
    );

    byId('verify-custody-button')?.addEventListener(
      'click',
      verifyCustody
    );

    byId('refresh-custody')?.addEventListener(
      'click',
      () => loadCustody().catch(error => {
        showMessage('verify-message', error.message, 'error');
      })
    );

    // Reports
    byId('generate-case-report')?.addEventListener(
      'click',
      generateCaseReport
    );

    byId('generate-evidence-report')?.addEventListener(
      'click',
      generateEvidenceReport
    );

    // Recovery
    byId('scan-recovery')?.addEventListener(
      'click',
      scanRecovery
    );

    byId('register-recovery')?.addEventListener(
      'click',
      registerRecovery
    );

    // System checks
    byId('run-system-checks')?.addEventListener(
      'click',
      loadSystemChecks
    );

    // Backup
    byId('create-backup')?.addEventListener(
      'click',
      createBackup
    );

    // Mobile menu
    const menuButton = byId('mobile-menu-button');
    const sidebar = byId('sidebar');

    function closeMobileMenu() {
      sidebar?.classList.remove('sidebar-open');
      document.body.classList.remove('sidebar-menu-open');

      menuButton?.setAttribute('aria-expanded', 'false');
    }

    menuButton?.addEventListener('click', event => {
      event.preventDefault();

      const open =
        sidebar?.classList.toggle('sidebar-open') || false;

      document.body.classList.toggle(
        'sidebar-menu-open',
        open
      );

      menuButton.setAttribute(
        'aria-expanded',
        String(open)
      );
    });

    document.addEventListener('click', event => {
      if (!sidebar?.classList.contains('sidebar-open')) {
        return;
      }

      if (
        sidebar.contains(event.target) ||
        menuButton?.contains(event.target)
      ) {
        return;
      }

      closeMobileMenu();
    });

    document.addEventListener('keydown', event => {
      if (event.key === 'Escape') {
        closeMobileMenu();
      }
    });
  }

  // ------------------------------------------------------------
  // APPLICATION STARTUP
  // ------------------------------------------------------------

  document.addEventListener('DOMContentLoaded', async () => {
    try {
      bindEvents();

      const savedInvestigator = localStorage.getItem(
        'datalens-investigator'
      );

      const investigatorInput = byId('investigator-name');

      if (investigatorInput && savedInvestigator) {
        investigatorInput.value = savedInvestigator;
      }

      investigatorInput?.addEventListener('change', event => {
        localStorage.setItem(
          'datalens-investigator',
          event.target.value.trim()
        );
      });

      await checkConnection();

      const requestedPage = location.hash.replace('#', '');

      navigate(
        pageNames[requestedPage]
          ? requestedPage
          : 'dashboard',
        false
      );

      await loadCases();
      await loadDashboard();

    } catch (error) {
      console.error('DataLens startup error:', error);
      globalMessage(error.message, 'error');
    }
  });

})();
