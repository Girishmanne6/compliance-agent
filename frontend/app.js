const editor = document.getElementById('code-editor');
const languageSelect = document.getElementById('language');
const loadSampleButton = document.getElementById('load-sample');
const runScanButton = document.getElementById('run-scan');
const runRepoScanButton = document.getElementById('run-repo-scan');
const repoLanguageSelect = document.getElementById('repo-language');
const repoUrlInput = document.getElementById('repo-url');
const tabPaste = document.getElementById('tab-paste');
const tabRepo = document.getElementById('tab-repo');
const pastePane = document.getElementById('paste-pane');
const repoPane = document.getElementById('repo-pane');
const downloadReportButton = document.getElementById('download-report');
const loading = document.getElementById('loading');
const resultsBody = document.getElementById('results-body');
const historyBody = document.getElementById('history-body');
const summaryContent = document.getElementById('summary-content');
const scanMeta = document.getElementById('scan-meta');

const statElements = {
  total: document.getElementById('stat-total'),
  critical: document.getElementById('stat-critical'),
  medium: document.getElementById('stat-medium'),
  low: document.getElementById('stat-low'),
};

let latestReport = null;
let currentMode = 'paste';

function setLoadingState(isLoading) {
  loading.classList.toggle('hidden', !isLoading);
  runScanButton.disabled = isLoading;
  runRepoScanButton.disabled = isLoading;
  loadSampleButton.disabled = isLoading;
  languageSelect.disabled = isLoading;
  repoLanguageSelect.disabled = isLoading;
  repoUrlInput.disabled = isLoading;
  tabPaste.disabled = isLoading;
  tabRepo.disabled = isLoading;
}

function animateCount(element, targetValue) {
  const startValue = Number(element.textContent) || 0;
  const startTime = performance.now();
  const duration = 700;

  function tick(now) {
    const progress = Math.min((now - startTime) / duration, 1);
    const nextValue = Math.round(startValue + (targetValue - startValue) * progress);
    element.textContent = String(nextValue);
    if (progress < 1) {
      requestAnimationFrame(tick);
    }
  }

  requestAnimationFrame(tick);
}

function updateStats(report) {
  animateCount(statElements.total, report.total_violations);
  animateCount(statElements.critical, report.critical);
  animateCount(statElements.medium, report.medium);
  animateCount(statElements.low, report.low);
}

function renderViolations(violations) {
  if (!violations.length) {
    resultsBody.innerHTML = '<tr><td colspan="5" class="empty-state">No violations detected.</td></tr>';
    return;
  }

  resultsBody.innerHTML = violations.map((violation) => `
    <tr>
      <td>${violation.rule_id}</td>
      <td><span class="badge ${violation.severity}">${violation.severity}</span></td>
      <td>${violation.message}</td>
      <td>${violation.file_path || '-'}</td>
      <td>${violation.line_number}</td>
    </tr>
  `).join('');
}

function switchMode(mode) {
  currentMode = mode;
  const isPaste = mode === 'paste';
  tabPaste.classList.toggle('active', isPaste);
  tabRepo.classList.toggle('active', !isPaste);
  pastePane.classList.toggle('hidden', !isPaste);
  repoPane.classList.toggle('hidden', isPaste);
}

function parseInlineMarkdown(text) {
  return text
    .replace(/`([^`]+)`/g, '<code>$1</code>')
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
}

function renderMarkdown(markdownText) {
  const lines = markdownText.split(/\r?\n/);
  let html = '';
  let listType = null;

  const closeList = () => {
    if (listType) {
      html += `</${listType}>`;
      listType = null;
    }
  };

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) {
      closeList();
      continue;
    }

    if (trimmed.startsWith('### ')) {
      closeList();
      html += `<h3>${parseInlineMarkdown(trimmed.slice(4))}</h3>`;
      continue;
    }

    if (trimmed.startsWith('## ')) {
      closeList();
      html += `<h2>${parseInlineMarkdown(trimmed.slice(3))}</h2>`;
      continue;
    }

    if (trimmed.startsWith('# ')) {
      closeList();
      html += `<h1>${parseInlineMarkdown(trimmed.slice(2))}</h1>`;
      continue;
    }

    if (trimmed.startsWith('- ')) {
      if (listType !== 'ul') {
        closeList();
        html += '<ul>';
        listType = 'ul';
      }
      html += `<li>${parseInlineMarkdown(trimmed.slice(2))}</li>`;
      continue;
    }

    if (/^\d+\.\s/.test(trimmed)) {
      if (listType !== 'ol') {
        closeList();
        html += '<ol>';
        listType = 'ol';
      }
      html += `<li>${parseInlineMarkdown(trimmed.replace(/^\d+\.\s/, ''))}</li>`;
      continue;
    }

    closeList();
    html += `<p>${parseInlineMarkdown(trimmed)}</p>`;
  }

  closeList();
  return html || '<p>No summary available.</p>';
}

async function loadSample() {
  const language = languageSelect.value;
  const sampleMap = {
    python: '/sample_code/vulnerable.py',
    terraform: '/sample_code/infra.tf',
    javascript: '/sample_code/vulnerable.py',
  };

  const response = await fetch(sampleMap[language] || sampleMap.python);
  if (!response.ok) {
    throw new Error('Sample file could not be loaded.');
  }
  editor.value = await response.text();
}

async function runScan() {
  if (!editor.value.trim()) {
    window.alert('Add code to scan first.');
    return;
  }

  setLoadingState(true);
  try {
    const response = await fetch('/scan', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        code: editor.value,
        language: languageSelect.value,
      }),
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.detail || 'Scan failed.');
    }

    applyReport(data);
    await loadHistory();
  } catch (error) {
    renderViolations([]);
    summaryContent.innerHTML = `<p>${error.message}</p>`;
    scanMeta.textContent = 'Scan failed';
  } finally {
    setLoadingState(false);
  }
}

async function runRepoScan() {
  const repoUrl = repoUrlInput.value.trim();
  if (!repoUrl) {
    window.alert('Enter a GitHub repo URL first.');
    return;
  }

  setLoadingState(true);
  try {
    const response = await fetch('/scan-repo', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        repo_url: repoUrl,
        language: repoLanguageSelect.value,
      }),
    });

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.detail || 'Repo scan failed.');
    }

    applyReport(data);
    await loadHistory();
  } catch (error) {
    renderViolations([]);
    summaryContent.innerHTML = `<p>${error.message}</p>`;
    scanMeta.textContent = 'Scan failed';
  } finally {
    setLoadingState(false);
  }
}

function applyReport(report) {
  latestReport = report;
  updateStats(report);
  renderViolations(report.violations || []);
  summaryContent.innerHTML = renderMarkdown(report.ai_summary || 'No summary available.');
  scanMeta.textContent = `Report ${report.report_id} • ${report.scan_type || 'paste'} • ${report.source || 'pasted-code'} • ${report.scan_duration_ms} ms`;
  downloadReportButton.disabled = false;
}

function formatTimestamp(value) {
  if (!value) {
    return '-';
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return value;
  }
  return date.toLocaleString();
}

function severityRowClass(item) {
  if (item.critical > 0) {
    return 'history-critical';
  }
  if (item.medium > 0) {
    return 'history-medium';
  }
  return 'history-low';
}

function renderHistory(items) {
  if (!items.length) {
    historyBody.innerHTML = '<tr><td colspan="7" class="empty-state">No scans yet</td></tr>';
    return;
  }

  historyBody.innerHTML = items.map((item) => `
    <tr class="${severityRowClass(item)}">
      <td>${formatTimestamp(item.timestamp)}</td>
      <td>${item.source}</td>
      <td>${item.total_violations}</td>
      <td>${item.critical}</td>
      <td>${item.medium}</td>
      <td>${item.low}</td>
      <td><button class="view-report" data-report-id="${item.report_id}">View</button></td>
    </tr>
  `).join('');
}

async function loadHistory() {
  try {
    const response = await fetch('/history');
    if (!response.ok) {
      throw new Error('History could not be loaded.');
    }
    const data = await response.json();
    renderHistory(Array.isArray(data) ? data : []);
  } catch (error) {
    historyBody.innerHTML = `<tr><td colspan="7" class="empty-state">${error.message}</td></tr>`;
  }
}

async function viewReport(reportId) {
  try {
    const response = await fetch(`/report/${reportId}`);
    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.detail || 'Report could not be loaded.');
    }
    applyReport(data);
  } catch (error) {
    window.alert(error.message);
  }
}

async function downloadReport() {
  if (!latestReport) {
    return;
  }

  const response = await fetch(`/report/${latestReport.report_id}`);
  if (!response.ok) {
    window.alert('Report download failed.');
    return;
  }

  const data = await response.json();
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = `${latestReport.report_id}.json`;
  anchor.click();
  URL.revokeObjectURL(url);
}

loadSampleButton.addEventListener('click', () => {
  loadSample().catch((error) => {
    window.alert(error.message);
  });
});
runScanButton.addEventListener('click', () => {
  runScan().catch((error) => {
    window.alert(error.message);
    setLoadingState(false);
  });
});
runRepoScanButton.addEventListener('click', () => {
  runRepoScan().catch((error) => {
    window.alert(error.message);
    setLoadingState(false);
  });
});
downloadReportButton.addEventListener('click', downloadReport);
tabPaste.addEventListener('click', () => switchMode('paste'));
tabRepo.addEventListener('click', () => switchMode('repo'));
languageSelect.addEventListener('change', () => {
  downloadReportButton.disabled = true;
  latestReport = null;
});
historyBody.addEventListener('click', (event) => {
  const target = event.target;
  if (!(target instanceof HTMLElement)) {
    return;
  }
  if (!target.classList.contains('view-report')) {
    return;
  }
  const reportId = target.dataset.reportId;
  if (reportId) {
    viewReport(reportId).catch(() => {
      window.alert('Report could not be loaded.');
    });
  }
});

loadSample().catch(() => {
  editor.value = '# Load sample failed. Paste code here and run a scan.';
});
loadHistory().catch(() => {
  historyBody.innerHTML = '<tr><td colspan="7" class="empty-state">No scans yet</td></tr>';
});
