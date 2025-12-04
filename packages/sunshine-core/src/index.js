import { Chart, BarController, BarElement, CategoryScale, LinearScale, Legend, Tooltip } from 'chart.js';

Chart.register(BarController, BarElement, CategoryScale, LinearScale, Legend, Tooltip);

const DEFAULT_SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
const DEFAULT_COLORS = {
  critical: '#a10a0a',
  high: '#ff4633',
  medium: '#ff9335',
  low: '#fccd58',
  info: '#7dd491',
  unknown: '#bcbcbc'
};

function injectBaseStyles() {
  if (typeof document === 'undefined') return;
  if (document.getElementById('sunshine-core-styles')) return;
  const style = document.createElement('style');
  style.id = 'sunshine-core-styles';
  style.textContent = `
    .sunshine-card { background: #ffffff; border: 1px solid #e5e7eb; border-radius: 12px; padding: 16px; box-shadow: 0 12px 32px rgba(18,38,63,0.12); }
    .sunshine-header { display: flex; justify-content: space-between; align-items: baseline; margin-bottom: 12px; }
    .sunshine-title { font-size: 1.25rem; font-weight: 600; color: #0f172a; margin: 0; }
    .sunshine-meta { color: #475569; font-size: 0.9rem; margin: 0; }
    .sunshine-table { width: 100%; border-collapse: collapse; font-size: 0.95rem; }
    .sunshine-table thead { background: #f8fafc; text-align: left; }
    .sunshine-table th, .sunshine-table td { padding: 10px 12px; border-bottom: 1px solid #e2e8f0; color: #0f172a; }
    .sunshine-pill { display: inline-block; padding: 4px 10px; border-radius: 9999px; font-size: 0.85rem; color: #0f172a; background: #e2e8f0; text-transform: capitalize; }
    .sunshine-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 12px; }
    .sunshine-stat { background: #f8fafc; border-radius: 10px; padding: 10px 12px; }
    .sunshine-stat label { display: block; color: #475569; font-size: 0.85rem; margin-bottom: 4px; }
    .sunshine-stat strong { color: #0f172a; font-size: 1.1rem; }
    .sunshine-empty { color: #475569; text-align: center; padding: 18px 0; }
    canvas.sunshine-chart { width: 100% !important; height: 320px !important; }
  `;
  document.head.appendChild(style);
}

function normalizeSeverity(value) {
  if (!value) return 'unknown';
  const normalized = String(value).toLowerCase();
  if (['information', 'informational', 'info'].includes(normalized)) return 'info';
  return normalized;
}

function getSeverityFromVulnerability(vulnerability) {
  const rating = (vulnerability.ratings || []).find(r => r.severity);
  return normalizeSeverity(rating?.severity);
}

function summarizeSeverities(vulnerabilities) {
  return vulnerabilities.reduce((acc, vuln) => {
    const severity = getSeverityFromVulnerability(vuln);
    acc[severity] = (acc[severity] || 0) + 1;
    return acc;
  }, {});
}

function buildComponentIndex(components) {
  return (components || []).reduce((acc, component) => {
    if (component['bom-ref']) acc[component['bom-ref']] = component;
    return acc;
  }, {});
}

function createSection(container, title, subtitle) {
  injectBaseStyles();
  container.innerHTML = '';
  const wrapper = document.createElement('div');
  wrapper.className = 'sunshine-card';

  const header = document.createElement('div');
  header.className = 'sunshine-header';
  const h2 = document.createElement('h2');
  h2.className = 'sunshine-title';
  h2.textContent = title;
  const meta = document.createElement('p');
  meta.className = 'sunshine-meta';
  meta.textContent = subtitle || '';
  header.appendChild(h2);
  header.appendChild(meta);
  wrapper.appendChild(header);
  container.appendChild(wrapper);
  return wrapper;
}

function renderSummaryTable(container, bom) {
  const components = bom?.components || [];
  const vulnerabilities = bom?.vulnerabilities || [];
  const severityCounts = summarizeSeverities(vulnerabilities);
  const title = bom?.metadata?.component?.name || 'SBOM summary';
  const subtitle = bom?.metadata?.timestamp ? `Generated ${new Date(bom.metadata.timestamp).toLocaleString()}` : 'CycloneDX JSON overview';
  const section = createSection(container, title, subtitle);

  const stats = document.createElement('div');
  stats.className = 'sunshine-grid';

  const statItems = [
    ['Components', components.length],
    ['Vulnerabilities', vulnerabilities.length],
    ['Direct dependencies', bom?.metadata?.component ? 1 : 0]
  ];
  statItems.forEach(([label, value]) => {
    const card = document.createElement('div');
    card.className = 'sunshine-stat';
    const l = document.createElement('label');
    l.textContent = label;
    const v = document.createElement('strong');
    v.textContent = value;
    card.appendChild(l);
    card.appendChild(v);
    stats.appendChild(card);
  });
  section.appendChild(stats);

  const table = document.createElement('table');
  table.className = 'sunshine-table';
  const thead = document.createElement('thead');
  thead.innerHTML = '<tr><th>Severity</th><th>Count</th></tr>';
  table.appendChild(thead);
  const tbody = document.createElement('tbody');

  const severities = DEFAULT_SEVERITY_ORDER.filter(key => severityCounts[key]).length
    ? DEFAULT_SEVERITY_ORDER
    : Object.keys(severityCounts);

  if (severities.length === 0) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = 2;
    cell.className = 'sunshine-empty';
    cell.textContent = 'No vulnerabilities present in this SBOM.';
    row.appendChild(cell);
    tbody.appendChild(row);
  } else {
    severities.forEach(sev => {
      if (severityCounts[sev] === undefined) return;
      const row = document.createElement('tr');
      const label = document.createElement('td');
      label.innerHTML = `<span class="sunshine-pill" style="background:${DEFAULT_COLORS[sev] || '#e2e8f0'}">${sev}</span>`;
      const value = document.createElement('td');
      value.textContent = severityCounts[sev];
      row.appendChild(label);
      row.appendChild(value);
      tbody.appendChild(row);
    });
  }
  table.appendChild(tbody);
  section.appendChild(table);
}

function renderComponentsChart(container, bom, options = {}) {
  const vulnerabilities = bom?.vulnerabilities || [];
  const severityCounts = summarizeSeverities(vulnerabilities);
  const section = createSection(container, 'Components chart', 'Vulnerability distribution by severity');

  const canvas = document.createElement('canvas');
  canvas.className = 'sunshine-chart';
  section.appendChild(canvas);

  const dataLabels = DEFAULT_SEVERITY_ORDER.filter(sev => severityCounts[sev] !== undefined);
  const chartData = dataLabels.map(label => severityCounts[label]);

  if (container.__sunshineChart) {
    container.__sunshineChart.destroy();
    delete container.__sunshineChart;
  }

  if (dataLabels.length === 0) {
    const empty = document.createElement('p');
    empty.className = 'sunshine-empty';
    empty.textContent = 'No vulnerability data available for chart rendering.';
    section.appendChild(empty);
    return;
  }

  const chart = new Chart(canvas.getContext('2d'), {
    type: 'bar',
    data: {
      labels: dataLabels.map(label => label.toUpperCase()),
      datasets: [
        {
          label: 'Vulnerabilities',
          data: chartData,
          backgroundColor: dataLabels.map(label => DEFAULT_COLORS[label] || '#cbd5e1'),
          borderRadius: 8,
          maxBarThickness: 42
        }
      ]
    },
    options: {
      responsive: true,
      plugins: {
        legend: { display: false },
        tooltip: { callbacks: { label: ctx => `${ctx.formattedValue} vulnerabilities` } }
      },
      scales: {
        x: { grid: { display: false } },
        y: { beginAtZero: true, ticks: { precision: 0 } }
      },
      ...options.chartOptions
    }
  });
  container.__sunshineChart = chart;
}

function renderComponentsTable(container, bom) {
  const components = bom?.components || [];
  const section = createSection(container, 'Components', 'Declared CycloneDX components');
  const table = document.createElement('table');
  table.className = 'sunshine-table';
  const thead = document.createElement('thead');
  thead.innerHTML = '<tr><th>Name</th><th>Version</th><th>PURL</th><th>Supplier</th><th>Scope</th></tr>';
  table.appendChild(thead);
  const tbody = document.createElement('tbody');

  if (!components.length) {
    const row = document.createElement('tr');
    const empty = document.createElement('td');
    empty.colSpan = 5;
    empty.className = 'sunshine-empty';
    empty.textContent = 'No components found in this SBOM.';
    row.appendChild(empty);
    tbody.appendChild(row);
  } else {
    components.forEach(component => {
      const row = document.createElement('tr');
      const fields = [
        component.name || 'Unknown component',
        component.version || '—',
        component.purl || '—',
        component.supplier?.name || '—',
        component.scope || '—'
      ];
      fields.forEach(text => {
        const cell = document.createElement('td');
        cell.textContent = text;
        row.appendChild(cell);
      });
      tbody.appendChild(row);
    });
  }
  table.appendChild(tbody);
  section.appendChild(table);
}

function renderVulnerabilitiesTable(container, bom) {
  const vulnerabilities = bom?.vulnerabilities || [];
  const componentIndex = buildComponentIndex(bom?.components || []);
  const section = createSection(container, 'Vulnerabilities', 'Mapped to affected components');
  const table = document.createElement('table');
  table.className = 'sunshine-table';
  const thead = document.createElement('thead');
  thead.innerHTML = '<tr><th>ID</th><th>Severity</th><th>Description</th><th>Affects</th></tr>';
  table.appendChild(thead);
  const tbody = document.createElement('tbody');

  if (!vulnerabilities.length) {
    const row = document.createElement('tr');
    const empty = document.createElement('td');
    empty.colSpan = 4;
    empty.className = 'sunshine-empty';
    empty.textContent = 'No vulnerabilities reported.';
    row.appendChild(empty);
    tbody.appendChild(row);
  } else {
    vulnerabilities.forEach(vuln => {
      const row = document.createElement('tr');
      const id = vuln.id || vuln.source?.name || 'Unlabeled vulnerability';
      const severity = getSeverityFromVulnerability(vuln);
      const description = vuln.description || '—';
      const affectedRefs = (vuln.affects || []).map(a => a.ref);
      const affectedNames = affectedRefs.map(ref => componentIndex[ref]?.name || ref).filter(Boolean);

      const cells = [
        id,
        severity,
        description,
        affectedNames.length ? affectedNames.join(', ') : '—'
      ];
      cells.forEach((value, index) => {
        const cell = document.createElement('td');
        if (index === 1) {
          cell.innerHTML = `<span class="sunshine-pill" style="background:${DEFAULT_COLORS[severity] || '#e2e8f0'}">${severity}</span>`;
        } else {
          cell.textContent = value;
        }
        row.appendChild(cell);
      });
      tbody.appendChild(row);
    });
  }
  table.appendChild(tbody);
  section.appendChild(table);
}

export {
  renderSummaryTable,
  renderComponentsChart,
  renderComponentsTable,
  renderVulnerabilitiesTable
};
