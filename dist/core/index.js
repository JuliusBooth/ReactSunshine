import * as echarts from 'echarts';

const STYLE_ID = 'sunshine-core-styles';
const SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
const DEFAULT_COMPONENT_TYPE = 'library';

function ensureElement(container) {
  if (!container) {
    throw new Error('No container provided to Sunshine renderer.');
  }
  if (typeof container === 'string') {
    const node = document.querySelector(container);
    if (!node) {
      throw new Error(`Selector ${container} did not match any elements.`);
    }
    return node;
  }
  return container;
}

function injectBaseStyles() {
  if (document.getElementById(STYLE_ID)) {
    return;
  }
  const style = document.createElement('style');
  style.id = STYLE_ID;
  style.textContent = `
    .sunshine-panel { background: #fff; border: 1px solid #dce3eb; border-radius: 10px; padding: 16px; box-shadow: 0 1px 4px rgba(0,0,0,0.06); }
    .sunshine-heading { margin: 0 0 12px; font-size: 1.1rem; color: #0f2c4b; }
    .sunshine-table { width: 100%; border-collapse: collapse; font-size: 0.95rem; }
    .sunshine-table th, .sunshine-table td { padding: 10px 12px; border-bottom: 1px solid #e7edf5; text-align: left; }
    .sunshine-table th { background: #f4f7fb; font-weight: 600; color: #0f2c4b; }
    .sunshine-chip { display: inline-block; padding: 4px 10px; border-radius: 999px; font-size: 0.8rem; font-weight: 600; text-transform: capitalize; }
    .sunshine-chip.critical { background: #a10a0a; color: #fff; }
    .sunshine-chip.high { background: #ff4633; color: #fff; }
    .sunshine-chip.medium { background: #ff9335; color: #fff; }
    .sunshine-chip.low { background: #fccd58; color: #3b2f00; }
    .sunshine-chip.info { background: #7dd491; color: #0b3b1d; }
    .sunshine-chip.unknown { background: #9fc5e8; color: #0f2c4b; }
    .sunshine-empty { color: #6b7c93; font-size: 0.95rem; }
    .sunshine-chart { width: 100%; height: 360px; }
  `;
  document.head.appendChild(style);
}

function normalizeComponents(sbom = {}) {
  if (Array.isArray(sbom.components)) {
    return sbom.components;
  }
  if (sbom.metadata && Array.isArray(sbom.metadata.components)) {
    return sbom.metadata.components;
  }
  return [];
}

function normalizeVulnerabilities(sbom = {}) {
  return Array.isArray(sbom.vulnerabilities) ? sbom.vulnerabilities : [];
}

function pickSeverityFromRatings(ratings = []) {
  for (const rating of ratings) {
    if (rating && rating.severity) {
      return (rating.severity || '').toLowerCase();
    }
  }
  return 'unknown';
}

function deriveSeverity(vulnerability = {}) {
  if (vulnerability.severity) {
    return String(vulnerability.severity).toLowerCase();
  }
  if (Array.isArray(vulnerability.ratings)) {
    return pickSeverityFromRatings(vulnerability.ratings);
  }
  return 'unknown';
}

function computeSeverityCounts(vulnerabilities) {
  const counts = Object.fromEntries(SEVERITY_LEVELS.map((level) => [level, 0]));
  for (const vuln of vulnerabilities) {
    const level = deriveSeverity(vuln);
    counts[level] = (counts[level] || 0) + 1;
  }
  return counts;
}

function clearContainer(container) {
  const el = ensureElement(container);
  const chart = echarts.getInstanceByDom(el);
  if (chart) {
    chart.dispose();
  }
  el.innerHTML = '';
}

function renderSummaryTable(container, sbom) {
  const el = ensureElement(container);
  injectBaseStyles();
  clearContainer(el);

  const components = normalizeComponents(sbom);
  const vulnerabilities = normalizeVulnerabilities(sbom);
  const severityCounts = computeSeverityCounts(vulnerabilities);

  const wrapper = document.createElement('div');
  wrapper.className = 'sunshine-panel';

  const heading = document.createElement('h3');
  heading.className = 'sunshine-heading';
  heading.textContent = 'SBOM Summary';
  wrapper.appendChild(heading);

  const table = document.createElement('table');
  table.className = 'sunshine-table';
  const headerRow = document.createElement('tr');
  for (const title of ['Metric', 'Value']) {
    const th = document.createElement('th');
    th.textContent = title;
    headerRow.appendChild(th);
  }
  const thead = document.createElement('thead');
  thead.appendChild(headerRow);
  table.appendChild(thead);

  const tbody = document.createElement('tbody');
  const rows = [
    { label: 'Components', value: components.length },
    { label: 'Vulnerabilities', value: vulnerabilities.length },
    ...SEVERITY_LEVELS.map((level) => ({
      label: `${level.charAt(0).toUpperCase()}${level.slice(1)} vulnerabilities`,
      value: severityCounts[level] || 0,
      severity: level
    }))
  ];

  for (const row of rows) {
    const tr = document.createElement('tr');
    const label = document.createElement('td');
    label.textContent = row.label;
    const value = document.createElement('td');
    if (row.severity) {
      const chip = document.createElement('span');
      chip.className = `sunshine-chip ${row.severity}`;
      chip.textContent = row.value;
      value.appendChild(chip);
    } else {
      value.textContent = row.value;
    }
    tr.appendChild(label);
    tr.appendChild(value);
    tbody.appendChild(tr);
  }

  table.appendChild(tbody);
  wrapper.appendChild(table);
  el.appendChild(wrapper);
}

function renderComponentsChart(container, sbom) {
  const el = ensureElement(container);
  injectBaseStyles();
  clearContainer(el);

  const components = normalizeComponents(sbom);
  const typeCounts = new Map();
  for (const component of components) {
    const type = (component.type || DEFAULT_COMPONENT_TYPE).toLowerCase();
    typeCounts.set(type, (typeCounts.get(type) || 0) + 1);
  }

  if (!typeCounts.size) {
    const empty = document.createElement('p');
    empty.className = 'sunshine-empty';
    empty.textContent = 'No components found to chart.';
    el.appendChild(empty);
    return;
  }

  const chartEl = document.createElement('div');
  chartEl.className = 'sunshine-chart';
  el.appendChild(chartEl);

  const chart = echarts.init(chartEl);
  chart.setOption({
    title: { text: 'Components by type', left: 'center' },
    tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
    series: [
      {
        type: 'pie',
        radius: ['35%', '65%'],
        emphasis: { focus: 'data' },
        data: Array.from(typeCounts.entries()).map(([name, value]) => ({ name, value }))
      }
    ]
  });
}

function buildTable(headers, rows) {
  const table = document.createElement('table');
  table.className = 'sunshine-table';
  const thead = document.createElement('thead');
  const headerRow = document.createElement('tr');
  headers.forEach((header) => {
    const th = document.createElement('th');
    th.textContent = header;
    headerRow.appendChild(th);
  });
  thead.appendChild(headerRow);
  table.appendChild(thead);

  const tbody = document.createElement('tbody');
  rows.forEach((cells) => {
    const tr = document.createElement('tr');
    cells.forEach((cell) => {
      const td = document.createElement('td');
      if (cell instanceof Node) {
        td.appendChild(cell);
      } else {
        td.textContent = cell ?? '';
      }
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  return table;
}

function renderComponentsTable(container, sbom) {
  const el = ensureElement(container);
  injectBaseStyles();
  clearContainer(el);

  const components = normalizeComponents(sbom);
  const wrapper = document.createElement('div');
  wrapper.className = 'sunshine-panel';

  const heading = document.createElement('h3');
  heading.className = 'sunshine-heading';
  heading.textContent = 'Components';
  wrapper.appendChild(heading);

  if (!components.length) {
    const empty = document.createElement('p');
    empty.className = 'sunshine-empty';
    empty.textContent = 'No components were found in the SBOM.';
    wrapper.appendChild(empty);
    el.appendChild(wrapper);
    return;
  }

  const headers = ['Name', 'Version', 'Type', 'Scope', 'Supplier', 'PURL'];
  const rows = components.map((component) => [
    component.name || 'Unknown component',
    component.version || '—',
    component.type || DEFAULT_COMPONENT_TYPE,
    component.scope || '—',
    component.supplier?.name || '—',
    component.purl || '—'
  ]);

  wrapper.appendChild(buildTable(headers, rows));
  el.appendChild(wrapper);
}

function renderVulnerabilitiesTable(container, sbom) {
  const el = ensureElement(container);
  injectBaseStyles();
  clearContainer(el);

  const vulnerabilities = normalizeVulnerabilities(sbom);
  const components = normalizeComponents(sbom);
  const componentLookup = new Map();
  for (const component of components) {
    const ref = component['bom-ref'] || component.bomRef || component.name;
    if (ref) {
      componentLookup.set(ref, component);
    }
  }

  const wrapper = document.createElement('div');
  wrapper.className = 'sunshine-panel';
  const heading = document.createElement('h3');
  heading.className = 'sunshine-heading';
  heading.textContent = 'Vulnerabilities';
  wrapper.appendChild(heading);

  if (!vulnerabilities.length) {
    const empty = document.createElement('p');
    empty.className = 'sunshine-empty';
    empty.textContent = 'No vulnerabilities were reported.';
    wrapper.appendChild(empty);
    el.appendChild(wrapper);
    return;
  }

  const headers = ['ID', 'Severity', 'Component', 'Description'];
  const rows = vulnerabilities.map((vuln) => {
    const severity = deriveSeverity(vuln);
    const chip = document.createElement('span');
    chip.className = `sunshine-chip ${severity}`;
    chip.textContent = severity;

    const affectedRefs = (vuln.affects || []).map((affect) => affect.ref).filter(Boolean);
    const componentNames = affectedRefs
      .map((ref) => componentLookup.get(ref)?.name || ref)
      .filter(Boolean);

    return [
      vuln.id || vuln.source?.name || 'Unknown',
      chip,
      componentNames.length ? componentNames.join(', ') : '—',
      vuln.description || '—'
    ];
  });

  wrapper.appendChild(buildTable(headers, rows));
  el.appendChild(wrapper);
}

export const SunshineCore = {
  renderSummaryTable,
  renderComponentsChart,
  renderComponentsTable,
  renderVulnerabilitiesTable,
  clearContainer
};

export {
  renderSummaryTable,
  renderComponentsChart,
  renderComponentsTable,
  renderVulnerabilitiesTable,
  clearContainer
};
