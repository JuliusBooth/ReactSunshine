import * as echarts from 'echarts';

const STYLE_ID = 'sunshine-core-styles';
const SEVERITY_LEVELS = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
const DEFAULT_COMPONENT_TYPE = 'library';

// Color constants matching the original Python implementation
const COLORS = {
  GREY: '#bcbcbc',
  GREEN: '#7dd491',
  YELLOW: '#fccd58',
  ORANGE: '#ff9335',
  RED: '#ff4633',
  DARK_RED: '#a10a0a',
  LIGHT_BLUE: '#9fc5e8'
};

const VALID_SEVERITIES = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  info: 0,
  information: 0,
  clean: -1
};

const STYLES = {
  critical: { color: COLORS.DARK_RED, borderWidth: 2 },
  high: { color: COLORS.RED, borderWidth: 2 },
  medium: { color: COLORS.ORANGE, borderWidth: 2 },
  low: { color: COLORS.YELLOW, borderWidth: 2 },
  information: { color: COLORS.GREEN, borderWidth: 2 },
  info: { color: COLORS.GREEN, borderWidth: 2 },
  clean: { color: COLORS.GREY, borderWidth: 2 },
  transitive: { color: COLORS.LIGHT_BLUE, borderWidth: 2 }
};

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
    .sunshine-chart { width: 100%; height: 500px; min-height: 400px; }
    .sunshine-chart-controls { margin-bottom: 12px; display: flex; gap: 16px; align-items: center; }
    .sunshine-chart-controls label { display: flex; align-items: center; gap: 6px; cursor: pointer; font-size: 0.9rem; }
    .sunshine-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 600; margin: 2px; }
    .sunshine-badge.bg-dark-red { background: #a10a0a; color: #fff; }
    .sunshine-badge.bg-danger { background: #ff4633; color: #fff; }
    .sunshine-badge.bg-orange { background: #ff9335; color: #fff; }
    .sunshine-badge.bg-yellow { background: #fccd58; color: #3b2f00; }
    .sunshine-badge.bg-success { background: #7dd491; color: #0b3b1d; }
    .sunshine-badge.bg-secondary { background: #bcbcbc; color: #333; }
    .sunshine-badge.bg-light-blue { background: #9fc5e8; color: #0f2c4b; }
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

function normalizeDependencies(sbom = {}) {
  return Array.isArray(sbom.dependencies) ? sbom.dependencies : [];
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

function getSeverityScore(vulnerability = {}) {
  if (Array.isArray(vulnerability.ratings)) {
    for (const rating of vulnerability.ratings) {
      if (rating && rating.score !== undefined) {
        return parseFloat(rating.score);
      }
    }
  }
  return 0;
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
  if (!container) {
    return;
  }
  const el = typeof container === 'string' ? document.querySelector(container) : container;
  if (!el) {
    return;
  }
  const chart = echarts.getInstanceByDom(el);
  if (chart) {
    chart.dispose();
  }
  el.innerHTML = '';
}

// Parse SBOM data to build component relationships and vulnerability mapping
function parseSbomData(sbom) {
  const rawComponents = normalizeComponents(sbom);
  const rawVulnerabilities = normalizeVulnerabilities(sbom);
  const rawDependencies = normalizeDependencies(sbom);

  // Build component lookup by bom-ref
  const components = new Map();
  
  for (const comp of rawComponents) {
    const bomRef = comp['bom-ref'] || comp.bomRef || comp.purl || comp.name;
    if (bomRef) {
      components.set(bomRef, {
        name: comp.name || 'Unknown',
        version: comp.version || '-',
        type: comp.type || DEFAULT_COMPONENT_TYPE,
        license: parseLicenses(comp),
        dependsOn: new Set(),
        dependencyOf: new Set(),
        vulnerabilities: [],
        transitiveVulnerabilities: [],
        maxVulnerabilitySeverity: 'clean',
        hasTransitiveVulnerabilities: false,
        visited: false
      });
    }
  }

  // Build dependency relationships
  for (const dep of rawDependencies) {
    const ref = dep.ref;
    if (!ref || !components.has(ref)) continue;

    const dependsOn = dep.dependsOn || [];
    for (const childRef of dependsOn) {
      if (components.has(childRef)) {
        components.get(ref).dependsOn.add(childRef);
        components.get(childRef).dependencyOf.add(ref);
      }
    }
  }

  // Map vulnerabilities to components
  for (const vuln of rawVulnerabilities) {
    const vulnId = vuln.id || vuln.source?.name || 'Unknown';
    const severity = deriveSeverity(vuln);
    const score = getSeverityScore(vuln);
    
    const affects = vuln.affects || [];
    for (const affect of affects) {
      const ref = affect.ref;
      if (ref && components.has(ref)) {
        const comp = components.get(ref);
        const vulnData = { id: vulnId, severity, score };
        
        if (!comp.vulnerabilities.some(v => v.id === vulnId)) {
          comp.vulnerabilities.push(vulnData);
        }
        
        const severityValue = VALID_SEVERITIES[severity] ?? -1;
        const currentMax = VALID_SEVERITIES[comp.maxVulnerabilitySeverity] ?? -1;
        if (severityValue > currentMax) {
          comp.maxVulnerabilitySeverity = severity === 'info' ? 'information' : severity;
        }
      }
    }
  }

  return components;
}

function parseLicenses(component) {
  const licenses = new Set();
  if (Array.isArray(component.licenses)) {
    for (const lic of component.licenses) {
      if (lic.license) {
        if (lic.license.id) licenses.add(lic.license.id);
        else if (lic.license.name) licenses.add(lic.license.name);
      }
    }
  }
  return Array.from(licenses);
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function prepareChartElementName(component) {
  let name = component.version !== '-' 
    ? `${escapeHtml(component.name)} <b>${escapeHtml(component.version)}</b>`
    : escapeHtml(component.name);

  if (component.vulnerabilities.length > 0) {
    name += '<br><br>Vulnerabilities:<br>';
    const vulns = component.vulnerabilities
      .sort((a, b) => (VALID_SEVERITIES[b.severity] ?? 0) - (VALID_SEVERITIES[a.severity] ?? 0))
      .slice(0, 10)
      .map(v => `<li>${escapeHtml(v.id)} (${escapeHtml(v.severity)})</li>`);
    
    if (component.vulnerabilities.length > 10) {
      vulns.push('<li>...</li>');
    }
    name += vulns.join('');
  }

  if (component.license.length > 0) {
    name += component.vulnerabilities.length === 0 ? '<br>' : '';
    name += '<br>License:<br>';
    const licenses = component.license.slice(0, 10).map(l => `<li>${escapeHtml(l)}</li>`);
    if (component.license.length > 10) {
      licenses.push('<li>...</li>');
    }
    name += licenses.join('');
  }

  return name;
}

function determineStyle(component) {
  if (component.maxVulnerabilitySeverity !== 'clean') {
    return STYLES[component.maxVulnerabilitySeverity] || STYLES.clean;
  }
  if (component.hasTransitiveVulnerabilities) {
    return STYLES.transitive;
  }
  return STYLES.clean;
}

function getChildren(components, component, parents, bomRef) {
  const children = [];
  let value = 0;
  let hasVulnerableChildrenOrIsVulnerable = component.vulnerabilities.length > 0;

  for (const dependsOnRef of component.dependsOn) {
    const childComponent = components.get(dependsOnRef);
    if (!childComponent) continue;

    childComponent.visited = true;
    const childName = prepareChartElementName(childComponent);
    
    // Avoid infinite recursion for circular dependencies
    if (!parents.has(dependsOnRef)) {
      const childParents = new Set(parents);
      childParents.add(dependsOnRef);
      
      const [childChildren, childValue, childVulnerable] = getChildren(
        components, childComponent, childParents, dependsOnRef
      );
      
      if (childComponent.vulnerabilities.length > 0 || 
          childComponent.hasTransitiveVulnerabilities || 
          childVulnerable) {
        component.hasTransitiveVulnerabilities = true;
        // Add transitive vulnerabilities
        for (const vuln of childComponent.vulnerabilities) {
          if (!component.transitiveVulnerabilities.some(v => v.id === vuln.id)) {
            component.transitiveVulnerabilities.push(vuln);
          }
        }
        for (const vuln of childComponent.transitiveVulnerabilities) {
          if (!component.transitiveVulnerabilities.some(v => v.id === vuln.id)) {
            component.transitiveVulnerabilities.push(vuln);
          }
        }
        hasVulnerableChildrenOrIsVulnerable = true;
      }

      value += childValue;
      children.push({
        name: childName,
        children: childChildren,
        value: childValue,
        itemStyle: determineStyle(childComponent)
      });
    } else {
      // Circular dependency - just show as leaf
      value += 1;
      children.push({
        name: childName,
        children: [],
        value: 1,
        itemStyle: determineStyle(childComponent)
      });
    }
  }

  if (value === 0) value = 1;
  return [children, value, hasVulnerableChildrenOrIsVulnerable];
}

function buildEchartsData(components) {
  const data = [];

  for (const [bomRef, component] of components) {
    // Start with root components (not a dependency of anything else)
    if (component.dependencyOf.size !== 0) continue;

    component.visited = true;
    const parents = new Set([bomRef]);
    const rootName = prepareChartElementName(component);
    const [rootChildren, rootValue, hasVulnerable] = getChildren(
      components, component, parents, bomRef
    );

    if (hasVulnerable) {
      component.hasTransitiveVulnerabilities = true;
      for (const depRef of component.dependsOn) {
        const child = components.get(depRef);
        if (child) {
          for (const vuln of child.vulnerabilities) {
            if (!component.transitiveVulnerabilities.some(v => v.id === vuln.id)) {
              component.transitiveVulnerabilities.push(vuln);
            }
          }
          for (const vuln of child.transitiveVulnerabilities) {
            if (!component.transitiveVulnerabilities.some(v => v.id === vuln.id)) {
              component.transitiveVulnerabilities.push(vuln);
            }
          }
        }
      }
    }

    data.push({
      name: rootName,
      children: rootChildren,
      value: rootValue,
      itemStyle: determineStyle(component)
    });
  }

  // Handle any unvisited components (circular dependencies at root level)
  for (const [bomRef, component] of components) {
    if (!component.visited) {
      component.visited = true;
      const parents = new Set([bomRef]);
      const rootName = prepareChartElementName(component);
      const [rootChildren, rootValue] = getChildren(components, component, parents, bomRef);

      data.push({
        name: rootName,
        children: rootChildren,
        value: rootValue,
        itemStyle: determineStyle(component)
      });
    }
  }

  return data;
}

function getOnlyVulnerableComponents(components) {
  const vulnerableComponents = new Map();

  for (const [bomRef, component] of components) {
    if (component.vulnerabilities.length === 0 && component.transitiveVulnerabilities.length === 0) {
      continue;
    }

    vulnerableComponents.set(bomRef, {
      ...component,
      dependsOn: new Set(component.dependsOn),
      dependencyOf: new Set(component.dependencyOf),
      vulnerabilities: [...component.vulnerabilities],
      transitiveVulnerabilities: [...component.transitiveVulnerabilities],
      visited: false
    });
  }

  // Clean non-vulnerable dependency relationships
  const vulnBomRefs = new Set(vulnerableComponents.keys());
  for (const [, component] of vulnerableComponents) {
    component.dependsOn = new Set([...component.dependsOn].filter(ref => vulnBomRefs.has(ref)));
    component.dependencyOf = new Set([...component.dependencyOf].filter(ref => vulnBomRefs.has(ref)));
  }

  return vulnerableComponents;
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

function renderComponentsChart(container, sbom, options = {}) {
  const el = ensureElement(container);
  injectBaseStyles();
  clearContainer(el);

  const components = parseSbomData(sbom);
  
  if (components.size === 0) {
    const empty = document.createElement('p');
    empty.className = 'sunshine-empty';
    empty.textContent = 'No components found to chart.';
    el.appendChild(empty);
    return;
  }

  const wrapper = document.createElement('div');
  wrapper.className = 'sunshine-panel';

  const heading = document.createElement('h3');
  heading.className = 'sunshine-heading';
  heading.textContent = 'Components Chart';
  wrapper.appendChild(heading);

  // Add description
  const description = document.createElement('div');
  description.style.marginBottom = '12px';
  description.style.fontSize = '0.9rem';
  description.style.color = '#6b7c93';
  description.innerHTML = `
    <p>This chart visualizes components and their dependencies. Each segment represents a component.</p>
    <ul style="margin: 8px 0; padding-left: 20px;">
      <li><b>Innermost circle:</b> root components (not dependencies of others)</li>
      <li><b>Outer circles:</b> dependencies, with depth indicating dependency level</li>
    </ul>
    <p><b>Colors:</b> 
      <span style="color: ${COLORS.DARK_RED}">■</span> Critical &nbsp;
      <span style="color: ${COLORS.RED}">■</span> High &nbsp;
      <span style="color: ${COLORS.ORANGE}">■</span> Medium &nbsp;
      <span style="color: ${COLORS.YELLOW}">■</span> Low &nbsp;
      <span style="color: ${COLORS.GREEN}">■</span> Info &nbsp;
      <span style="color: ${COLORS.LIGHT_BLUE}">■</span> Transitive vuln &nbsp;
      <span style="color: ${COLORS.GREY}">■</span> Clean
    </p>
  `;
  wrapper.appendChild(description);

  // Add toggle controls
  const controls = document.createElement('div');
  controls.className = 'sunshine-chart-controls';
  
  const allLabel = document.createElement('label');
  const allRadio = document.createElement('input');
  allRadio.type = 'radio';
  allRadio.name = `sunshine-chart-view-${Date.now()}`;
  allRadio.value = 'all';
  allRadio.checked = true;
  allLabel.appendChild(allRadio);
  allLabel.appendChild(document.createTextNode(' All components'));
  controls.appendChild(allLabel);

  const vulnLabel = document.createElement('label');
  const vulnRadio = document.createElement('input');
  vulnRadio.type = 'radio';
  vulnRadio.name = allRadio.name;
  vulnRadio.value = 'vulnerable';
  vulnLabel.appendChild(vulnRadio);
  vulnLabel.appendChild(document.createTextNode(' Only vulnerable components'));
  controls.appendChild(vulnLabel);

  wrapper.appendChild(controls);

  const chartEl = document.createElement('div');
  chartEl.className = 'sunshine-chart';
  wrapper.appendChild(chartEl);

  el.appendChild(wrapper);

  // Build chart data
  const allComponentsData = buildEchartsData(components);
  
  const vulnerableComponents = getOnlyVulnerableComponents(components);
  const vulnerableComponentsData = buildEchartsData(vulnerableComponents);

  // Initialize chart
  const chart = echarts.init(chartEl);
  
  function updateChart(showAll) {
    const data = showAll ? allComponentsData : vulnerableComponentsData;
    
    if (data.length === 0) {
      chart.clear();
      const noData = showAll ? 'No components found.' : 'No vulnerable components found.';
      chart.setOption({
        title: {
          text: noData,
          left: 'center',
          top: 'center',
          textStyle: { color: '#6b7c93', fontSize: 14 }
        }
      });
      return;
    }

    chart.setOption({
      tooltip: {
        trigger: 'item',
        formatter: (params) => params.name,
        confine: true
      },
      series: [{
        type: 'sunburst',
        radius: ['15%', '95%'],
        sort: undefined,
        emphasis: {
          focus: 'ancestor'
        },
        data: data,
        label: {
          rotate: 'radial',
          show: false
        },
        levels: []
      }]
    }, true);
  }

  updateChart(true);

  // Handle resize
  const resizeObserver = new ResizeObserver(() => {
    chart.resize();
  });
  resizeObserver.observe(chartEl);

  // Handle toggle
  allRadio.addEventListener('change', () => updateChart(true));
  vulnRadio.addEventListener('change', () => updateChart(false));
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

  const rawComponents = normalizeComponents(sbom);
  const components = parseSbomData(sbom);
  
  const wrapper = document.createElement('div');
  wrapper.className = 'sunshine-panel';

  const heading = document.createElement('h3');
  heading.className = 'sunshine-heading';
  heading.textContent = 'Components';
  wrapper.appendChild(heading);

  if (rawComponents.length === 0) {
    const empty = document.createElement('p');
    empty.className = 'sunshine-empty';
    empty.textContent = 'No components were found in the SBOM.';
    wrapper.appendChild(empty);
    el.appendChild(wrapper);
    return;
  }

  const headers = ['Name', 'Version', 'Type', 'Dependencies', 'Vulnerabilities'];
  const rows = [];

  for (const [bomRef, comp] of components) {
    // Create vulnerability badges
    const vulnContainer = document.createElement('span');
    if (comp.vulnerabilities.length > 0) {
      comp.vulnerabilities
        .sort((a, b) => (VALID_SEVERITIES[b.severity] ?? 0) - (VALID_SEVERITIES[a.severity] ?? 0))
        .forEach(v => {
          const badge = document.createElement('span');
          badge.className = `sunshine-badge ${getSeverityBadgeClass(v.severity)}`;
          badge.textContent = `${v.severity.toUpperCase()}: ${v.id}`;
          vulnContainer.appendChild(badge);
        });
    } else {
      vulnContainer.textContent = '—';
    }

    rows.push([
      comp.name,
      comp.version,
      comp.type,
      comp.dependsOn.size > 0 ? comp.dependsOn.size.toString() : '—',
      vulnContainer
    ]);
  }

  wrapper.appendChild(buildTable(headers, rows));
  el.appendChild(wrapper);
}

function getSeverityBadgeClass(severity) {
  switch (severity) {
    case 'critical': return 'bg-dark-red';
    case 'high': return 'bg-danger';
    case 'medium': return 'bg-orange';
    case 'low': return 'bg-yellow';
    case 'info':
    case 'information': return 'bg-success';
    default: return 'bg-secondary';
  }
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

  const headers = ['ID', 'Severity', 'Score', 'Component', 'Description'];
  const rows = vulnerabilities.map((vuln) => {
    const severity = deriveSeverity(vuln);
    const score = getSeverityScore(vuln);
    
    const chip = document.createElement('span');
    chip.className = `sunshine-chip ${severity === 'information' ? 'info' : severity}`;
    chip.textContent = severity;

    const affectedRefs = (vuln.affects || []).map((affect) => affect.ref).filter(Boolean);
    const componentNames = affectedRefs
      .map((ref) => componentLookup.get(ref)?.name || ref)
      .filter(Boolean);

    return [
      vuln.id || vuln.source?.name || 'Unknown',
      chip,
      score > 0 ? score.toFixed(1) : '—',
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
