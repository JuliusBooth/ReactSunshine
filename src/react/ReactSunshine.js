import React, { useEffect, useRef } from 'react';
import PropTypes from 'prop-types';
import {
  renderSummaryTable,
  renderComponentsChart,
  renderComponentsTable,
  renderVulnerabilitiesTable,
  clearContainer
} from '../core/index.js';

function useImperativeRenderer(renderer, sbom, options) {
  const ref = useRef(null);

  useEffect(() => {
    if (!ref.current || !sbom) {
      return undefined;
    }
    renderer(ref.current, sbom, options);
    return () => clearContainer(ref.current);
  }, [renderer, sbom, options]);

  return ref;
}

function SunshineMount({ renderer, sbom, className, options }) {
  const ref = useImperativeRenderer(renderer, sbom, options);
  return React.createElement('div', { className, ref });
}

SunshineMount.propTypes = {
  renderer: PropTypes.func.isRequired,
  sbom: PropTypes.object,
  className: PropTypes.string,
  options: PropTypes.object
};

export function SummaryTable(props) {
  return React.createElement(SunshineMount, { ...props, renderer: renderSummaryTable });
}

export function ComponentsChart(props) {
  return React.createElement(SunshineMount, { ...props, renderer: renderComponentsChart });
}

export function ComponentsTable(props) {
  return React.createElement(SunshineMount, { ...props, renderer: renderComponentsTable });
}

export function VulnerabilitiesTable(props) {
  return React.createElement(SunshineMount, { ...props, renderer: renderVulnerabilitiesTable });
}

SummaryTable.propTypes = {
  sbom: PropTypes.object,
  className: PropTypes.string,
  options: PropTypes.object
};

ComponentsChart.propTypes = SummaryTable.propTypes;
ComponentsTable.propTypes = SummaryTable.propTypes;
VulnerabilitiesTable.propTypes = SummaryTable.propTypes;

export function ReactSunshine({
  sbom,
  showSummary = true,
  showComponentsChart = true,
  showComponentsTable = true,
  showVulnerabilitiesTable = true,
  className,
  sectionClassName
}) {
  const children = [];

  if (showSummary) {
    children.push(
      React.createElement(SummaryTable, { sbom, className: sectionClassName, key: 'summary' })
    );
  }
  if (showComponentsChart) {
    children.push(
      React.createElement(ComponentsChart, { sbom, className: sectionClassName, key: 'components-chart' })
    );
  }
  if (showComponentsTable) {
    children.push(
      React.createElement(ComponentsTable, { sbom, className: sectionClassName, key: 'components-table' })
    );
  }
  if (showVulnerabilitiesTable) {
    children.push(
      React.createElement(VulnerabilitiesTable, { sbom, className: sectionClassName, key: 'vulnerabilities-table' })
    );
  }

  return React.createElement('div', { className }, children);
}

ReactSunshine.propTypes = {
  sbom: PropTypes.object,
  showSummary: PropTypes.bool,
  showComponentsChart: PropTypes.bool,
  showComponentsTable: PropTypes.bool,
  showVulnerabilitiesTable: PropTypes.bool,
  className: PropTypes.string,
  sectionClassName: PropTypes.string
};

export default ReactSunshine;
