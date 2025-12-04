import React, { useEffect, useRef } from 'react';
import {
  renderSummaryTable,
  renderComponentsChart,
  renderComponentsTable,
  renderVulnerabilitiesTable
} from 'sunshine-core';

function useSunshineRenderer(renderer, bom, options) {
  const ref = useRef(null);

  useEffect(() => {
    if (!ref.current || !bom) return;
    renderer(ref.current, bom, options);
    return () => {
      if (ref.current) {
        if (ref.current.__sunshineChart) {
          ref.current.__sunshineChart.destroy();
          delete ref.current.__sunshineChart;
        }
        ref.current.innerHTML = '';
      }
    };
  }, [renderer, bom, options]);

  return ref;
}

function createComponent(renderer, displayName) {
  const Component = ({ bom, className, options }) => {
    const ref = useSunshineRenderer(renderer, bom, options);
    return <div className={className} ref={ref} />;
  };
  Component.displayName = displayName;
  return Component;
}

const SunshineSummaryTable = createComponent(renderSummaryTable, 'SunshineSummaryTable');
const SunshineComponentsChart = createComponent(renderComponentsChart, 'SunshineComponentsChart');
const SunshineComponentsTable = createComponent(renderComponentsTable, 'SunshineComponentsTable');
const SunshineVulnerabilitiesTable = createComponent(renderVulnerabilitiesTable, 'SunshineVulnerabilitiesTable');

export {
  SunshineSummaryTable,
  SunshineComponentsChart,
  SunshineComponentsTable,
  SunshineVulnerabilitiesTable
};
