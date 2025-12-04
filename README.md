# React Sunshine

Imperative and React-friendly visualizations for CycloneDX SBOMs. This repository now ships two packages:

- **sunshine-core**: Pure JavaScript utilities that render summary tables, component charts, component tables, and vulnerability tables directly into DOM nodes. Treated like any other imperative charting library.
- **react-sunshine**: A lightweight React wrapper that exposes each visualization as a component.

Both packages publish an ESM build via the `module` field for modern bundlers.

## Getting started

```bash
npm install
npm run build
```

The build step copies each package's `src` directory into `dist`, keeping the modules ESM ready for consumption.

## sunshine-core usage

```js
import {
  renderSummaryTable,
  renderComponentsChart,
  renderComponentsTable,
  renderVulnerabilitiesTable
} from 'sunshine-core';

// Assuming you have a CycloneDX JSON object in `bom` and a DOM node `container`
renderSummaryTable(container, bom);
renderComponentsChart(container, bom);
renderComponentsTable(container, bom);
renderVulnerabilitiesTable(container, bom);
```

Each renderer replaces the content of the provided container and injects minimal styling plus a Chart.js powered bar chart for the vulnerability distribution.

## react-sunshine usage

```jsx
import React from 'react';
import {
  SunshineSummaryTable,
  SunshineComponentsChart,
  SunshineComponentsTable,
  SunshineVulnerabilitiesTable
} from 'react-sunshine';

export function SunshineDashboard({ bom }) {
  return (
    <div className="sunshine-layout">
      <SunshineSummaryTable bom={bom} />
      <SunshineComponentsChart bom={bom} />
      <SunshineComponentsTable bom={bom} />
      <SunshineVulnerabilitiesTable bom={bom} />
    </div>
  );
}
```

React components accept a `bom` prop plus optional `className` and `options` (forwarded to the underlying renderer). They clean up charts and DOM nodes when the component unmounts or the BOM changes.

## Scripts

From the repository root:

- `npm run build` – builds all workspaces.
- `npm --workspace sunshine-core run build` – builds just the core package.
- `npm --workspace react-sunshine run build` – builds the React wrapper.

## License

Apache-2.0
