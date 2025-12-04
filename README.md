# React Sunshine

React Sunshine packages the CycloneDX Sunshine visualizations as a reusable JavaScript core and a React wrapper.

## Packages

- **sunshine-core (ESM)**: imperative render helpers that accept a DOM node (or selector) and a CycloneDX JSON object.
- **react-sunshine**: thin React bindings that treat the core like any other charting library.

## Installation

```
npm install react-sunshine
```

Peer dependencies `react` and `react-dom` are expected to be provided by the host application.

## Core usage

```js
import {
  renderSummaryTable,
  renderComponentsChart,
  renderComponentsTable,
  renderVulnerabilitiesTable
} from 'react-sunshine/core';

fetch('/sbom.json')
  .then((resp) => resp.json())
  .then((sbom) => {
    renderSummaryTable('#summary', sbom);
    renderComponentsChart('#chart', sbom);
    renderComponentsTable('#components', sbom);
    renderVulnerabilitiesTable('#vulns', sbom);
  });
```

Each renderer accepts a DOM element or selector and the CycloneDX JSON object. Containers are cleared automatically on re-render.

## React usage

```js
import ReactSunshine, {
  SummaryTable,
  ComponentsChart,
  ComponentsTable,
  VulnerabilitiesTable
} from 'react-sunshine';

export function Dashboard({ sbom }) {
  return (
    <ReactSunshine sbom={sbom} sectionClassName="my-section" />
  );
}

export function SplitView({ sbom }) {
  return (
    <div className="grid">
      <SummaryTable sbom={sbom} />
      <ComponentsChart sbom={sbom} />
      <ComponentsTable sbom={sbom} />
      <VulnerabilitiesTable sbom={sbom} />
    </div>
  );
}
```

## Building

```
npm run build
```

The build step copies the ESM sources into `dist/`, which is the published entry point referenced by the `module` field.
