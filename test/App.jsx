import React, { useState, useEffect } from 'react';
import {
  ReactSunshine,
  SummaryTable,
  ComponentsChart,
  ComponentsTable,
  VulnerabilitiesTable
} from '../src/index.js';

// Import the SBOM data
import sbomData from '../sbom.json';

function App() {
  const [sbom] = useState(sbomData);
  const [activeView, setActiveView] = useState('all');

  return (
    <div className="app-container">
      <header className="app-header">
        <h1>🌤️ ReactSunshine SBOM Viewer</h1>
        <p className="subtitle">
          Visualizing {sbom?.components?.length || 0} components from sbom.json
        </p>
      </header>

      <nav className="view-tabs">
        <button
          className={activeView === 'all' ? 'active' : ''}
          onClick={() => setActiveView('all')}
        >
          All Panels
        </button>
        <button
          className={activeView === 'summary' ? 'active' : ''}
          onClick={() => setActiveView('summary')}
        >
          Summary
        </button>
        <button
          className={activeView === 'chart' ? 'active' : ''}
          onClick={() => setActiveView('chart')}
        >
          Chart
        </button>
        <button
          className={activeView === 'components' ? 'active' : ''}
          onClick={() => setActiveView('components')}
        >
          Components
        </button>
        <button
          className={activeView === 'vulnerabilities' ? 'active' : ''}
          onClick={() => setActiveView('vulnerabilities')}
        >
          Vulnerabilities
        </button>
      </nav>

      <main className="content">
        {activeView === 'all' && (
          <ReactSunshine
            sbom={sbom}
            className="sunshine-container"
            sectionClassName="section-panel"
          />
        )}

        {activeView === 'summary' && (
          <section className="single-view">
            <SummaryTable sbom={sbom} className="section-panel" />
          </section>
        )}

        {activeView === 'chart' && (
          <section className="single-view">
            <ComponentsChart sbom={sbom} className="section-panel" />
          </section>
        )}

        {activeView === 'components' && (
          <section className="single-view">
            <ComponentsTable sbom={sbom} className="section-panel" />
          </section>
        )}

        {activeView === 'vulnerabilities' && (
          <section className="single-view">
            <VulnerabilitiesTable sbom={sbom} className="section-panel" />
          </section>
        )}
      </main>

      <footer className="app-footer">
        <p>ReactSunshine Test App • SBOM Visualization Demo</p>
      </footer>
    </div>
  );
}

export default App;

