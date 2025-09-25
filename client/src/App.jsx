import { useMemo, useState } from 'react';
import './App.css';

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:4000';

const severityOrder = ['critical', 'high', 'medium', 'low'];
const severityLabels = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

function SeverityBadge({ severity, label }) {
  if (!severity) return null;
  return <span className={`severity-badge severity-${severity}`}>{label || severity}</span>;
}

function IssuesList({ title, items, emptyLabel }) {
  if (!items || items.length === 0) {
    return (
      <section className="card">
        <h3>{title}</h3>
        <p className="muted">{emptyLabel}</p>
      </section>
    );
  }

  return (
    <section className="card">
      <h3>{title}</h3>
      <div className="issues">
        {items.map((issue) => (
          <article key={`${issue.id}-${issue.packageName}-${issue.title}`} className="issue">
            <header className="issue-header">
              <SeverityBadge severity={issue.severity} label={severityLabels[issue.severity]} />
              <h4>{issue.title}</h4>
            </header>
            <dl>
              {issue.packageName && (
                <div>
                  <dt>Package</dt>
                  <dd>{issue.packageName}{issue.version ? `@${issue.version}` : ''}</dd>
                </div>
              )}
              {issue.from && issue.from.length > 0 && (
                <div>
                  <dt>From</dt>
                  <dd className="muted">{issue.from.join(' → ')}</dd>
                </div>
              )}
              {issue.description && (
                <div>
                  <dt>Description</dt>
                  <dd>{issue.description}</dd>
                </div>
              )}
              {issue.publicationTime && (
                <div>
                  <dt>Published</dt>
                  <dd>{new Date(issue.publicationTime).toLocaleDateString()}</dd>
                </div>
              )}
              {issue.upgradePath && issue.upgradePath.length > 0 && issue.upgradePath.some(Boolean) && (
                <div>
                  <dt>Upgrade Path</dt>
                  <dd>{issue.upgradePath.filter(Boolean).join(' → ')}</dd>
                </div>
              )}
              {issue.url && (
                <div>
                  <dt>More Info</dt>
                  <dd>
                    <a href={issue.url} target="_blank" rel="noreferrer">
                      View in Snyk
                    </a>
                  </dd>
                </div>
              )}
            </dl>
          </article>
        ))}
      </div>
    </section>
  );
}

function SummaryCard({ summary }) {
  const entries = useMemo(() => severityOrder.map((severity) => ({
    severity,
    count: summary?.[severity] || 0,
  })), [summary]);

  return (
    <section className="card">
      <h3>Severity Overview</h3>
      <ul className="summary-grid">
        {entries.map(({ severity, count }) => (
          <li key={severity}>
            <SeverityBadge severity={severity} label={severityLabels[severity]} />
            <span className="summary-count">{count}</span>
          </li>
        ))}
      </ul>
    </section>
  );
}

function ScanResults({ result }) {
  if (!result) return null;

  const scanTargets = result.scanTargetFiles?.length
    ? result.scanTargetFiles
    : result.primaryTargetFile
      ? [result.primaryTargetFile]
      : [];

  const scanTargetLabel = scanTargets.length > 0 ? scanTargets.join(', ') : 'Entire project';
  const repoLinkLabel = result.repositoryUrl
    ? result.repositoryUrl.replace(/^https?:\/\//, '')
    : null;

  return (
    <div className="results">
      <section className="card project-card">
        <div className="project-card-header">
          <div>
            <h2>{result.projectName}</h2>
            {(result.projectType || repoLinkLabel) && (
              <p className="muted">
                {result.projectType && <span>{result.projectType}</span>}
                {result.projectType && repoLinkLabel && ' · '}
                {repoLinkLabel && (
                  <a href={result.repositoryUrl} target="_blank" rel="noreferrer">
                    {repoLinkLabel}
                  </a>
                )}
              </p>
            )}
          </div>
          <span className={`status-pill ${result.ok ? 'status-success' : 'status-alert'}`}>
            {result.ok ? 'No vulnerabilities detected' : 'Vulnerabilities found'}
          </span>
        </div>

        <ul className="project-meta">
          <li>
            <span className="muted">Dependencies:</span>{' '}
            {typeof result.dependencyCount === 'number' ? result.dependencyCount : 'Unknown'}
          </li>
          <li>
            <span className="muted">Repository access:</span>{' '}
            <span className={`status-pill status-compact ${result.repositoryAccessible ? 'status-success' : 'status-alert'}`}>
              {result.repositoryAccessible ? 'Accessible' : 'Unavailable'}
            </span>
          </li>
        </ul>

        <div className="scan-status-grid">
          <div>
            <span className="muted">Scan target</span>
            <p className="scan-target">{scanTargetLabel}</p>
          </div>
          {result.snykCommand && (
            <div>
              <span className="muted">Command</span>
              <code className="command-chip">{result.snykCommand}</code>
            </div>
          )}
        </div>
      </section>

      <SummaryCard summary={result.summary} />

      <IssuesList
        title="Security Issues"
        items={result.issues}
        emptyLabel="No security vulnerabilities reported."
      />

      <IssuesList
        title="License Issues"
        items={result.licenses}
        emptyLabel="No license issues reported."
      />

      <section className="card">
        <h3>Action Plan</h3>
        {Array.isArray(result.actionPlan) && result.actionPlan.length > 0 ? (
          <ol className="action-plan">
            {result.actionPlan.map((step, index) => (
              <li key={`${index}-${step}`}>{step}</li>
            ))}
          </ol>
        ) : (
          <p className="muted">No actions recommended.</p>
        )}
      </section>
    </div>
  );
}

function App() {
  const [repoUrl, setRepoUrl] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState(null);
  const [result, setResult] = useState(null);

  const handleSubmit = async (event) => {
    event.preventDefault();
    if (!repoUrl) {
      setError('Please enter a GitHub repository URL.');
      return;
    }

    setIsLoading(true);
    setError(null);
    setResult(null);

    try {
      const response = await fetch(`${API_BASE}/api/scan`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ repoUrl }),
      });

      const data = await response.json();

      if (!response.ok) {
        const detail = typeof data?.details === 'string' ? data.details : null;
        const combined = [data?.error, detail].filter(Boolean).join(': ');
        throw new Error(combined || 'Scan failed.');
      }

      setResult(data);
    } catch (err) {
      setError(err.message || 'Unexpected error while scanning repository.');
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="app-shell">
      <header className="hero">
        <div>
          <h1>Snyk Security Scanner</h1>
          <p>Audit any public GitHub repository for known vulnerabilities and license issues.</p>
        </div>
      </header>

      <main className="content">
        <form className="scan-form" onSubmit={handleSubmit}>
          <label htmlFor="repoUrl">GitHub Repository URL</label>
          <div className="form-row">
            <input
              id="repoUrl"
              type="url"
              placeholder="https://github.com/org/project"
              value={repoUrl}
              onChange={(event) => setRepoUrl(event.target.value)}
              autoComplete="off"
            />
            <button type="submit" disabled={isLoading}>
              {isLoading ? 'Scanning…' : 'Run Scan'}
            </button>
          </div>
          <p className="helper">
            Ensure the backend has access to a valid `SNYK_TOKEN` environment variable before running scans.
          </p>
        </form>

        {error && (
          <div className="card error-card">
            <h3>Scan Error</h3>
            <p>{error}</p>
          </div>
        )}

        {isLoading && (
          <div className="card loading-card">
            <div className="spinner" aria-hidden />
            <p>Running Snyk scan… This may take a minute.</p>
          </div>
        )}

        {!isLoading && result && <ScanResults result={result} />}
      </main>

      <footer className="footer">
        <p className="muted">
          Powered by <a href="https://snyk.io" target="_blank" rel="noreferrer">Snyk</a>. Provide an access token via the backend `SNYK_TOKEN` env variable.
        </p>
      </footer>
    </div>
  );
}

export default App;
