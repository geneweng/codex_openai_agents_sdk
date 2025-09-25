const severityOrder = ['critical', 'high', 'medium', 'low'];

const summarizePackages = (issues = []) => {
  const packages = issues
    .map((issue) => issue.packageName)
    .filter(Boolean);
  const unique = [...new Set(packages)].slice(0, 5);
  if (unique.length === 0) return null;
  const list = unique.join(', ');
  return packages.length > unique.length ? `${list}, …` : list;
};

class ActionPlanAgent {
  generate(scanResult) {
    if (!scanResult || typeof scanResult !== 'object') {
      return [];
    }

    const plan = [];

    if (!scanResult.repositoryAccessible) {
      plan.push('Restore repository access so automated scans can run.');
      return plan;
    }

    if (!Array.isArray(scanResult.issues)) {
      return plan;
    }

    const issuesBySeverity = severityOrder.reduce((acc, severity) => {
      acc[severity] = scanResult.issues.filter((issue) => issue.severity === severity);
      return acc;
    }, {});

    severityOrder.forEach((severity) => {
      const issues = issuesBySeverity[severity];
      if (!issues || issues.length === 0) return;

      const packages = summarizePackages(issues);
      const title = `${severity.charAt(0).toUpperCase()}${severity.slice(1)} vulnerabilities`;

      const fixHints = new Set();
      issues.forEach((issue) => {
        if (Array.isArray(issue.upgradePath) && issue.upgradePath.some(Boolean)) {
          fixHints.add('upgrade dependencies to secure versions');
        }
        if (issue.isPatched) {
          fixHints.add('apply available patches');
        }
      });

      const hintText = fixHints.size > 0 ? ` (${Array.from(fixHints).join(' or ')})` : '';
      const packageText = packages ? ` (${packages})` : '';

      plan.push(`Resolve ${title} first${packageText}${hintText}.`);
    });

    if (Array.isArray(scanResult.licenses) && scanResult.licenses.length > 0) {
      const licensePkgs = summarizePackages(scanResult.licenses);
      plan.push(`Review license findings${licensePkgs ? ` for ${licensePkgs}` : ''} with legal/compliance teams.`);
    }

    if (scanResult.issues.length > 0) {
      plan.push('Add automated dependency updates (Dependabot, Renovate) and enforce Snyk scans in CI.');
      plan.push('Re-run `snyk test` after applying fixes to confirm a clean report.');
    } else {
      plan.push('No vulnerabilities found. Schedule recurring scans and keep dependencies updated.');
    }

    return plan;
  }
}

module.exports = { ActionPlanAgent };
