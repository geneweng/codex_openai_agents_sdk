const express = require('express');
const cors = require('cors');
const path = require('path');
const os = require('os');
const fs = require('fs/promises');
const { exec } = require('child_process');
const util = require('util');
const simpleGit = require('simple-git');
const { ActionPlanAgent } = require('./actionPlanAgent');

const execAsync = util.promisify(exec);
const app = express();
const PORT = process.env.PORT || 4000;
const SNYK_COMMAND = process.env.SNYK_COMMAND || 'npx snyk test --json';
const CLIENT_DIST_PATH = path.join(__dirname, '..', 'client', 'dist');
const actionPlanAgent = new ActionPlanAgent();

const buildHelpfulErrorDetail = (details = '') => {
  const normalized = String(details || '').toLowerCase();
  if (normalized.includes('snyk auth') || normalized.includes('authentication')) {
    return `${details} Ensure the backend process has a valid SNYK_TOKEN environment variable.`.trim();
  }
  return details;
};

app.use(cors());
app.use(express.json());

(async () => {
  try {
    await fs.access(CLIENT_DIST_PATH);
    app.use(express.static(CLIENT_DIST_PATH));
    app.get(/^\/(?!api).*/, (_req, res) => {
      res.sendFile(path.join(CLIENT_DIST_PATH, 'index.html'));
    });
  } catch (err) {
    console.log('Client build not found, running API-only mode.');
  }
})();

const cleanUpDir = async (dirPath) => {
  if (!dirPath) return;
  try {
    await fs.rm(dirPath, { recursive: true, force: true });
  } catch (err) {
    console.warn('Failed to clean temporary directory', dirPath, err.message);
  }
};

const deriveRepoName = (repoUrl = '') => {
  try {
    const cleaned = repoUrl.trim().replace(/\.git$/, '');
    const parts = cleaned.split('/').filter(Boolean);
    const lastTwo = parts.slice(-2);
    return lastTwo.join('/');
  } catch (err) {
    return 'Repository';
  }
};

const formatSnykPayload = (payload, context = {}) => {
  const { repoUrl, snykCommand } = context;
  const legacyVulns = Array.isArray(payload?.vulnerabilities)
    ? payload.vulnerabilities
    : [];
  const issues = Array.isArray(payload?.issues?.vulnerabilities)
    ? payload.issues.vulnerabilities
    : legacyVulns;
  const licenseIssues = Array.isArray(payload?.issues?.licenses)
    ? payload.issues.licenses
    : [];

  const projectName =
    payload?.projectName ||
    payload?.projectNames?.[0] ||
    payload?.displayTargetFile ||
    deriveRepoName(repoUrl) ||
    'Unknown project';

  const targetFiles = [];
  const pushTarget = (value) => {
    if (typeof value !== 'string') return;
    const trimmed = value.trim();
    if (!trimmed) return;
    if (!targetFiles.includes(trimmed)) targetFiles.push(trimmed);
  };

  pushTarget(payload?.displayTargetFile);
  pushTarget(payload?.targetFile);
  if (Array.isArray(payload?.targetFiles)) {
    payload.targetFiles.forEach(pushTarget);
  }

  const projectType = payload?.projectType || payload?.packageManager || null;
  const dependencyCount = payload?.dependencyCount ?? payload?.summary?.dependencyCount ?? null;
  const repositoryUrl = repoUrl || payload?.projectUrl || null;
  const repositoryAccessible = true; // clone succeeded if we reach this point

  const counters = { critical: 0, high: 0, medium: 0, low: 0 }; // Snyk severities
  issues.forEach((item) => {
    if (item.severity && counters[item.severity] !== undefined) {
      counters[item.severity] += 1;
    }
  });

  return {
    ok: Boolean(payload?.ok),
    projectName,
    summary: counters,
    issues: issues.map((item) => ({
      id: item.id,
      title: item.title,
      severity: item.severity,
      packageName: item.packageName,
      version: item.version,
      from: item.from,
      description: item.description,
      url: item.url || item.identifiers?.url?.[0] || null,
      publicationTime: item.publicationTime || null,
      upgradePath: item.upgradePath || [],
      isPatched: item.isPatched || false,
    })),
    licenses: licenseIssues.map((item) => ({
      id: item.id,
      title: item.title,
      severity: item.severity,
      packageName: item.packageName,
      description: item.description,
      url: item.url || null,
    })),
    projectType,
    repositoryUrl,
    repositoryAccessible,
    scanTargetFiles: targetFiles,
    primaryTargetFile: targetFiles[0] || null,
    snykCommand: snykCommand || null,
    dependencyCount,
    raw: payload,
  };
};

app.post('/api/scan', async (req, res) => {
  const repoUrl = req.body?.repoUrl;

  if (!repoUrl || typeof repoUrl !== 'string') {
    return res.status(400).json({ error: 'A valid GitHub repository URL is required.' });
  }

  const baseTempDir = await fs.mkdtemp(path.join(os.tmpdir(), 'snyk-scan-'));
  const repoDir = path.join(baseTempDir, 'repo');
  const git = simpleGit();

  try {
    await git.clone(repoUrl, repoDir, ['--depth', '1']);
  } catch (err) {
    await cleanUpDir(baseTempDir);
    return res.status(400).json({
      error: 'Failed to clone repository.',
      details: err.message,
    });
  }

  let scanOutput = '';

  try {
    const { stdout } = await execAsync(SNYK_COMMAND, {
      cwd: repoDir,
      env: { ...process.env },
      maxBuffer: 1024 * 1024 * 10, // 10 MB
    });
    scanOutput = stdout;
  } catch (err) {
    const stdout = err.stdout || (Array.isArray(err.output) ? err.output[1] : '');
    const stderr = err.stderr || (Array.isArray(err.output) ? err.output[2] : '');

    if (stdout) {
      scanOutput = stdout;
    } else {
      await cleanUpDir(baseTempDir);
      return res.status(500).json({
        error: 'Snyk scan failed.',
        details: buildHelpfulErrorDetail(stderr || err.message),
      });
    }
  }

  try {
    const parsed = JSON.parse(scanOutput);
    if (parsed?.error || parsed?.userMessage) {
      return res.status(502).json({
        error: 'Snyk scan reported an error.',
        details: buildHelpfulErrorDetail(parsed.userMessage || parsed.error),
      });
    }
    const formatted = formatSnykPayload(parsed, { repoUrl, snykCommand: SNYK_COMMAND });
    const actionPlan = await actionPlanAgent.generate(formatted);
    res.json({ ...formatted, actionPlan });
  } catch (err) {
    return res.status(500).json({
      error: 'Unable to parse Snyk output.',
      details: err.message,
      rawOutput: scanOutput,
    });
  } finally {
    await cleanUpDir(baseTempDir);
  }
});

app.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

app.listen(PORT, () => {
  console.log(`Snyk scanner backend listening on port ${PORT}`);
});
