let OpenAI;
try {
  // eslint-disable-next-line global-require
  OpenAI = require('openai');
} catch (err) {
  OpenAI = null;
}

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
  constructor() {
    this.apiKey = process.env.OPENAI_API_KEY;
    this.model = process.env.OPENAI_AGENT_MODEL || 'gpt-4.1-mini';
    this.client = this.apiKey && OpenAI ? new OpenAI({ apiKey: this.apiKey }) : null;
    this.agentPromise = null;
  }

  async ensureAgent() {
    if (!this.client) return null;
    if (!this.agentPromise) {
      this.agentPromise = this.client.agents
        .create({
          model: this.model,
          name: 'Snyk Remediation Planner',
          instructions:
            'You are a security engineer. Given a Snyk scan result JSON, output remediation guidance as JSON matching schema {"steps": string[], "no_action": boolean}. If fixes are required, order steps by impact and include concrete actions. If no remediation is needed, set no_action to true and steps to an empty array. Return JSON only.',
        })
        .catch((err) => {
          console.error('Failed to create OpenAI agent:', err.message);
          this.agentPromise = null;
          return null;
        });
    }
    return this.agentPromise;
  }

  async generateWithOpenAI(scanResult) {
    const agent = await this.ensureAgent();
    if (!agent) return null;

    try {
      const extractText = (response) => {
        if (!response) return '';
        if (typeof response.output_text === 'string' && response.output_text.trim()) {
          return response.output_text;
        }
        const chunks = Array.isArray(response.output)
          ? response.output.flatMap((item) =>
              Array.isArray(item.content)
                ? item.content
                    .filter((contentItem) => contentItem?.type === 'output_text' || contentItem?.type === 'text')
                    .map((contentItem) => contentItem.text || contentItem.value || '')
                : [],
            )
          : [];
        return chunks.join('\n').trim();
      };

      const response = await this.client.responses.create({
        agent_id: agent.id,
        response_format: {
          type: 'json_schema',
          json_schema: {
            name: 'snyk_action_plan',
            schema: {
              type: 'object',
              properties: {
                steps: {
                  type: 'array',
                  items: { type: 'string' },
                  description: 'Ordered list of remediation steps',
                },
                no_action: {
                  type: 'boolean',
                  description: 'True when no remediation is needed',
                },
              },
              required: ['steps', 'no_action'],
              additionalProperties: false,
            },
          },
        },
        input: [
          {
            role: 'user',
            content: [
              {
                type: 'text',
                text: `Using this Snyk scan result JSON, produce a remediation action plan: \n${JSON.stringify(
                  scanResult,
                  null,
                  2,
                )}`,
              },
            ],
          },
        ],
      });

      const textOutput = extractText(response);
      if (!textOutput) {
        throw new Error('No text output from agent');
      }
      const parsed = JSON.parse(textOutput);
      const steps = Array.isArray(parsed.steps) ? parsed.steps.filter(Boolean) : [];
      const noAction = Boolean(parsed.no_action) || steps.length === 0;
      return { steps, noAction, source: 'openai' };
    } catch (err) {
      console.error('Failed to generate action plan with OpenAI agent:', err.message);
      return null;
    }
  }

  generateFallback(scanResult) {
    if (!scanResult || typeof scanResult !== 'object') {
      return { steps: [], noAction: true, source: 'fallback' };
    }

    const steps = [];

    if (!scanResult.repositoryAccessible) {
      steps.push('Restore repository access so automated scans can run.');
      return { steps, noAction: false, source: 'fallback' };
    }

    if (!Array.isArray(scanResult.issues)) {
      return { steps, noAction: true, source: 'fallback' };
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

      steps.push(`Resolve ${title} first${packageText}${hintText}.`);
    });

    if (Array.isArray(scanResult.licenses) && scanResult.licenses.length > 0) {
      const licensePkgs = summarizePackages(scanResult.licenses);
      steps.push(
        `Review license findings${licensePkgs ? ` for ${licensePkgs}` : ''} with legal/compliance teams.`,
      );
    }

    if (scanResult.issues.length > 0) {
      steps.push('Add automated dependency updates (Dependabot, Renovate) and enforce Snyk scans in CI.');
      steps.push('Re-run `snyk test` after applying fixes to confirm a clean report.');
      return { steps, noAction: false, source: 'fallback' };
    }

    return {
      steps: [],
      noAction: true,
      source: 'fallback',
    };
  }

  async generate(scanResult) {
    const aiPlan = await this.generateWithOpenAI(scanResult);
    if (aiPlan) {
      return aiPlan;
    }

    return this.generateFallback(scanResult);
  }
}

module.exports = { ActionPlanAgent };
