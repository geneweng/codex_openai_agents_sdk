# Snyk Security Scanner

One-page web app for running Snyk security scans on any public GitHub repository.

## Prerequisites

- Node.js 18+
- A valid [`SNYK_TOKEN`](https://docs.snyk.io/snyk-cli/authenticate-the-cli-with-your-account) available to the backend environment
- (Optional) An `OPENAI_API_KEY` with access to the [OpenAI Agents API](https://openai.com/) to generate AI remediation plans
- `git` installed on the server running the backend

## Getting Started

Install dependencies for the backend and frontend:

```bash
npm install
npm install --prefix client
```

### Development

Start the backend API:

```bash
SNYK_TOKEN=your-token OPENAI_API_KEY=sk-... npm run dev
```

In a second terminal, start the Vite dev server (will proxy API calls via CORS):

```bash
npm run dev --prefix client
```

By default the frontend expects the API at `http://localhost:4000`. If you run the backend on a different origin, set `VITE_API_BASE` in `client/.env`:

```ini
VITE_API_BASE=https://your-api-host
```

### Production Build

Generate the frontend production bundle and serve it directly from the backend:

```bash
npm run build --prefix client
SNYK_TOKEN=your-token OPENAI_API_KEY=sk-... NODE_ENV=production npm start
```

When a `client/dist` folder is present the Express app serves the static files and falls back to the SPA for non-API routes.

## How It Works

1. A repo URL is submitted from the UI.
2. The backend clones the repository into a temporary directory.
3. The backend runs `snyk test --json` in that directory (using the token provided via environment var) and converts the response to a friendly shape.
4. The frontend displays severity summaries, detailed findings, license issues, and an agent-generated action plan (falls back to heuristics if the OpenAI API is unavailable).

Cleanup is handled automatically after every scan, even if the clone or Snyk run fails.
