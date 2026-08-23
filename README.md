# OSV-DepGuard 🛡️

[![npm version](https://img.shields.io/npm/v/osv-depguard.svg)](https://www.npmjs.com/package/osv-depguard)
[![npm downloads](https://img.shields.io/npm/dm/osv-depguard.svg)](https://www.npmjs.com/package/osv-depguard)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js >= 18](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org/)

> Scan your Node.js dependencies for real vulnerabilities — not guesses.

**OSV-DepGuard** is a CLI tool that checks your `package-lock.json` against [OSV.dev](https://osv.dev) (Google's open source vulnerability database) to find known CVEs in your exact installed versions. Any vulnerabilities found are then passed to Claude AI, which generates a plain-English summary and a concrete fix command for each one — no hallucination, no invented data.

```bash
npm install -g osv-depguard
```

---

## How it works

| Layer | Tool | Role |
|---|---|---|
| **Scanner** | OSV.dev (Google) | 100% deterministic CVE lookup — no hallucination |
| **Source** | `package-lock.json` | Exact installed versions, not semver ranges |
| **AI** | Claude (Anthropic) | Interprets OSV data into plain English + fix commands |
| **UI** | chalk + cli-table3 | Colour-coded terminal table |

```
package-lock.json
      │
      ▼  exact installed versions
  OSV.dev /v1/querybatch  ──►  real CVE data, zero hallucination
      │
      ▼  (if vulns found)
  Anthropic API  ──────────►  plain English summary + remediation
  (no web search — interprets OSV data only, cannot fabricate vulns)
      │
      ▼
  cli-table3 + chalk  ─────►  colour-coded terminal table
```

---

## Requirements

- Node.js >= 18.0.0
- npm >= 7 (for lockfileVersion 2/3 support)
- An Anthropic API key — [get one here](https://console.anthropic.com/)

---

## Installation

### Global install (recommended — use as a CLI from any project)

```bash
npm install -g osv-depguard
```

Verify it installed correctly:

```bash
osv-depguard --version
```

### Local install (per-project, or run via npx)

```bash
# Install as a dev dependency in your project
npm install --save-dev osv-depguard

# Run via npx without installing at all
npx osv-depguard
```

### Local development (clone and run from source)

```bash
# 1. Clone the repository
git clone https://github.com/CodeAbbas/osv-depguard.git
cd osv-depguard

# 2. Install dependencies
npm install

# 3. Set up your API key (see Setup section below)

# 4. Run directly from source
node depguard.js

# 5. Or link it globally so the osv-depguard command works from anywhere
npm link
osv-depguard
```

---

## Setup

### 1. Get an Anthropic API key

Sign up at [console.anthropic.com](https://console.anthropic.com/) and create an API key.

### 2. Set up the API key

Choose whichever method fits your workflow:

#### Option A — Shell environment variable (recommended for global install)

This sets the key once and it works from any directory — no `.env` file needed.

**Mac / Linux** — add to your `~/.bashrc`, `~/.zshrc`, or `~/.profile`:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

Then reload your shell:

```bash
source ~/.bashrc   # or source ~/.zshrc
```

**Windows (PowerShell)** — add to your PowerShell profile:

```powershell
# Open your profile file (creates it if it doesn't exist)
if (!(Test-Path -Path $PROFILE)) { New-Item -ItemType File -Path $PROFILE -Force }
notepad $PROFILE

# Add this line, save, and restart the terminal
$env:ANTHROPIC_API_KEY = "sk-ant-..."
```

**Windows (System-wide)** — set it permanently via System Settings:

```
Settings → System → About → Advanced system settings
→ Environment Variables → New (under User variables)
→ Variable name: ANTHROPIC_API_KEY
→ Variable value: sk-ant-...
```

You can verify it's set by running:

```bash
# Mac / Linux
echo $ANTHROPIC_API_KEY

# Windows (PowerShell)
echo $env:ANTHROPIC_API_KEY
```

#### Option B — `.env` file (recommended for per-project or local install)

Create a `.env` file in your project root:

```
ANTHROPIC_API_KEY=sk-ant-...
```

Then gitignore it immediately:

```bash
echo ".env" >> .gitignore
```

A safe `.env.example` template is included in the repo — copy it as a starting point:

```bash
cp .env.example .env
# then fill in your real key
```

> ⚠️ **Important:** The `.env` file is read from the directory you run the command in. If you use a global install and scan different projects, use Option A instead — otherwise you'd need a `.env` in every project folder.

> ⚠️ OSV-DepGuard will warn you at startup if a `.env` file is present but not listed in `.gitignore`. Never commit your API key.

---

## Usage

Run from any directory that contains a `package-lock.json`:

```bash
# Scan the current directory
osv-depguard

# Scan a specific project directory
osv-depguard ~/projects/my-app

# Skip devDependencies
osv-depguard --no-dev

# Only show HIGH and CRITICAL vulnerabilities
osv-depguard --min-severity high

# Only show CRITICAL vulnerabilities
osv-depguard --min-severity critical

# Output raw JSON (useful for CI pipelines and scripting)
osv-depguard --json

# Show version
osv-depguard --version

# Show help
osv-depguard --help
```

### Severity levels

| Level | Colour | Description |
|---|---|---|
| `CRITICAL` | Red background | Immediate action required |
| `HIGH` | Red | Upgrade as soon as possible |
| `MEDIUM` | Yellow | Plan an upgrade |
| `LOW` | Blue | Monitor and patch in routine updates |

---

## CI Integration

Use the `--json` flag to integrate OSV-DepGuard into CI pipelines:

```bash
# List all vulnerable package names
osv-depguard --json | jq '.[].package'

# Get a count grouped by severity
osv-depguard --json | jq 'group_by(.severity) | map({severity: .[0].severity, count: length})'
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Scan completed successfully (check JSON output for vulnerabilities) |
| `1` | Scan failed — missing lockfile, API error, or invalid config |

---

## Security notes

- Never hardcode your API key — use a shell environment variable or `.env` via dotenv.
- If using a `.env` file, always add it to `.gitignore` before committing.
- OSV.dev is a public API — no key required. Only package names and exact versions are sent.
- The AI has no web search access — it only interprets verified OSV data, so it cannot fabricate vulnerabilities.

---

## Project structure

```
depguard.js          # thin executable entry point
src/
  cli.js             # argument parsing + pipeline orchestration
  lockfile.js        # package-lock.json discovery, loading, extraction
  osv.js             # OSV.dev querying + vulnerability list building
  severity.js        # severity extraction, ranking, colouring
  ai.js              # Anthropic enrichment + merge
  renderer.js        # table, summary, advisory-link rendering
  gitignore.js       # .env safety check
  constants.js       # shared constants
  utils.js           # safe JSON parsing + validation helpers
  logger.js          # standardized logging
tests/               # vitest unit tests
```

---

## Development

```bash
npm test            # run the test suite
npm run test:watch  # watch mode
npm run coverage    # run with a coverage report (≥80% enforced)
```

Network and AI calls accept an injectable `fetch`, so `osv.js` and `ai.js`
are unit-tested without hitting real endpoints.

---

## Contributing

Contributions, issues, and feature requests are welcome.

1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Commit your changes: `git commit -m 'feat: add your feature'`
4. Push to the branch: `git push origin feat/your-feature`
5. Open a Pull Request

---

## License

[MIT](https://opensource.org/licenses/MIT) © [Abbas Uddin](https://github.com/CodeAbbas)