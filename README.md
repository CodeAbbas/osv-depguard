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

### 2. Add it to a `.env` file in your project root

```bash
echo "ANTHROPIC_API_KEY=sk-ant-..." > .env
```

Or create the file manually:

```
ANTHROPIC_API_KEY=sk-ant-...
```

### 3. Gitignore it immediately

```bash
echo ".env" >> .gitignore
```

> ⚠️ OSV-DepGuard will warn you at startup if `.env` is missing from `.gitignore`. Never commit your API key.

A safe `.env.example` template is included in the repo — copy it as a starting point:

```bash
cp .env.example .env
# then fill in your real key
```

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

- Never hardcode your API key — always use `.env` via dotenv.
- Always add `.env` to `.gitignore` before your first commit.
- OSV.dev is a public API — no key required. Only package names and exact versions are sent.
- The AI has no web search access — it only interprets verified OSV data, so it cannot fabricate vulnerabilities.

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
