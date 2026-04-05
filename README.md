# OSV-DepGuard 🛡️

**Deterministic Hybrid Vulnerability Scanner for Node.js projects.**

| Layer | Tool | Role |
|---|---|---|
| **Scanner** | OSV.dev (Google) | 100% deterministic CVE lookup — no hallucination |
| **Source** | `package-lock.json` | Exact installed versions, not semver ranges |
| **AI** | Claude (Anthropic) | Interprets OSV data into plain English + fix commands |
| **UI** | chalk + cli-table3 | Colour-coded terminal table |

## Setup

### 1. Install dependencies
```bash
npm install
```

### 2. API key — add to .env
```
ANTHROPIC_API_KEY=sk-ant-...
```

### IMPORTANT — do this immediately:
```bash
echo ".env" >> .gitignore
```

DepGuard will warn you at startup if .env is missing from .gitignore.

## Usage

```bash
node depguard.js                        # scan ./package-lock.json
node depguard.js ~/projects/my-app      # scan a specific directory
node depguard.js --no-dev               # skip devDependencies
node depguard.js --min-severity high    # only HIGH + CRITICAL
node depguard.js --json                 # raw JSON output for CI
```

### Install globally
```bash
npm install -g .
depguard
```

## How it works

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

## Security notes

- Never hardcode your API key. Use `.env` via dotenv.
- Always add `.env` to `.gitignore` before your first commit.
- OSV.dev is a public API — no key required, only package names + versions are sent.

## CI integration

```bash
node depguard.js --json --min-severity high | jq '.[].package'
```

Exit code `1` = scan failed (missing lockfile, API error). Exit code `0` = completed (check JSON for vulns).