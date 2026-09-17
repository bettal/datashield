<div align="center">

# DataShield

**Data-leak auditor for AI agent configurations**

Scans AI agent setups (OpenCode, Claude Code, Codex, Gemini, MCP servers, hooks, skills, agents)<br/>
for **secrets, personal data, credentials, keys, and one-time codes** — plus the inherited<br/>
agent-configuration security checks (permissions, hook injection, MCP risk, prompt injection).

[![tests](https://img.shields.io/badge/tests-passing-brightgreen)]()
[![coverage](https://img.shields.io/badge/coverage-v8-blue)]()
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

[Quick Start](#quick-start) · [What It Finds](#what-it-finds) · [Config-Driven Discovery](#config-driven-discovery) · [Development](#development) · [Roadmap](#roadmap) · [Attribution](#attribution)

</div>

---

## Why

Agent configurations, skills, prompts, notes, and `.env` files routinely end up holding
API keys, tokens, personal data, logins, and recovery codes. These files are copied between
machines, committed to repos, pasted into prompts, and installed from community marketplaces.
DataShield reads a configuration first, then walks the surfaces it describes — recursively —
and flags data leaks before they become incidents.

DataShield is a hard fork of [AgentShield](https://github.com/affaan-m/agentshield) (MIT).
It keeps AgentShield's rule engine and agent-security checks, and extends detection toward
data-leak classes that upstream does not cover.

## What It Finds

| Class | Examples |
|---|---|
| Secret data | API keys (Anthropic, OpenAI, xAI, AWS, Google, Stripe, …), tokens, bearer tokens, DB connection strings, private key material, webhooks |
| Personal data | RF: СНИЛС, ИНН, ОГРН/ОГРНИП, паспорт РФ, водительское, БИК/р/с, +7 phones. Intl: email, phone (E.164), SSN, IBAN, credit cards (Luhn) |
| Credentials | login/password pairs, `Authorization: Basic`, `.env` credentials, credential-file references (`.aws/credentials`, `.netrc`, `.kube/config`, …) |
| Keys | PEM/PGP private keys, cloud service-account keys, signing keys |
| One-time codes | OTP/TOTP/2FA, verification codes, recovery/backup codes, PINs |
| Inherited | permission misconfigs, hook injection, MCP server risk, agent prompt-injection surface |

> Detection classes marked *in progress* are being implemented in the roadmap below.
> The inherited agent-security engine is fully present and tested.

## Quick Start

DataShield is not published to npm yet; run it from source:

```bash
git clone https://github.com/bettal/datashield.git
cd datashield
npm install
npm run build

# Scan a config directory
node dist/index.js scan --path ~/.config/opencode

# JSON report for CI
node dist/index.js scan --path . --format json
```

Or in watch mode during development:

```bash
npm run dev -- scan --path ~/.config/opencode
```

DataShield auto-discovers `./.claude`, `~/.claude`, or the current directory when `--path`
is omitted. Discovery skips generated directories (`node_modules`, build output, `.dmux`)
so transient copies do not duplicate findings.

## Config-Driven Discovery

**The first step of every scan is reading the scan configuration.** Discovery is driven
entirely by it, and it is re-read on every scan — so an operator or a running agent can
change it between runs and the next scan picks it up.

Resolution order (low → high priority):

1. built-in defaults (`src/config/scan-config.ts`)
2. `~/.config/datashield/scan.json` (global)
3. `<scanRoot>/datashield.config.json` (project)
4. `$DATASHIELD_SCAN_CONFIG` (explicit override)

Arrays merge additively (new directories/subdirectories/files extend the set); scalar
toggles are overridden. Invalid JSON or schema violations fail closed.

Example project override:

```json
{
  "version": 1,
  "ignoredDirs": ["node_modules", "dist"],
  "genericScan": true,
  "genericScanExamples": false,
  "directories": [
    { "path": "leaks", "type": "text-generic", "recursive": true }
  ],
  "extensions": [
    { "extension": ".pem", "type": "text-generic" }
  ]
}
```

### Discovery model

- **Exact files** (`files`): `CLAUDE.md`, `AGENTS.md`, `settings.json`, `opencode.json`, …
- **Directories** (`directories`): `skills/`, `agents/`, `commands/`, `.opencode/*`, …
  with optional `recursive: true` to walk nested per-item folders.
- **Generic scan** (`genericScan`): recursively classifies arbitrary files by extension
  (`.md`, `.txt`, `.env`, `.json`, `.yaml`, `.toml`, `.ini`, …). Example-like subtrees
  (`docs/`, `examples/`, `tutorials/`, …) are skipped unless `genericScanExamples` is on.

## Development

```bash
npm install
npm run build       # tsup → dist/
npm test            # vitest, full suite
npm run typecheck   # tsc --noEmit
npm run lint        # eslint src/
```

Run a single suite:

```bash
npx vitest run tests/rules/secrets.test.ts
npx vitest run tests/config/scan-config.test.ts
```

Rules are modules exporting `ReadonlyArray<Rule>`; each rule has
`check(file, allFiles)`. New detection modules live in `src/rules/` and are registered in
`src/rules/index.ts`. The scan configuration lives in `src/config/scan-config.ts`.

## Roadmap

| Phase | Scope | Status |
|---|---|---|
| 0 | Config-driven discovery, recursion, generic scan, rebrand | done |
| 1 | Secret detection: provider catalog + high-entropy generic secrets | planned |
| 2 | PII module (RF + international) with validators (Luhn, INN/SNILS checksum) | planned |
| 3 | Credentials module (login/password pairs, Basic auth, `.env`) | planned |
| 4 | One-time codes module (OTP/TOTP/2FA/recovery/PIN) | planned |
| 5 | Scoring/reporting tuning for new categories, rebrand cleanup | planned |

## Attribution

DataShield is a fork of [AgentShield](https://github.com/affaan-m/agentshield) by
[affaan-m](https://github.com/affaan-m), used under the MIT License. The original rule
engine, agent-security checks, and much of the infrastructure originate there. See
[`LICENSE`](./LICENSE) and [`CHANGELOG.md`](./CHANGELOG.md).

## License

MIT
