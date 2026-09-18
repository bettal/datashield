# DataShield

Data-leak auditor for AI agent configurations (Claude Code, OpenCode, MCP servers, hooks, agents).
Finds secrets, personal data (RF + international), credentials, keys, and one-time codes.

## Build & Test

```bash
npm run build      # tsc + tsup → dist/
npm test           # vitest (912 tests)
npm run dev        # tsx watch mode
```

## Architecture

```
src/
  index.ts          # CLI entry (commander)
  types.ts          # Core types + Zod schemas
  scanner/
    discovery.ts    # File discovery (CLAUDE.md, settings.json, mcp.json, agents/, etc.)
    index.ts        # Orchestrates discovery → rules → sorted findings
  config/
    scan-config.ts  # Config-driven scan configuration (files, dirs, extensions, toggles)
  detection/
    entropy.ts      # Shannon entropy + high-entropy secret heuristic
    mask.ts         # Safe redaction (never leaks short values)
    validators.ts   # Luhn, IBAN mod-97, СНИЛС/ИНН/ОГРН checksums, SSN plausibility
  rules/
    index.ts        # Barrel export of all rule modules
    helpers.ts      # Shared match/line/file/example-suppression helpers
    secrets.ts      # 13 rules — vendor keys/tokens, generic assignments, high-entropy, env exposure, webhooks, private keys, base64, internal IPs
    pii.ts          # 11 rules — email, phones (RF/intl), СНИЛС, ИНН, ОГРН, passport/license, cards, IBAN, BIK/account, SSN
    credentials.ts  # 3 rules — login/password pairs, HTTP Basic auth, weak passwords
    codes.ts        # 3 rules — OTP/2FA, recovery/backup codes, PINs
    permissions.ts  # 10 rules — allow/deny analysis, dangerous flags, destructive git, mutable tools, sensitive paths, network access
    hooks.ts        # 34 rules — injection, exfiltration, persistence, container escape, clipboard, log tampering, reverse shells
    mcp.ts          # 23 rules — risky servers, env override, npx supply chain, auto-approve, timeout, bind-all, CORS
    agents.ts       # 25 rules — tool restrictions, prompt injection, reflection attacks, output manipulation, social engineering
  reporter/
    score.ts        # Scoring engine (severity deductions, grade A-F, category breakdown)
    terminal.ts     # Colored terminal output
    json.ts         # JSON + Markdown report formats
    index.ts        # Format dispatcher
  opus/
    prompts.ts      # System prompts for Attacker/Defender/Auditor
    pipeline.ts     # Claude Opus three-agent adversarial pipeline
    render.ts       # Opus analysis terminal + markdown rendering
    index.ts        # Pipeline entry point
  miniclaw/
    types.ts        # Core types (immutable, readonly)
    sandbox.ts      # Sandbox lifecycle + path validation
    router.ts       # Prompt sanitization + output filtering
    tools.ts        # Whitelist-based tool authorization
    server.ts       # HTTP server with rate limiting + CORS
    dashboard.tsx   # React dashboard component
    index.ts        # Entry point + startMiniClaw()
```

## Key Patterns

- **Rules**: Each rule module exports `ReadonlyArray<Rule>`. Each `Rule` has `check(file: ConfigFile): ReadonlyArray<Finding>`.
- **Immutability**: All arrays typed as `ReadonlyArray`, all interfaces use `readonly` fields.
- **No RegExp .prototype methods**: Use `String.matchAll()` via `findAllMatches()` helper to avoid security hook conflicts.
- **False positive prevention**: `parsePermissionLists()` JSON-parses settings to check only the allow array. Negation-aware context checking downgrades prohibitive mentions to `info`.

## Severity Scoring

| Severity | Deduction | Example |
|----------|-----------|---------|
| critical | -25 | Hardcoded API key, Bash(*) |
| high     | -15 | Shell MCP server, no deny list |
| medium   | -5  | Unrestricted curl, missing denials |
| low      | -2  | No model specified in agent |
| info     | 0   | Missing description, good practice |

Grades: A (>=90), B (>=75), C (>=60), D (>=40), F (<40)

## CLI

```bash
datashield scan [path]              # Static analysis
datashield scan --opus              # + Claude Opus adversarial pipeline
datashield scan --format json|md    # Output format
datashield scan --fix               # Show auto-fix suggestions
datashield miniclaw start           # Launch MiniClaw secure agent server
datashield miniclaw start --port N  # Custom port
```

## Scan configuration (config-driven discovery)

Discovery is config-driven: every scan resolves the effective `ScanConfig`
before reading any file. Resolution order (low → high priority):
`DEFAULT_SCAN_CONFIG` → `~/.config/datashield/scan.json` →
`<scanRoot>/datashield.config.json` → `$DATASHIELD_SCAN_CONFIG`.
The config is re-read on every scan, so it can change at runtime.
See `src/config/scan-config.ts`. `genericScan` (recursive arbitrary
markdown/text/env/config discovery) is on by default.

## Testing

Tests in `tests/` mirror `src/` structure. Use `makeFinding()`, `makeSettings()`, etc. helper factories.
Run specific suite: `npx vitest run tests/rules/mcp.test.ts`

## Conventions

- TypeScript strict mode, ESM modules
- No mutation, no `any`, no `console.log` in src
- Zod for config validation at boundaries
- Conventional commits: feat/fix/test/refactor/docs
