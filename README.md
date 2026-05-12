# keyleaks

One-command local audit for credential-like values in coding-agent chat histories.

Keyleaks is designed as a local trust check: it reads supported agent history
files from your machine, detects credential-like values, and redacts raw values
from terminal output by default. It does not upload scan contents, send
telemetry, or make network calls as part of scanning.

## Supported Agents

- Pi
- Claude Code
- Codex
- Amp
- OpenCode
- Cline / Roo Cline
- Zed

Cursor, Windsurf, and standalone Gemini history stores are not currently
supported. Google/Gemini in detector output refers to detected Google or Gemini
API-key-shaped values, not a supported Gemini agent history source.

See [docs/supported-agents.md](docs/supported-agents.md) for the current local
history locations and unsupported-agent caveats.

Named key detectors include OpenAI, OpenAI-compatible, Anthropic, OpenRouter, xAI, Groq, Perplexity, GitHub, GitLab, Google/Gemini, Slack, SendGrid, Telegram, Sentry, Square, Shopify, Stripe, Linear, AWS, JWT, Hugging Face, npm, PyPI, and private-key blocks, plus label-based generic token/secret detection.

By default, keyleaks scans both user prompts and assistant responses. Key values
are redacted in terminal output; `--show-values` works only with `details` or
`types`, writes raw values to `.keyleaks/` by default, and prints its file link.

## Install

```bash
npm install -g keyleaks
```

After installation, run:

```bash
keyleaks
keyleaks details
keyleaks types
keyleaks types --show-values
keyleaks --agent codex
```

Keyleaks scans both user prompts and assistant responses to detect keys exposed
to your agents, whether shared directly or via environment variables.

Without installing globally:

```bash
npx keyleaks
```

Local development:

```bash
cd /Users/sahanp/keyleaks
npm link
keyleaks
```

## Commands

### Summary

```bash
keyleaks
keyleaks summary
keyleaks list
keyleaks --agent codex
keyleaks --role user
keyleaks --role assistant
```

The summary renders the total key leaks line and summary table.

### Month-wise breakup

```bash
keyleaks month-wise-breakup
keyleaks month-wise-breakup --agent pi
keyleaks month-wise-breakup --role assistant
```

The month-wise breakup renders per-agent leak charts grouped by user and assistant.

### Key details table

Shows Coding Agent, Role, Date, inferred Key Type, and Key Value. Values are redacted by default.

```bash
keyleaks details
keyleaks details --agent pi
keyleaks details --type anthropic
```

To export raw key values to JSON and get a file link. By default this writes into `.keyleaks/`, which contains a `.gitignore` to avoid accidental commits:

```bash
keyleaks details --show-values
keyleaks details --show-values --output ./keyleaks-details.json
```

### Key-type counts

```bash
keyleaks types
keyleaks types --show-values
keyleaks types --show-values --output ./keyleaks-types.json
keyleaks types --agent opencode
```

### JSON

```bash
keyleaks --json
keyleaks --json --inventory
keyleaks details --json
keyleaks details --show-values
keyleaks details --json --events
```

## Performance

- Native Node scanner; no Python process startup.
- Uses `rg` when available to prefilter large JSONL histories.
- Scans agents concurrently by default.
- Provides clean per-agent month-wise bar charts via `keyleaks month-wise-breakup`.
- Use `--agent <name>` for the fastest targeted scan.
- Use `--role user` or `--role assistant` to scan one side only.
- Use `--sequential` to disable concurrent scanning for debugging.

## Trust and Safety

- Scans are local-only. Keyleaks reads supported history files from your machine
  and does not upload prompts, responses, file contents, or findings.
- Keyleaks does not send telemetry and does not make network calls during scan
  or report generation.
- Raw credential values are redacted from terminal output by default.
- `--show-values` is intentionally limited to `details` and `types`; it writes
  raw values to JSON instead of printing them into the terminal.
- Default raw-value exports go into `.keyleaks/`, which keyleaks creates with a
  `.gitignore` to reduce accidental commits.
- `--show-values` refuses to overwrite existing files. Pick a new `--output`
  path or delete the old file first.
- Treat any `--show-values` export as sensitive material. Store it only
  temporarily, avoid syncing it, and delete it after remediation.
- Detection is heuristic and tuned to avoid code, docs, and tool-result false
  positives, but findings still need human review.

## If Keyleaks Finds a Credential

1. Assume the credential is exposed anywhere the scanned agent history is stored.
2. Revoke or rotate the credential with the issuing provider.
3. Replace the credential in your local environment, secrets manager, CI/CD
   settings, and any deployed services that use it.
4. Remove the leaked value from prompts, notes, shell history, docs, or other
   local files where it was copied.
5. Re-run `keyleaks` to confirm the old value no longer appears in supported
   agent histories.
6. If the value was committed, pushed, or shared externally, follow the
   provider's incident guidance and audit recent usage logs.

## Requirements

- Node.js 18+
- Optional speedup: `rg` / ripgrep
- Optional for OpenCode/Zed SQLite histories: `sqlite3` CLI
