# keyleaks

One-command local audit for credential-like values in coding-agent chat histories.

Supported agents:

- Pi
- Claude Code
- Codex
- Amp
- OpenCode
- Cline / Roo Cline
- Zed

Named key detectors include OpenAI, OpenAI-compatible, Anthropic, OpenRouter, xAI, Groq, Perplexity, GitHub, GitLab, Google/Gemini, Slack, SendGrid, Telegram, Sentry, Square, Shopify, Stripe, Linear, AWS, JWT, Hugging Face, npm, PyPI, and private-key blocks, plus label-based generic token/secret detection.

By default, keyleaks scans both user prompts and assistant responses. Key values are redacted in terminal output; `--show-values` works only with `details` or `types`, writes raw values to `.keyleaks/` by default, and prints its file link.

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

Keyleaks scans both user prompts and assistant responses to detect keys exposed to your agents, whether shared directly or via environment variables.

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

## Safety

- Raw key values are not printed to the terminal; `--show-values` writes them to a JSON file and prints the file link.
- Default raw-value exports go into `.keyleaks/`, which keyleaks creates with a `.gitignore`.
- `--show-values` refuses to overwrite existing files. Pick a new `--output` path or delete the old file first.
- The package scans local history files only.
- It uses heuristic detection and is tuned to avoid code/docs/tool-result false positives.

## Requirements

- Node.js 18+
- Optional speedup: `rg` / ripgrep
- Optional for OpenCode/Zed SQLite histories: `sqlite3` CLI
