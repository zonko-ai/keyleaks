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

Named key detectors include OpenAI/OpenRouter, Anthropic, GitHub, Google/Gemini, Slack, Square, Shopify, Stripe, Linear, AWS, JWT, Hugging Face, npm, PyPI, and private-key blocks, plus label-based generic token/secret detection.

By default, keyleaks scans both user prompts and assistant responses. Key values are redacted unless `--show-values` is passed.

## Install

```bash
npm install -g keyleaks
```

After installation, run:

```bash
keyleaks
keyleaks details
keyleaks types
keyleaks --agent codex
```

Without installing globally:

```bash
npx keyleaks
```

Local development:

```bash
cd /Users/sahanp/chat-secret-audit
npm link
keyleaks
```

## Commands

### Summary and charts

```bash
keyleaks
keyleaks summary
keyleaks list
keyleaks --agent codex
keyleaks --role user
keyleaks --role assistant
```

The summary renders as tables and per-agent month-wise leak charts.

### Key details table

Shows Coding Agent, Role, Date, inferred Key Type, and Key Value. Values are redacted by default.

```bash
keyleaks details
keyleaks details --agent pi
keyleaks details --type anthropic
```

To show raw key values:

```bash
keyleaks details --show-values
```

### Key-type counts

```bash
keyleaks types
keyleaks types --agent opencode
```

### JSON

```bash
keyleaks --json
keyleaks --json --inventory
keyleaks details --json
keyleaks details --json --show-values
keyleaks details --json --events
```

## Performance

- Native Node scanner; no Python process startup.
- Uses `rg` when available to prefilter large JSONL histories.
- Scans agents concurrently by default.
- Includes clean per-agent month-wise bar charts in summary output.
- Use `--agent <name>` for the fastest targeted scan.
- Use `--role user` or `--role assistant` to scan one side only.
- Use `--sequential` to disable concurrent scanning for debugging.

## Safety

- No key values are printed unless `--show-values` is passed.
- The package scans local history files only.
- It uses heuristic detection and is tuned to avoid code/docs/tool-result false positives.

## Requirements

- Node.js 18+
- Optional speedup: `rg` / ripgrep
- Optional for OpenCode/Zed SQLite histories: `sqlite3` CLI
