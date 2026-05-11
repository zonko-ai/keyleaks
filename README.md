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

By default, key values are redacted. Use `--show-values` only when your terminal output is private.

## Install / run

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

### Summary

```bash
keyleaks
keyleaks summary
keyleaks list
keyleaks --agent codex
```

Example:

```text
pi:
messages: 6
credential occurrences: 14
distinct occurrences: 14

claude:
messages: 72
credential occurrences: 78
distinct occurrences: 65

codex:
messages: 23
credential occurrences: 30
distinct occurrences: 24
```

### Details

Shows Coding Agent, Date, inferred Key Type, and Key Value. Values are redacted by default.

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
- Use `--agent <name>` for the fastest targeted scan.
- Use `--sequential` to disable concurrent scanning for debugging.

## Safety

- No key values are printed unless `--show-values` is passed.
- The package scans local history files only.
- It uses heuristic detection and is tuned to avoid code/docs/tool-result false positives.

## Requirements

- Node.js 18+
- Optional speedup: `rg` / ripgrep
- Optional for OpenCode/Zed SQLite histories: `sqlite3` CLI
