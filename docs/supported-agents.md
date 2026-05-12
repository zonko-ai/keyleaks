# Supported Agents

Keyleaks scans local history files for these coding-agent surfaces:

| Agent | Local history source |
| --- | --- |
| Pi | `~/.pi/agent/sessions` |
| Claude Code | `~/.claude/history.jsonl`, `~/.claude/projects`, and `~/.claude/paste-cache` |
| Codex | `~/.codex/history.jsonl`, `~/.codex/sessions`, and `~/.codex/archived_sessions` |
| Amp | Amp thread storage under the user's local data directory |
| OpenCode | OpenCode SQLite history database |
| Cline / Roo Cline | Cline/Roo Cline extension and standalone task history |
| Zed | Zed conversation files and local Zed database files |

## Unsupported Agents

Cursor, Windsurf, and standalone Gemini history stores are not currently
supported. Keyleaks may detect Google/Gemini API-key-shaped values when those
values appear inside a supported agent's history, but that detector label is not
the same thing as scanning Gemini agent history.

## Local-Only Behavior

Keyleaks reads local files and databases from the current machine. It does not
upload history, send telemetry, or make network calls during scanning. Use
`--agent <name>` to restrict scanning to one supported source when you want a
narrower local audit.
