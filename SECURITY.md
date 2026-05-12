# Security

## Local-Only Scanning

Keyleaks scans supported coding-agent history files on your machine. It does not
upload prompts, responses, file contents, findings, or raw credential values.
Scan and report generation do not make network calls and do not send telemetry.

## Redaction Defaults

Raw credential values are redacted from terminal output by default. Summary,
month-wise, detail, type-count, JSON, and event outputs are intended to avoid
printing the secret itself unless you explicitly request raw values.

`--show-values` is available only for `details` and `types`. It writes raw
credential values to a JSON file instead of printing them in the terminal, uses
`.keyleaks/` by default, and refuses to overwrite an existing output file.
Treat any `--show-values` file as sensitive: keep it local, avoid syncing it,
and delete it after you finish remediation.

## If Keyleaks Finds a Leaked Credential

1. Assume the credential is compromised anywhere the scanned agent history is
   stored.
2. Revoke or rotate the credential with the issuing provider.
3. Update every place that uses it, including local `.env` files, shell profile
   exports, secrets managers, CI/CD variables, and deployed service settings.
4. Remove the old value from prompts, notes, docs, shell history, and any other
   local file where it was copied.
5. Re-run `keyleaks` to verify the old value no longer appears in supported
   agent histories.
6. If the credential was committed, pushed, pasted into third-party systems, or
   used from an unexpected location, review provider audit logs and follow the
   provider's incident-response guidance.

## Supported and Unsupported Agents

Current supported agent history sources are Pi, Claude Code, Codex, Amp,
OpenCode, Cline / Roo Cline, and Zed. Cursor, Windsurf, and standalone Gemini
history stores are not currently supported.

Google/Gemini detector findings mean keyleaks found a Google or Gemini
API-key-shaped value in a supported history source. They do not mean keyleaks
scanned Gemini agent history.

See [docs/supported-agents.md](docs/supported-agents.md) for the current
coverage details.

## Reporting Security Issues

Please report security issues privately instead of opening a public issue with
credential values or exploit details. Use GitHub private vulnerability reporting
after the repository is public; until then, email the npm package maintainer
listed for `keyleaks`.

Include the keyleaks version, command, operating system, and whether
`--show-values` was used. Do not include raw secrets; use redacted examples
whenever possible.
