#!/usr/bin/env node
import { chmodSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import {
  ALL_AGENT_KEYS,
  DEFAULT_ROLES,
  TOOL_LABELS,
  buildReport,
} from "../lib/native-audit.js";

const toolLabels = TOOL_LABELS;
const displayLabels = {
  pi_agent: "Pi",
  claude_code: "Claude",
  codex: "Codex",
  amp: "Amp",
  opencode: "OpenCode",
  cline: "Cline",
  zed: "Zed",
};
const agentKeys = Object.fromEntries(
  Object.entries(toolLabels).map(([key, label]) => [label, key]),
);
const agentList = Object.values(toolLabels).join("|");
const BAR_WIDTH = 34;
const FORCE_COLOR = ["1", "true", "always"].includes(
  String(process.env.KEYLEAKS_FORCE_COLOR || process.env.FORCE_COLOR || "")
    .toLowerCase()
    .trim(),
);
const USE_COLOR =
  !process.env.NO_COLOR &&
  (FORCE_COLOR ||
    (Boolean(process.stdout.isTTY) && process.env.TERM !== "dumb"));
const BLUE = USE_COLOR ? "\x1b[34m" : "";
const BOLD = USE_COLOR ? "\x1b[1m" : "";
const DIM = USE_COLOR ? "\x1b[2m" : "";
const CYAN = USE_COLOR ? "\x1b[36m" : "";
const MAGENTA = USE_COLOR ? "\x1b[35m" : "";
const GREEN = USE_COLOR ? "\x1b[32m" : "";
const YELLOW = USE_COLOR ? "\x1b[33m" : "";
const AMBER = USE_COLOR ? "\x1b[38;5;208m" : "";
const LIGHT_RED = USE_COLOR ? "\x1b[38;5;203m" : "";
const RED_BOLD = USE_COLOR ? "\x1b[1;31m" : "";
const GRAY = USE_COLOR ? "\x1b[90m" : "";
const RESET = USE_COLOR ? "\x1b[0m" : "";
const ANSI_RE = /\x1b\[[0-9;]*m/g;
const SCAN_LOADER_MESSAGES = [
  "scanning user and assistant responses...",
  "agents access keys through envs..",
];

function blue(value) {
  return `${BLUE}${value}${RESET}`;
}

function redBold(value) {
  return `${RED_BOLD}${value}${RESET}`;
}

function lightRed(value) {
  return `${RED_BOLD}${value}${RESET}`;
}

function cyan(value) {
  return `${CYAN}${value}${RESET}`;
}

function green(value) {
  return `${GREEN}${value}${RESET}`;
}

function amber(value) {
  return `${AMBER}${value}${RESET}`;
}

function yellow(value) {
  return `${YELLOW}${value}${RESET}`;
}

function magenta(value) {
  return `${MAGENTA}${value}${RESET}`;
}

function gray(value) {
  return `${GRAY}${value}${RESET}`;
}

function bold(value) {
  return `${BOLD}${value}${RESET}`;
}

function dim(value) {
  return `${DIM}${value}${RESET}`;
}

function rule(width = 72) {
  return dim("─".repeat(width));
}

function tableHeader(value) {
  return bold(cyan(value));
}

function agentColor(agentLabel) {
  const colors = [blue, cyan, magenta, green, amber, yellow];
  let sum = 0;
  for (const char of String(agentLabel)) sum += char.charCodeAt(0);
  return colors[sum % colors.length](agentLabel);
}

function severityColor(value) {
  return lightRed(value);
}

function roleColor(role) {
  if (role === "user") return cyan(role);
  if (role === "assistant") return magenta(role);
  return role;
}

function keyTypeColor(keyType) {
  const value = String(keyType || "");
  if (/private|secret|password|token|key/i.test(value)) return redBold(value);
  if (/aws|github|gitlab|stripe|slack|npm|pypi/i.test(value))
    return amber(value);
  if (/openai|anthropic|gemini|openrouter|xai|groq|perplexity/i.test(value))
    return magenta(value);
  return yellow(value);
}

function redactColor(value) {
  return String(value || "").includes("REDACTED")
    ? gray(value)
    : redBold(value);
}

function visibleLength(value) {
  return String(value ?? "").replace(ANSI_RE, "").length;
}

function padVisible(value, width) {
  const text = String(value ?? "");
  return text + " ".repeat(Math.max(0, width - visibleLength(text)));
}

function printHelp() {
  console.log(`keyleaks

Usage:
  keyleaks                         Structured summary
  keyleaks summary                 Structured summary
  keyleaks month-wise-breakup      Per-agent month-wise leak charts
  keyleaks details                 Detail table with redacted values
  keyleaks details --show-values   Write raw key details JSON and print file link
  keyleaks types                   Counts by inferred key type
  keyleaks types --show-values     Write grouped key values JSON and print file link
  keyleaks --json                  Raw JSON summary
  keyleaks details --json          Raw JSON with credential_details

Options:
  --agent ${agentList}
                                  Scan/filter one agent only
  --type <text>                    Filter detail output by key type text
  --role user|assistant|all        Scan one role or both roles; default: all
  --events                         Include redacted event metadata in JSON
  --inventory                      Include file inventory in JSON
  --show-values                    Write raw credential values to a JSON file
  --output <file>                  File path for --show-values JSON output
                                  Refuses to overwrite existing files
  --sequential                     Disable default concurrent scanning

Safety:
  key values are redacted by default. Use --show-values only when your terminal
  output is private.`);
}

function useScanLoader({ json }) {
  return (
    !json &&
    (Boolean(process.stderr.isTTY) || process.env.KEYLEAKS_FORCE_LOADER === "1")
  );
}

function startScanLoader(options) {
  if (!useScanLoader(options)) return () => {};

  let messageIndex = 0;
  let dotCount = 0;
  let rendered = false;
  const render = () => {
    dotCount = (dotCount + 1) % 4;
    const message =
      SCAN_LOADER_MESSAGES[messageIndex % SCAN_LOADER_MESSAGES.length];
    const dots = ".".repeat(dotCount || 1);
    process.stderr.write(`\r${message}${dots}\x1b[K`);
    rendered = true;
  };

  render();
  const timer = setInterval(() => {
    messageIndex++;
    render();
  }, 1500);
  timer.unref?.();

  return () => {
    clearInterval(timer);
    if (rendered) process.stderr.write("\r\x1b[K");
  };
}

function reportKeys(report) {
  return ALL_AGENT_KEYS.filter((key) => report[key]);
}

function displayAgent(agentLabel) {
  const key = agentKeys[agentLabel];
  return displayLabels[key] || agentLabel;
}

function printList(report) {
  printHeader(report);
  printTotalKeyLeaks(report);
  printSummaryTable(report);
  printCommandHints();
}

function printMonthWiseBreakup(report) {
  printHeader(report);
  printAgentMonthlyGraphs(report);
}

function detailRows(report) {
  return reportKeys(report).flatMap(
    (key) => report[key].credential_details || [],
  );
}

function parseFlagValue(args, name) {
  const index = args.indexOf(name);
  if (index === -1) return undefined;
  return args[index + 1];
}

function parseCommand(args) {
  const valueFlags = new Set(["--agent", "--type", "--role", "--output"]);
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (valueFlags.has(arg)) {
      i++;
      continue;
    }
    if (!arg.startsWith("-")) return arg;
  }
  return "summary";
}

function applyFilters(rows, args) {
  const agent = parseFlagValue(args, "--agent");
  const type = parseFlagValue(args, "--type");
  return rows.filter((row) => {
    if (agent && row.coding_agent !== agent) return false;
    if (
      type &&
      !String(row.key_type).toLowerCase().includes(type.toLowerCase())
    )
      return false;
    return true;
  });
}

function table(rows, columns) {
  const widths = columns.map((col) =>
    Math.max(
      visibleLength(col.header),
      ...rows.map((row) => visibleLength(row[col.key])),
    ),
  );
  const line = columns
    .map((col, i) => padVisible(tableHeader(col.header), widths[i]))
    .join("  ");
  const divider = dim(widths.map((width) => "─".repeat(width)).join("  "));
  const body = rows.flatMap((row) => {
    const rendered = columns
      .map((col, i) => padVisible(row[col.key], widths[i]))
      .join("  ");
    return row.separatorBefore ? [divider, rendered] : [rendered];
  });
  return [line, divider, ...body].join("\n");
}

function printHeader() {
  console.log(rule());
  console.log(
    `${redBold("KEYLEAKS")} ${gray("—")} ${bold("Credential Leak Report")}`,
  );
  console.log(rule());
}

function activeReportKeys(report) {
  return reportKeys(report).filter(
    (key) => (report[key]?.messages_with_credentials || 0) > 0,
  );
}

function scannedReportKeys(report) {
  return reportKeys(report).filter((key) => (report[key]?.records_scanned || 0) > 0);
}

function totalKeyLeaks(report) {
  if (Number.isFinite(report.credential_occurrences)) return report.credential_occurrences;
  return activeReportKeys(report).reduce(
    (sum, key) => sum + (report[key]?.credential_occurrences || 0),
    0,
  );
}

function printTotalKeyLeaks(report) {
  console.log(
    `\n${redBold("Total Key Leaks to Agents:")} ${severityColor(
      totalKeyLeaks(report),
    )}`,
  );
}

function totalSummaryRow(rows, report) {
  return {
    separatorBefore: true,
    Agent: bold("Total"),
    "Messages Scanned": report.records_scanned ?? rows.reduce((sum, row) => sum + row["Messages Scanned"], 0),
    "Leak Messages": report.messages_with_credentials ?? rows.reduce((sum, row) => sum + row["Leak Messages"], 0),
    "Key Leaks": report.credential_occurrences ?? rows.reduce((sum, row) => sum + row["Key Leaks"], 0),
    "Distinct Leaks": report.distinct_credential_values ?? rows.reduce((sum, row) => sum + row["Distinct Leaks"], 0),
  };
}

function printSummaryTable(report) {
  const rows = scannedReportKeys(report).map((key) => {
    const data = report[key];
    return {
      Agent: agentColor(displayLabels[key] || toolLabels[key]),
      "Messages Scanned": data.records_scanned,
      "Leak Messages": data.messages_with_credentials,
      "Key Leaks": data.credential_occurrences,
      "Distinct Leaks": data.distinct_credential_values,
    };
  });
  if (!rows.length) {
    console.log(`\n${cyan("SUMMARY")}`);
    console.log(rule());
    console.log(green("(no credential leaks found)"));
    return;
  }
  console.log(`\n${cyan("SUMMARY")}`);
  console.log(rule());
  const displayRows = [...rows, totalSummaryRow(rows, report)].map((row) => ({
    ...row,
    "Messages Scanned": severityColor(row["Messages Scanned"]),
    "Leak Messages": severityColor(row["Leak Messages"]),
    "Key Leaks": severityColor(row["Key Leaks"]),
    "Distinct Leaks": severityColor(row["Distinct Leaks"]),
  }));
  console.log(
    table(displayRows, [
      { key: "Agent", header: "Agent" },
      { key: "Messages Scanned", header: "Messages Scanned" },
      { key: "Leak Messages", header: "Leak Messages" },
      { key: "Key Leaks", header: "Key Leaks" },
      { key: "Distinct Leaks", header: "Distinct Leaks" },
    ]),
  );
  console.log(dim("Distinct Leaks total is deduplicated across agents."));
}

function stackedBar(user, assistant, maxTotal) {
  const total = user + assistant;
  if (!total) return " ".repeat(BAR_WIDTH);
  const minWidth = (user > 0 ? 1 : 0) + (assistant > 0 ? 1 : 0);
  const width = Math.max(minWidth, Math.round((total / maxTotal) * BAR_WIDTH));
  let userWidth = Math.round((user / total) * width);
  let assistantWidth = width - userWidth;
  if (user > 0 && userWidth === 0) userWidth = 1;
  if (assistant > 0 && assistantWidth === 0) assistantWidth = 1;
  return `${cyan("█".repeat(userWidth))}${magenta(
    "░".repeat(assistantWidth),
  )}${" ".repeat(Math.max(0, BAR_WIDTH - width))}`;
}

function monthlyRowsFor(data) {
  return (data.monthly_breakdown || [])
    .map((row) => {
      const user = row.credential_occurrences?.user || 0;
      const assistant = row.credential_occurrences?.assistant || 0;
      return { month: row.month, user, assistant, total: user + assistant };
    })
    .filter((row) => row.total > 0);
}

function printAgentMonthlyGraphs(report) {
  console.log(`\n${cyan("CREDENTIAL LEAKS BY MONTH")}`);
  console.log(rule());
  console.log(`Legend: ${cyan("█ user")}  ${magenta("░ assistant")}`);

  for (const key of activeReportKeys(report)) {
    const data = report[key];
    const rows = monthlyRowsFor(data);
    console.log(
      `\n${agentColor((displayLabels[key] || toolLabels[key]).toUpperCase())}`,
    );
    console.log(rule(48));
    if (!rows.length) continue;
    const maxTotal = Math.max(...rows.map((row) => row.total));
    const rendered = rows.map((row) => ({
      Month: row.month,
      User: severityColor(row.user),
      Assistant: severityColor(row.assistant),
      Total: severityColor(row.total),
      Bar: stackedBar(row.user, row.assistant, maxTotal),
    }));
    const totalUser = rows.reduce((sum, row) => sum + row.user, 0);
    const totalAssistant = rows.reduce((sum, row) => sum + row.assistant, 0);
    rendered.push({
      separatorBefore: true,
      Month: bold("Total"),
      User: severityColor(totalUser),
      Assistant: severityColor(totalAssistant),
      Total: severityColor(totalUser + totalAssistant),
      Bar: stackedBar(totalUser, totalAssistant, totalUser + totalAssistant),
    });
    console.log(
      table(rendered, [
        { key: "Month", header: "Month" },
        { key: "User", header: "User" },
        { key: "Assistant", header: "Assistant" },
        { key: "Total", header: "Total" },
        { key: "Bar", header: "Bar" },
      ]),
    );
  }
}

function printCommandHints() {
  console.log(`\n${cyan("COMMANDS")}`);
  console.log(rule());
  console.log(
    table(
      [
        {
          Command: redBold("npx keyleaks month-wise-breakup"),
          Purpose: "Show per-agent month-wise leak charts",
        },
        {
          Command: yellow("npx keyleaks details --show-values"),
          Purpose: "Write raw key details JSON and print file link",
        },
        {
          Command: cyan("npx keyleaks types"),
          Purpose: "Group key leaks by inferred key type",
        },
      ],
      [
        { key: "Command", header: "Command" },
        { key: "Purpose", header: "Purpose" },
      ],
    ),
  );
}

function detailTableRows(report, args, { color = true } = {}) {
  return applyFilters(detailRows(report), args).map((row) => ({
    agent: color
      ? agentColor(displayAgent(row.coding_agent))
      : displayAgent(row.coding_agent),
    agent_id: row.coding_agent,
    role: color ? roleColor(row.role) : row.role,
    date: row.date || "unknown",
    key_type: color ? keyTypeColor(row.key_type) : row.key_type,
    key_value: color ? redactColor(row.key_value) : row.key_value,
    detector: row.detector,
    source: row.source,
    loc: row.loc,
  }));
}

function printDetails(report, args) {
  const rows = detailTableRows(report, args);
  if (!rows.length) {
    console.log("No matching credential details found.");
    return;
  }
  console.log(
    table(
      [
        ...rows,
        {
          separatorBefore: true,
          agent: bold("Total"),
          role: "",
          date: "",
          key_type: `${severityColor(rows.length)} ${redBold("Key Leaks")}`,
          key_value: "",
        },
      ],
      [
        { key: "agent", header: "Coding Agent" },
        { key: "role", header: "Role" },
        { key: "date", header: "Date" },
        { key: "key_type", header: "Key Type" },
        { key: "key_value", header: "Key Value" },
      ],
    ),
  );
}

function oneLineValue(value) {
  return String(value ?? "")
    .replace(/\s+/g, " ")
    .trim();
}

function typeRows(report, args, { includeValues = false, color = true } = {}) {
  const rows = applyFilters(detailRows(report), args);
  const groups = new Map();
  for (const row of rows) {
    const key = `${row.coding_agent}\t${row.key_type}`;
    if (!groups.has(key))
      groups.set(key, { count: 0, user: 0, assistant: 0, values: new Set() });
    const group = groups.get(key);
    group.count++;
    if (row.role === "user") group.user++;
    if (row.role === "assistant") group.assistant++;
    if (includeValues) group.values.add(oneLineValue(row.key_value));
  }
  return [...groups.entries()]
    .map(([key, group]) => {
      const [agent, key_type] = key.split("\t");
      const agentLabel = displayAgent(agent);
      const row = {
        agent: color ? agentColor(agentLabel) : agentLabel,
        agent_id: agent,
        agent_sort: agentLabel,
        key_type,
        count: group.count,
        user: group.user,
        assistant: group.assistant,
      };
      if (includeValues) row.values = [...group.values];
      return row;
    })
    .sort(
      (a, b) =>
        a.agent_sort.localeCompare(b.agent_sort) ||
        b.count - a.count ||
        a.key_type.localeCompare(b.key_type),
    );
}

function printTypes(report, args) {
  const includeValues = args.includes("--show-values");
  const tableRows = typeRows(report, args, { includeValues, color: true }).map(
    (row) => ({
      ...row,
      values: includeValues ? row.values.join(", ") : undefined,
    }),
  );
  if (!tableRows.length) {
    console.log("No matching key types found.");
    return;
  }
  tableRows.push({
    separatorBefore: true,
    agent: bold("Total"),
    key_type: "All Types",
    count: tableRows.reduce((sum, row) => sum + row.count, 0),
    user: tableRows.reduce((sum, row) => sum + row.user, 0),
    assistant: tableRows.reduce((sum, row) => sum + row.assistant, 0),
    values: includeValues ? "" : undefined,
  });
  const displayRows = tableRows.map((row) => ({
    ...row,
    key_type:
      row.key_type === "All Types"
        ? bold(row.key_type)
        : keyTypeColor(row.key_type),
    count: severityColor(row.count),
    user: severityColor(row.user),
    assistant: severityColor(row.assistant),
  }));
  const columns = [
    { key: "agent", header: "Coding Agent" },
    { key: "key_type", header: "Key Type" },
    { key: "count", header: "Count" },
    { key: "user", header: "User" },
    { key: "assistant", header: "Assistant" },
  ];
  if (includeValues) columns.push({ key: "values", header: "Values" });
  console.log(table(displayRows, columns));
}

function safeTimestamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

function defaultOutputPath(command) {
  return resolve(
    process.cwd(),
    ".keyleaks",
    `keyleaks-${command}-${safeTimestamp()}.json`,
  );
}

function prepareOutputDirectory(outputPath, { defaultLocation }) {
  const dir = dirname(outputPath);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  if (defaultLocation) {
    writeFileSync(resolve(dir, ".gitignore"), "*\n!.gitignore\n", {
      mode: 0o644,
    });
  }
}

function showValuesPayload(command, report, args, filters) {
  const base = {
    generated_at: report.generated_at,
    command,
    filters,
    warning:
      "This file contains raw credential-like values. Treat it as sensitive.",
  };
  if (command === "types") {
    return {
      ...base,
      rows: typeRows(report, args, { includeValues: true, color: false }),
    };
  }
  if (command === "details") {
    return { ...base, rows: detailTableRows(report, args, { color: false }) };
  }
  return { ...base, report };
}

function writeShowValuesFile(command, report, args, filters) {
  const requestedOutput = parseFlagValue(args, "--output");
  const defaultLocation = !requestedOutput;
  const outputPath = requestedOutput
    ? resolve(requestedOutput)
    : defaultOutputPath(command);
  prepareOutputDirectory(outputPath, { defaultLocation });
  const payload =
    JSON.stringify(showValuesPayload(command, report, args, filters), null, 2) +
    "\n";
  try {
    writeFileSync(outputPath, payload, { mode: 0o600, flag: "wx" });
    chmodSync(outputPath, 0o600);
  } catch (error) {
    if (error?.code === "EEXIST") {
      console.error(`Refusing to overwrite existing file: ${outputPath}`);
      console.error(
        "Choose a new --output path or remove the existing file first.",
      );
      process.exit(1);
    }
    throw error;
  }
  console.log(`JSON written: ${outputPath}`);
  console.log(`Open file:    ${pathToFileURL(outputPath).href}`);
  console.log(
    "Warning: this file contains raw credential-like values. Treat this file as sensitive and do not commit it.",
  );
}

const args = process.argv.slice(2);
if (args.includes("-h") || args.includes("--help")) {
  printHelp();
  process.exit(0);
}

const command = parseCommand(args);
const events = args.includes("--events");
const inventory = args.includes("--inventory");
const json = args.includes("--json");
const showValues = args.includes("--show-values");
const parallel = !args.includes("--sequential");
const needsDetails = ["details", "types"].includes(command);
const requestedRole = parseFlagValue(args, "--role") || "all";

if (
  !["summary", "list", "month-wise-breakup", "details", "types"].includes(
    command,
  )
) {
  console.error(`Unknown command: ${command}`);
  printHelp();
  process.exit(2);
}
if (showValues && !needsDetails) {
  console.error("--show-values is only supported with `details` or `types`.");
  console.error("Try: keyleaks details --show-values");
  console.error("Or:  keyleaks types --show-values");
  process.exit(2);
}

const agent = parseFlagValue(args, "--agent");
if (agent && !agentKeys[agent]) {
  console.error(
    `Unknown agent: ${agent}. Expected one of: ${Object.values(toolLabels).join(", ")}.`,
  );
  process.exit(2);
}
if (!["all", ...DEFAULT_ROLES].includes(requestedRole)) {
  console.error(
    `Unknown role: ${requestedRole}. Expected user, assistant, or all.`,
  );
  process.exit(2);
}
const agents = agent ? [agentKeys[agent]] : ALL_AGENT_KEYS;
const roles = requestedRole === "all" ? DEFAULT_ROLES : [requestedRole];

const stopScanLoader = startScanLoader({ json });
let report;
try {
  report = await buildReport({
    includeEvents: events,
    includeDetails: needsDetails,
    includeInventory: inventory,
    showValues,
    parallel,
    agents,
    roles,
  });
} finally {
  stopScanLoader();
}
const filters = {
  agent: agent || "all",
  type: parseFlagValue(args, "--type") || "all",
  role: requestedRole,
};

if (showValues) {
  writeShowValuesFile(command, report, args, filters);
} else if (json) {
  console.log(JSON.stringify(report, null, 2));
} else if (command === "details") {
  printDetails(report, args);
} else if (command === "types") {
  printTypes(report, args);
} else if (command === "month-wise-breakup") {
  printMonthWiseBreakup(report);
} else {
  printList(report);
}
