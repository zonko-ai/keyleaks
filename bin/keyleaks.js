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
const RULE = "─".repeat(72);
const BAR_WIDTH = 34;
const USE_COLOR =
  Boolean(process.stdout.isTTY) &&
  !process.env.NO_COLOR &&
  process.env.TERM !== "dumb";
const BLUE = USE_COLOR ? "\x1b[34m" : "";
const RED_BOLD = USE_COLOR ? "\x1b[1;31m" : "";
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
    .map((col, i) => padVisible(col.header, widths[i]))
    .join("  ");
  const divider = widths.map((width) => "─".repeat(width)).join("  ");
  const body = rows.flatMap((row) => {
    const rendered = columns
      .map((col, i) => padVisible(row[col.key], widths[i]))
      .join("  ");
    return row.separatorBefore ? [divider, rendered] : [rendered];
  });
  return [line, divider, ...body].join("\n");
}

function printHeader() {
  console.log(RULE);
  console.log("KEYLEAKS — Credential Leak Report");
  console.log(RULE);
}

function activeReportKeys(report) {
  return reportKeys(report).filter(
    (key) => (report[key]?.messages_with_credentials || 0) > 0,
  );
}

function totalKeyLeaks(report) {
  return activeReportKeys(report).reduce(
    (sum, key) => sum + (report[key]?.credential_occurrences || 0),
    0,
  );
}

function printTotalKeyLeaks(report) {
  console.log(
    `\n${redBold(`Total Key Leaks to Agents: ${totalKeyLeaks(report)}`)}`,
  );
}

function totalSummaryRow(rows) {
  return {
    separatorBefore: true,
    Agent: blue("Total"),
    Messages: rows.reduce((sum, row) => sum + row.Messages, 0),
    "Key Leaks": rows.reduce((sum, row) => sum + row["Key Leaks"], 0),
    "Distinct Leaks": rows.reduce((sum, row) => sum + row["Distinct Leaks"], 0),
  };
}

function printSummaryTable(report) {
  const rows = activeReportKeys(report).map((key) => {
    const data = report[key];
    return {
      Agent: blue(displayLabels[key] || toolLabels[key]),
      Messages: data.messages_with_credentials,
      "Key Leaks": data.credential_occurrences,
      "Distinct Leaks": data.distinct_credential_values,
    };
  });
  if (!rows.length) {
    console.log("\n🔐 SUMMARY");
    console.log(RULE);
    console.log("(no credential leaks found)");
    return;
  }
  console.log("\n🔐 SUMMARY");
  console.log(RULE);
  console.log(
    table(
      [...rows, totalSummaryRow(rows)],
      [
        { key: "Agent", header: "Agent" },
        { key: "Messages", header: "Messages" },
        { key: "Key Leaks", header: "Key Leaks" },
        { key: "Distinct Leaks", header: "Distinct Leaks" },
      ],
    ),
  );
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
  return `${"█".repeat(userWidth)}${"░".repeat(assistantWidth)}`.padEnd(
    BAR_WIDTH,
    " ",
  );
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
  console.log("\n📊 CREDENTIAL LEAKS BY MONTH");
  console.log(RULE);
  console.log("Legend: █ user  ░ assistant");

  for (const key of activeReportKeys(report)) {
    const data = report[key];
    const rows = monthlyRowsFor(data);
    console.log(
      `\n${blue((displayLabels[key] || toolLabels[key]).toUpperCase())}`,
    );
    console.log("─".repeat(48));
    if (!rows.length) continue;
    const maxTotal = Math.max(...rows.map((row) => row.total));
    const rendered = rows.map((row) => ({
      Month: row.month,
      User: row.user,
      Assistant: row.assistant,
      Total: row.total,
      Bar: stackedBar(row.user, row.assistant, maxTotal),
    }));
    const totalUser = rows.reduce((sum, row) => sum + row.user, 0);
    const totalAssistant = rows.reduce((sum, row) => sum + row.assistant, 0);
    rendered.push({
      separatorBefore: true,
      Month: "Total",
      User: totalUser,
      Assistant: totalAssistant,
      Total: totalUser + totalAssistant,
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
  console.log("\n▶ COMMANDS");
  console.log(RULE);
  console.log(
    table(
      [
        {
          Command: "keyleaks month-wise-breakup",
          Purpose: "Show per-agent month-wise leak charts",
        },
        {
          Command: "keyleaks details --show-values",
          Purpose: "Write raw key details JSON and print file link",
        },
        {
          Command: "keyleaks types",
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
      ? blue(displayAgent(row.coding_agent))
      : displayAgent(row.coding_agent),
    agent_id: row.coding_agent,
    role: row.role,
    date: row.date || "unknown",
    key_type: row.key_type,
    key_value: row.key_value,
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
          agent: blue("Total"),
          role: "",
          date: "",
          key_type: `${rows.length} Key Leaks`,
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
        agent: color ? blue(agentLabel) : agentLabel,
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
    agent: blue("Total"),
    key_type: "All Types",
    count: tableRows.reduce((sum, row) => sum + row.count, 0),
    user: tableRows.reduce((sum, row) => sum + row.user, 0),
    assistant: tableRows.reduce((sum, row) => sum + row.assistant, 0),
    values: includeValues ? "" : undefined,
  });
  const columns = [
    { key: "agent", header: "Coding Agent" },
    { key: "key_type", header: "Key Type" },
    { key: "count", header: "Count" },
    { key: "user", header: "User" },
    { key: "assistant", header: "Assistant" },
  ];
  if (includeValues) columns.push({ key: "values", header: "Values" });
  console.log(table(tableRows, columns));
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

if (!["summary", "list", "month-wise-breakup", "details", "types"].includes(command)) {
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
