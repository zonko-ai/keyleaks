#!/usr/bin/env node
import { ALL_AGENT_KEYS, DEFAULT_ROLES, TOOL_LABELS, buildReport } from '../lib/native-audit.js';

const toolLabels = TOOL_LABELS;
const agentKeys = Object.fromEntries(Object.entries(toolLabels).map(([key, label]) => [label, key]));
const agentList = Object.values(toolLabels).join('|');

function printHelp() {
  console.log(`keyleaks

Usage:
  keyleaks                         Compact summary list
  keyleaks summary                 Compact summary list
  keyleaks details                 Detail table with redacted values
  keyleaks details --show-values   Detail table with raw key values
  keyleaks types                   Counts by inferred key type
  keyleaks --json                  Raw JSON summary
  keyleaks details --json          Raw JSON with credential_details

Options:
  --agent ${agentList}
                                  Scan/filter one agent only
  --type <text>                    Filter detail output by key type text
  --role user|assistant|all        Scan one role or both roles; default: all
  --events                         Include redacted event metadata in JSON
  --inventory                      Include file inventory in JSON
  --show-values                    Show raw credential values in details
  --sequential                     Disable default concurrent scanning

Safety:
  key values are redacted by default. Use --show-values only when your terminal
  output is private.`);
}

function reportKeys(report) {
  return ALL_AGENT_KEYS.filter((key) => report[key]);
}

function printList(report) {
  const sections = reportKeys(report);
  const blocks = sections.map((key) => {
    const data = report[key];
    return `${toolLabels[key]}:\nmessages: ${data.messages_with_credentials}\ncredential occurrences: ${data.credential_occurrences}\ndistinct occurrences: ${data.distinct_credential_values}`;
  });
  console.log(blocks.join('\n\n'));
  printMonthlyGraph(report);
}

function detailRows(report) {
  return reportKeys(report).flatMap((key) => report[key].credential_details || []);
}

function parseFlagValue(args, name) {
  const index = args.indexOf(name);
  if (index === -1) return undefined;
  return args[index + 1];
}

function parseCommand(args) {
  const valueFlags = new Set(['--agent', '--type', '--role']);
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (valueFlags.has(arg)) {
      i++;
      continue;
    }
    if (!arg.startsWith('-')) return arg;
  }
  return 'summary';
}

function applyFilters(rows, args) {
  const agent = parseFlagValue(args, '--agent');
  const type = parseFlagValue(args, '--type');
  return rows.filter((row) => {
    if (agent && row.coding_agent !== agent) return false;
    if (type && !String(row.key_type).toLowerCase().includes(type.toLowerCase())) return false;
    return true;
  });
}

function table(rows, columns) {
  const widths = columns.map((col) => Math.max(col.header.length, ...rows.map((row) => String(row[col.key] ?? '').length)));
  const line = columns.map((col, i) => col.header.padEnd(widths[i])).join('  ');
  const divider = widths.map((width) => '-'.repeat(width)).join('  ');
  const body = rows.map((row) => columns.map((col, i) => String(row[col.key] ?? '').padEnd(widths[i])).join('  '));
  return [line, divider, ...body].join('\n');
}

function printMonthlyGraph(report) {
  const rows = report.monthly_breakdown || [];
  if (!rows.length) return;
  const graphRows = rows.map((row) => {
    const user = row.credential_occurrences?.user || 0;
    const assistant = row.credential_occurrences?.assistant || 0;
    return { month: row.month, user, assistant, total: user + assistant };
  }).filter((row) => row.total > 0);
  if (!graphRows.length) return;
  const max = Math.max(...graphRows.map((row) => row.total));
  const width = 32;
  const rendered = graphRows.map((row) => {
    const barWidth = Math.max(1, Math.round((row.total / max) * width));
    const userWidth = row.total ? Math.round((row.user / row.total) * barWidth) : 0;
    const assistantWidth = Math.max(0, barWidth - userWidth);
    return {
      month: row.month,
      user: row.user,
      assistant: row.assistant,
      total: row.total,
      graph: `${'#'.repeat(userWidth)}${'='.repeat(assistantWidth)}`,
    };
  });
  console.log('\nmonth-wise credential occurrences (# user, = assistant):');
  console.log(table(rendered, [
    { key: 'month', header: 'Month' },
    { key: 'user', header: 'User' },
    { key: 'assistant', header: 'Assistant' },
    { key: 'total', header: 'Total' },
    { key: 'graph', header: 'Graph' },
  ]));
}

function printDetails(report, args) {
  const rows = applyFilters(detailRows(report), args).map((row) => ({
    agent: row.coding_agent,
    role: row.role,
    date: row.date || 'unknown',
    key_type: row.key_type,
    key_value: row.key_value,
  }));
  if (!rows.length) {
    console.log('No matching credential details found.');
    return;
  }
  console.log(table(rows, [
    { key: 'agent', header: 'Coding Agent' },
    { key: 'role', header: 'Role' },
    { key: 'date', header: 'Date' },
    { key: 'key_type', header: 'Key Type' },
    { key: 'key_value', header: 'Key Value' },
  ]));
}

function printTypes(report, args) {
  const rows = applyFilters(detailRows(report), args);
  const counts = new Map();
  for (const row of rows) {
    const key = `${row.coding_agent}\t${row.key_type}`;
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  const tableRows = [...counts.entries()].map(([key, count]) => {
    const [agent, key_type] = key.split('\t');
    return { agent, key_type, count };
  }).sort((a, b) => a.agent.localeCompare(b.agent) || b.count - a.count || a.key_type.localeCompare(b.key_type));
  if (!tableRows.length) {
    console.log('No matching key types found.');
    return;
  }
  console.log(table(tableRows, [
    { key: 'agent', header: 'Coding Agent' },
    { key: 'key_type', header: 'Key Type' },
    { key: 'count', header: 'Count' },
  ]));
}

const args = process.argv.slice(2);
if (args.includes('-h') || args.includes('--help')) {
  printHelp();
  process.exit(0);
}

const command = parseCommand(args);
const events = args.includes('--events');
const inventory = args.includes('--inventory');
const json = args.includes('--json');
const showValues = args.includes('--show-values');
const parallel = !args.includes('--sequential');
const needsDetails = ['details', 'types'].includes(command);
const requestedRole = parseFlagValue(args, '--role') || 'all';

if (!['summary', 'list', 'details', 'types'].includes(command)) {
  console.error(`Unknown command: ${command}`);
  printHelp();
  process.exit(2);
}

const agent = parseFlagValue(args, '--agent');
if (agent && !agentKeys[agent]) {
  console.error(`Unknown agent: ${agent}. Expected one of: ${Object.values(toolLabels).join(', ')}.`);
  process.exit(2);
}
if (!['all', ...DEFAULT_ROLES].includes(requestedRole)) {
  console.error(`Unknown role: ${requestedRole}. Expected user, assistant, or all.`);
  process.exit(2);
}
const agents = agent ? [agentKeys[agent]] : ALL_AGENT_KEYS;
const roles = requestedRole === 'all' ? DEFAULT_ROLES : [requestedRole];

const report = await buildReport({
  includeEvents: events,
  includeDetails: needsDetails,
  includeInventory: inventory,
  showValues,
  parallel,
  agents,
  roles,
});

if (json) {
  console.log(JSON.stringify(report, null, 2));
} else if (command === 'details') {
  printDetails(report, args);
} else if (command === 'types') {
  printTypes(report, args);
} else {
  printList(report);
}
