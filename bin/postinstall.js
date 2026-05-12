#!/usr/bin/env node

const rows = [
  ['keyleaks', 'Show summary table'],
  ['keyleaks month-wise-breakup', 'Show per-agent month-wise leak charts'],
  ['keyleaks details --show-values', 'Write raw key details JSON and print file link'],
  ['keyleaks types', 'Group key leaks by inferred key type'],
];
const widths = [
  Math.max('Command'.length, ...rows.map((row) => row[0].length)),
  Math.max('Purpose'.length, ...rows.map((row) => row[1].length)),
];
const pad = (value, width) => value + ' '.repeat(Math.max(0, width - value.length));

console.log('\nkeyleaks installed. Try these commands:\n');
console.log(`${pad('Command', widths[0])}  ${pad('Purpose', widths[1])}`);
console.log(`${'─'.repeat(widths[0])}  ${'─'.repeat(widths[1])}`);
for (const row of rows) console.log(`${pad(row[0], widths[0])}  ${pad(row[1], widths[1])}`);
console.log('');
