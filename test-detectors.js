#!/usr/bin/env node
import assert from 'node:assert/strict';
import { detectText } from './lib/native-audit.js';

const cases = [
  ['OpenAI', 'openai api key = sk-' + 'A'.repeat(48), 'OpenAI/OpenRouter'],
  ['GitHub', 'github token = ghp_' + 'A'.repeat(36), 'GitHub'],
  ['Slack', 'slack token = xoxb-' + '1'.repeat(20), 'Slack'],
  ['Google', 'google api key = AIza' + 'A'.repeat(35), 'Google/Gemini'],
  ['Square', 'square access token = sq0atp-' + 'A'.repeat(32), 'Square'],
  ['Shopify', 'shopify access token = shpat_' + 'A'.repeat(32), 'Shopify'],
];

for (const [name, text, expectedType] of cases) {
  const hits = detectText(text);
  assert(hits.some((hit) => hit.key_type === expectedType), `${name} detector should emit ${expectedType}`);
}

console.log(`detector coverage ok (${cases.length} cases)`);
