#!/usr/bin/env node
import assert from 'node:assert/strict';
import { detectText } from './lib/native-audit.js';

const cases = [
  ['OpenAI project', 'openai api key = sk-proj-' + 'A'.repeat(48), 'OpenAI'],
  ['OpenAI compatible', 'api key = sk-' + 'A'.repeat(48), 'OpenAI-compatible'],
  ['Anthropic', 'anthropic api key = sk-ant-api03-' + 'A'.repeat(80), 'Anthropic'],
  ['OpenRouter', 'openrouter api key = sk-or-v1-' + 'A'.repeat(48), 'OpenRouter'],
  ['xAI', 'xai api key = xai-' + 'A'.repeat(48), 'xAI'],
  ['Groq', 'groq api key = gsk_' + 'A'.repeat(52), 'Groq'],
  ['Perplexity', 'perplexity api key = pplx-' + 'A'.repeat(48), 'Perplexity'],
  ['GitHub', 'github token = ghp_' + 'A'.repeat(36), 'GitHub'],
  ['GitLab', 'gitlab token = glpat-' + 'A'.repeat(20), 'GitLab'],
  ['Slack', 'slack token = xoxb-' + '1'.repeat(20), 'Slack'],
  ['SendGrid', 'sendgrid token = SG.' + 'A'.repeat(66), 'SendGrid'],
  ['Telegram', 'telegram bot token = 123456789:AA' + 'A'.repeat(33), 'Telegram'],
  ['Sentry user', 'sentry user token = sntryu_' + 'a'.repeat(64), 'Sentry'],
  ['Sentry org', 'sentry org token = sntrys_eyJpYXQiO' + 'A'.repeat(20) + 'LCJyZWdpb25fdXJs' + 'B'.repeat(20) + '_' + 'C'.repeat(43), 'Sentry'],
  ['Google', 'google api key = AIza' + 'A'.repeat(35), 'Google/Gemini'],
  ['Square', 'square access token = sq0atp-' + 'A'.repeat(32), 'Square'],
  ['Shopify', 'shopify access token = shpat_' + 'A'.repeat(32), 'Shopify'],
];

for (const [name, text, expectedType] of cases) {
  const hits = detectText(text);
  assert(hits.some((hit) => hit.key_type === expectedType), `${name} detector should emit ${expectedType}`);
}

console.log(`detector coverage ok (${cases.length} cases)`);
