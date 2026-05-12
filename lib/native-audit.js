import { createReadStream, existsSync } from 'node:fs';
import { readdir, readFile, stat } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { spawn } from 'node:child_process';
import { createInterface } from 'node:readline';
import { homedir } from 'node:os';
import { delimiter, join, relative } from 'node:path';

const HOME = homedir();

const TOOL_LABELS = {
  pi_agent: 'pi',
  claude_code: 'claude',
  codex: 'codex',
  amp: 'amp',
  opencode: 'opencode',
  cline: 'cline',
  zed: 'zed',
};
const ALL_AGENT_KEYS = Object.keys(TOOL_LABELS);
const DEFAULT_ROLES = ['user', 'assistant'];
const VALID_ROLES = new Set(DEFAULT_ROLES);

const KNOWN = [
  ['anthropic_key', /\bsk-ant-[A-Za-z0-9_-]{20,}\b/gms],
  ['openrouter_key', /\bsk-or-v1-[A-Za-z0-9_-]{20,}\b/gms],
  ['xai_key', /\bxai-[A-Za-z0-9]{20,80}\b/gms],
  ['groq_key', /\bgsk_[A-Za-z0-9]{40,}\b/gms],
  ['perplexity_key', /\bpplx-[A-Za-z0-9]{40,}\b/gms],
  ['openai_key', /\b(?:sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})\b/gms],
  ['openai_compatible_key', /\bsk-[A-Za-z0-9_-]{20,}\b/gms],
  ['github_token', /\b(?:gh[pousr]_[A-Za-z0-9_]{30,}|github_pat_[A-Za-z0-9_]{30,})\b/gms],
  ['gitlab_token', /\bgl(?:pat|rt|cbt|imt|ptt|rrt)-[A-Za-z0-9_-]{20,}\b/gms],
  ['google_api_key', /\bAIza[0-9A-Za-z_-]{30,}\b/gms],
  ['aws_access_key_id', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/gms],
  ['slack_token', /\bxox[baprs]-[A-Za-z0-9-]{20,}\b/gms],
  ['slack_webhook_url', /\bhttps:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/_-]{30,}\b/gms],
  ['sendgrid_token', /\bSG\.[A-Za-z0-9._=-]{40,}\b/gms],
  ['telegram_bot_token', /\b[0-9]{5,16}:AA[A-Za-z0-9_-]{33}\b/gms],
  ['sentry_user_token', /\bsntryu_[a-f0-9]{64}\b/gms],
  ['sentry_org_token', /\bsntrys_eyJpYXQiO[A-Za-z0-9+/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[A-Za-z0-9+/]{10,200}={0,2}_[A-Za-z0-9+/]{43}(?=$|[^A-Za-z0-9+/])/gms],
  ['square_token', /\bsq0(?:atp|csp)-[0-9A-Za-z_-]{20,}\b/gms],
  ['shopify_token', /\bshp(?:ss|at|ca|pa)_[0-9A-Za-z]{20,}\b/gms],
  ['stripe_key', /\b(?:sk|pk|rk)_(?:live|test)_[0-9A-Za-z]{20,}\b/gms],
  ['linear_key', /\blin_api_[0-9A-Za-z]{20,}\b/gms],
  ['jwt', /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/gms],
  ['hf_token', /\bhf_[A-Za-z0-9]{30,}\b/gms],
  ['npm_token', /\bnpm_[A-Za-z0-9]{30,}\b/gms],
  ['pypi_token', /\bpypi-[A-Za-z0-9_-]{30,}\b/gms],
  ['private_key_block', /-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/gms],
];
const KNOWN_PATTERN_NAMES = new Set(KNOWN.map(([name]) => name));

const VALUE = String.raw`(https?:\/\/\S+|[A-Za-z0-9][A-Za-z0-9_./+=:@$!%?&%:-]{7,})`;
const LABEL_WORD = String.raw`(?:api[_ -]?key|apikey|secret|token|password|passwd|pat|private[_ -]?key|client[_ -]?(?:secret|id)|app[_ -]?id|signing[_ -]?secret|webhook(?:[_ -]?url)?|auth[_ -]?token|access[_ -]?token(?:[_ -]?secret)?|refresh[_ -]?token|request[_ -]?token)`;
const LABEL_BEFORE = new RegExp(String.raw`\b(?<label>[A-Za-z0-9_ -]{0,35}${LABEL_WORD}[A-Za-z0-9_ -]{0,25})\b\s*(?:=|:|:=|=>|\bis\b|-|—)\s*["'\`]?\s*(?<value>${VALUE})`, 'gims');
const LABEL_AFTER = new RegExp(String.raw`(?<value>${VALUE})\s*(?:-|—|:)\s*(?<label>(?:use\s+this\s+)?(?:api\s+key|key|token|pat|client\s+secret|client\s+id|app\s+id|signing\s+secret|access\s+token|refresh\s+token|request\s+token|webhook))\b`, 'gims');
const SERVICE_LABEL = new RegExp(String.raw`\b(?<label>posthog|deepgram|google|openai|anthropic|openrouter|xai|groq|perplexity|gitlab|sendgrid|telegram|sentry|supabase|gemini|raindrop)\b\s*(?:-|:|=)\s*["'\`]?\s*(?<value>${VALUE})`, 'gims');
const LONG_STANDALONE = /^[A-Za-z0-9][A-Za-z0-9_./+=:@$!%?&%-]{20,}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const BAD_LABEL = /(output|input|cache|total|source|prefix|hint|used|match|path|pattern|stress|processed|success|webhookid|tokens\b|nsfilepath|backward compatibility|paramfield|disconnect|duplicate|starturl|key paths|patch|curl -x|mumbai|chhatrapati|shivaji)/i;
const BAD_VALUE_SUBSTRINGS = [
  'process.env', 'import.meta', 'deno.env', 'env.', 'v.optional', 'z.string', 'props.',
  '.tsx', '.ts:', '.jsx', '.js:', '.png', '.jpg', '.svg', 'node_modules',
  'localhost:', 'example.com', 'your@email', '<long>',
];
const SECRET_HINT = /(sk-|sk-or-v1-|github_pat_|gh[pousr]_|gl(?:pat|rt|cbt|imt|ptt|rrt)-|AIza|xox[baprs]-|hooks\.slack\.com\/services|sq0(?:atp|csp)-|shp(?:ss|at|ca|pa)_|xai-|gsk_|pplx-|SG\.|sntry[us]_|eyJ|hf_|npm_|pypi-|api[_ -]?key|apikey|secret|token|password|passwd|pat\b|private[_ -]?key|client[_ -]?(?:secret|id)|app[_ -]?id|signing[_ -]?secret|webhook|auth[_ -]?token|access[_ -]?token|refresh[_ -]?token|request[_ -]?token|posthog|deepgram|google|openai|anthropic|openrouter|xai|groq|perplexity|gitlab|sendgrid|telegram|sentry|supabase|gemini|raindrop|square|shopify)/i;
const CODEX_KEEP_HINT = /\b(use this|api key|token:|access_token|client token|app id|posthog:|supabsae token)\b/i;
const CODEX_CODE_LINE = /^\s*(import|export|interface|class|function|const)\b/m;
const LABEL_WORD_RE = new RegExp(LABEL_WORD, 'i');

function sha(value) {
  return createHash('sha256').update(value).digest('hex');
}

function entropy(value) {
  if (!value) return 0;
  const counts = new Map();
  for (const ch of value) counts.set(ch, (counts.get(ch) || 0) + 1);
  let total = 0;
  for (const n of counts.values()) {
    const p = n / value.length;
    total -= p * Math.log2(p);
  }
  return total;
}

function clean(value) {
  return String(value ?? '').trim().replace(/^["`'<>,).;]+|["`'<>,).;]+$/g, '');
}

function plausibleValue(raw, { allowShort = false, allowSecretUrl = true } = {}) {
  const value = clean(raw);
  const low = value.toLowerCase();
  if (value.length < (allowShort ? 8 : 16)) return false;
  if (UUID.test(value)) return false;
  if (new Set([
    'personal', 'localhost', 'token', 'secret', 'password', 'api_key', 'openai_api_key',
    'access_token', 'refresh_token', 'undefined', 'null', 'true', 'false',
  ]).has(low)) return false;
  if (low.startsWith('/users/') || low.startsWith('~/') || low.startsWith('./') || low.startsWith('../') || low.startsWith('@/')) return false;
  if (BAD_VALUE_SUBSTRINGS.some((part) => low.includes(part))) return false;
  if (low.startsWith('http://') || low.startsWith('https://')) {
    return allowSecretUrl && (
      low.includes('hooks.slack.com/services') ||
      ['token=', 'api_key=', 'secret=', 'key=', 'request_token=', 'access_token='].some((q) => low.includes(q))
    );
  }

  let letters = 0;
  let digits = 0;
  let symbols = 0;
  for (const ch of value) {
    if (/[A-Za-z]/.test(ch)) letters++;
    else if (/[0-9]/.test(ch)) digits++;
    else if ('_./+=:@$!%?&%-'.includes(ch)) symbols++;
  }
  if (letters === value.length) return false;
  if (allowShort && value.length >= 8 && (digits || symbols)) return true;
  return value.length >= 16 && (digits || symbols) && entropy(value) >= 3.0;
}

function matchAllFresh(regex, text) {
  regex.lastIndex = 0;
  return text.matchAll(regex);
}

function detectCredentials(text, { serviceLabels, credentialBlock }) {
  const hits = [];
  const add = (value, kind) => {
    value = clean(value);
    if (value) hits.push([value, kind]);
  };

  for (const [kind, rx] of KNOWN) {
    for (const match of matchAllFresh(rx, text)) add(match[0], kind);
  }

  for (const match of matchAllFresh(LABEL_BEFORE, text)) {
    const label = String(match.groups?.label ?? '').split(/\s+/).filter(Boolean).join(' ');
    if (BAD_LABEL.test(label)) continue;
    const allowShort = /client|app/i.test(label);
    const value = match.groups?.value;
    if (plausibleValue(value, { allowShort })) add(value, `label_before:${label.toLowerCase()}`);
  }

  for (const match of matchAllFresh(LABEL_AFTER, text)) {
    const label = String(match.groups?.label ?? '').split(/\s+/).filter(Boolean).join(' ').toLowerCase();
    if (label === 'key') continue;
    const allowShort = /client|app/.test(label);
    const value = match.groups?.value;
    if (plausibleValue(value, { allowShort })) add(value, `label_after:${label}`);
  }

  if (serviceLabels) {
    for (const match of matchAllFresh(SERVICE_LABEL, text)) {
      const label = String(match.groups?.label ?? '').toLowerCase();
      const allowShort = label === 'posthog' || label === 'supabase';
      const value = match.groups?.value;
      if (plausibleValue(value, { allowShort })) add(value, `service_label:${label}`);
    }
  }

  if (credentialBlock && new Set(hits.map(([value]) => sha(value))).size >= 2) {
    for (const line of text.split(/\r?\n/)) {
      const value = clean(line);
      if (!value || /\s/.test(value)) continue;
      if (value.includes('=') || value.includes(':')) continue;
      if (LABEL_WORD_RE.test(value)) continue;
      if (LONG_STANDALONE.test(value) && plausibleValue(value)) add(value, 'credential_block_standalone_opaque_value');
    }
  }

  const filtered = [];
  for (const [value, kind] of hits) {
    if (hits.some(([other]) => value !== other && other.includes(value) && other.length > value.length)) continue;
    filtered.push([value, kind]);
  }

  const rank = (kind) => {
    if (kind === 'openai_compatible_key') return 3;
    if (KNOWN_PATTERN_NAMES.has(kind)) return 5;
    if (kind.startsWith('label_before:') || kind.startsWith('label_after:') || kind.startsWith('service_label:')) return 4;
    return 2;
  };
  const best = new Map();
  for (const [value, kind] of filtered) {
    const digest = sha(value);
    if (!best.has(digest) || rank(kind) > rank(best.get(digest).kind)) best.set(digest, { kind, value });
  }
  return [...best.entries()].map(([digest, { kind, value }]) => ({ digest, kind, value }));
}

function keyTypeFromKind(kind) {
  const low = kind.toLowerCase();
  const direct = {
    openai_key: 'OpenAI',
    openai_compatible_key: 'OpenAI-compatible',
    anthropic_key: 'Anthropic',
    openrouter_key: 'OpenRouter',
    xai_key: 'xAI',
    groq_key: 'Groq',
    perplexity_key: 'Perplexity',
    github_token: 'GitHub',
    gitlab_token: 'GitLab',
    google_api_key: 'Google/Gemini',
    aws_access_key_id: 'AWS',
    slack_token: 'Slack',
    slack_webhook_url: 'Slack',
    sendgrid_token: 'SendGrid',
    telegram_bot_token: 'Telegram',
    sentry_user_token: 'Sentry',
    sentry_org_token: 'Sentry',
    square_token: 'Square',
    shopify_token: 'Shopify',
    stripe_key: 'Stripe',
    linear_key: 'Linear',
    jwt: 'JWT',
    hf_token: 'Hugging Face',
    npm_token: 'npm',
    pypi_token: 'PyPI',
    private_key_block: 'Private Key',
  };
  if (direct[kind]) return direct[kind];
  const serviceLabels = {
    posthog: 'PostHog',
    deepgram: 'Deepgram',
    google: 'Google/Gemini',
    gemini: 'Gemini',
    openai: 'OpenAI',
    anthropic: 'Anthropic',
    openrouter: 'OpenRouter',
    xai: 'xAI',
    groq: 'Groq',
    perplexity: 'Perplexity',
    gitlab: 'GitLab',
    sendgrid: 'SendGrid',
    telegram: 'Telegram',
    sentry: 'Sentry',
    supabase: 'Supabase',
    raindrop: 'Raindrop',
  };
  for (const [marker, label] of Object.entries(serviceLabels)) if (low.includes(marker)) return label;
  const generic = {
    github: 'GitHub',
    slack: 'Slack',
    square: 'Square',
    shopify: 'Shopify',
    stripe: 'Stripe',
    linear: 'Linear',
    aws: 'AWS',
    openrouter: 'OpenRouter',
    hugging: 'Hugging Face',
    npm: 'npm',
    pypi: 'PyPI',
  };
  for (const [marker, label] of Object.entries(generic)) if (low.includes(marker)) return label;
  if (low.includes('client')) return 'Client Credential';
  if (low.includes('webhook')) return 'Webhook';
  if (low.includes('password') || low.includes('passwd')) return 'Password';
  if (low.includes('token')) return 'Token';
  if (low.includes('key')) return 'API Key';
  return 'Unknown/Generic';
}

function redactValue(value) {
  return `[redacted length=${clean(value).length}]`;
}

function normalizeTimestamp(value) {
  if (value == null) return null;
  if (typeof value === 'number') {
    const ms = value > 10_000_000_000 ? value : value * 1000;
    const d = new Date(ms);
    return Number.isNaN(d.getTime()) ? String(value) : d.toISOString();
  }
  const text = String(value).trim();
  if (/^\d+$/.test(text)) return normalizeTimestamp(Number(text));
  return text || null;
}

function monthKey(value) {
  const timestamp = normalizeTimestamp(value);
  if (!timestamp) return 'unknown';
  const d = new Date(timestamp);
  if (Number.isNaN(d.getTime())) return 'unknown';
  return d.toISOString().slice(0, 7);
}

function normalizeRole(role) {
  const value = String(role ?? '').toLowerCase();
  return VALID_ROLES.has(value) ? value : null;
}

function emptyRoleCounts() {
  return { user: 0, assistant: 0 };
}

function ensureMonth(map, month) {
  if (!map.has(month)) {
    map.set(month, {
      month,
      messages_with_credentials: emptyRoleCounts(),
      credential_occurrences: emptyRoleCounts(),
    });
  }
  return map.get(month);
}

async function* readLines(filePath) {
  const rl = createInterface({ input: createReadStream(filePath, { encoding: 'utf8' }), crlfDelay: Infinity });
  for await (const line of rl) yield line;
}

async function entriesSafe(dir) {
  try {
    return await readdir(dir, { withFileTypes: true });
  } catch {
    return [];
  }
}

async function statSafe(path) {
  try {
    return await stat(path);
  } catch {
    return null;
  }
}

async function directJsonlTwoLevel(root) {
  const result = [];
  const dirs = await entriesSafe(root);
  for (const dirent of dirs) {
    if (!dirent.isDirectory()) continue;
    const dir = join(root, dirent.name);
    const entries = await entriesSafe(dir);
    for (const entry of entries) if (entry.isFile() && entry.name.endsWith('.jsonl')) result.push(join(dir, entry.name));
  }
  return result.sort();
}

async function recursiveJsonl(root) {
  const result = [];
  async function walk(dir) {
    const entries = await entriesSafe(dir);
    for (const entry of entries) {
      const full = join(dir, entry.name);
      if (entry.isDirectory()) await walk(full);
      else if (entry.isFile() && entry.name.endsWith('.jsonl')) result.push(full);
    }
  }
  await walk(root);
  return result.sort();
}

async function directFiles(root) {
  const entries = await entriesSafe(root);
  return entries.filter((entry) => entry.isFile()).map((entry) => join(root, entry.name)).sort();
}

async function directJsonFiles(root) {
  return (await directFiles(root)).filter((path) => path.endsWith('.json')).sort();
}

async function readJsonSafe(path) {
  try {
    return JSON.parse(await readFile(path, 'utf8'));
  } catch {
    return null;
  }
}

async function lineCount(path) {
  if (!existsSync(path)) return 0;
  let count = 0;
  try {
    for await (const _line of readLines(path)) count++;
  } catch {
    return 0;
  }
  return count;
}

function findExecutable(name) {
  for (const dir of (process.env.PATH || '').split(delimiter)) {
    const path = join(dir, name);
    if (existsSync(path)) return path;
  }
  return null;
}

function textFromTypedContent(content, typeName) {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    return content
      .filter((item) => item && typeof item === 'object' && item.type === typeName && typeof item.text === 'string')
      .map((item) => item.text)
      .join('\n');
  }
  return '';
}

function textFromAnyContent(content) {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    return content
      .filter((item) => item && typeof item === 'object' && typeof item.text === 'string')
      .map((item) => item.text)
      .join('\n');
  }
  return '';
}

async function* iterPiRecords(paths) {
  const root = join(HOME, '.pi', 'agent', 'sessions');
  for (const path of paths) {
    const rel = relative(root, path);
    let lineNo = 0;
    try {
      for await (const line of readLines(path)) {
        lineNo++;
        if (!line.includes('"role":"user"') && !line.includes('"role": "user"') && !line.includes('"role":"assistant"') && !line.includes('"role": "assistant"')) continue;
        let obj;
        try { obj = JSON.parse(line); } catch { continue; }
        const msg = obj && typeof obj.message === 'object' ? obj.message : {};
        const role = normalizeRole(msg.role);
        if (obj.type === 'message' && role) {
          const text = textFromTypedContent(msg.content, 'text');
          if (text.trim()) yield { source: 'pi_session', loc: `${rel}:${lineNo}`, timestamp: obj.timestamp ?? msg.timestamp, text, role };
        }
      }
    } catch {}
  }
}

async function* iterRgJsonlLines(paths, pattern) {
  const rg = findExecutable('rg');
  if (!rg || !paths.length) return;
  const child = spawn(rg, ['-n', '-H', '--no-heading', '-e', pattern, ...paths], { stdio: ['ignore', 'pipe', 'ignore'] });
  const rl = createInterface({ input: child.stdout, crlfDelay: Infinity });
  for await (const line of rl) {
    const marker = line.indexOf(':{');
    if (marker === -1) continue;
    const prefix = line.slice(0, marker);
    const colon = prefix.lastIndexOf(':');
    if (colon === -1) continue;
    yield {
      filePath: prefix.slice(0, colon),
      lineNo: prefix.slice(colon + 1),
      raw: `{${line.slice(marker + 2)}`,
    };
  }
  await new Promise((resolve) => child.once('close', resolve));
}

async function* iterPiRecordsFast(paths) {
  const root = join(HOME, '.pi', 'agent', 'sessions');
  if (!findExecutable('rg')) {
    yield* iterPiRecords(paths);
    return;
  }
  for await (const { filePath, lineNo, raw } of iterRgJsonlLines(paths, '"role"\\s*:\\s*"(?:user|assistant)"')) {
    let obj;
    try { obj = JSON.parse(raw); } catch { continue; }
    const msg = obj && typeof obj.message === 'object' ? obj.message : {};
    const role = normalizeRole(msg.role);
    if (obj.type !== 'message' || !role) continue;
    const text = textFromTypedContent(msg.content, 'text');
    if (text.trim()) yield { source: 'pi_session', loc: `${relative(root, filePath)}:${lineNo}`, timestamp: obj.timestamp ?? msg.timestamp, text, role };
  }
}

async function* iterClaudeHistoryRecords() {
  const path = join(HOME, '.claude', 'history.jsonl');
  if (!existsSync(path)) return;
  let lineNo = 0;
  try {
    for await (const line of readLines(path)) {
      lineNo++;
      let obj;
      try { obj = JSON.parse(line); } catch { continue; }
      const parts = [obj.display || ''];
      const pasted = obj.pastedContents;
      if (pasted && typeof pasted === 'object') {
        for (const item of Object.values(pasted)) {
          if (item && typeof item === 'object' && typeof item.content === 'string') parts.push(item.content);
        }
      }
      const text = parts.join('\n');
      if (text.trim()) yield { source: 'claude_history', loc: `.claude/history.jsonl:${lineNo}`, timestamp: obj.timestamp, text, role: 'user' };
    }
  } catch {}
}

const CLAUDE_GENERATED_PREFIXES = [
  'This session is being continued from a previous conversation',
  'Base directory for this skill:',
  '<bash-stdout>',
  '<local-command-stdout>',
  '<command-message>',
  '<system-reminder>',
  '<agent_result',
  '<function_results>',
];

function claudeMessageFromObject(obj) {
  const msg = obj && typeof obj.message === 'object' ? obj.message : {};
  const role = normalizeRole(msg.role);
  if (obj.type !== role || !role) return null;
  const content = msg.content;
  if (Array.isArray(content) && !content.some((item) => item && typeof item === 'object' && item.type === 'text')) return null;
  const text = textFromTypedContent(content, 'text');
  const stripped = text.trimStart();
  if (!text.trim()) return null;
  if (CLAUDE_GENERATED_PREFIXES.some((prefix) => stripped.startsWith(prefix)) || stripped.slice(0, 250).includes('<task-id>') || stripped.slice(0, 350).includes('<tool-use-id>')) return null;
  return { text, role };
}

async function* iterClaudeProjectRecords(paths) {
  for (const path of paths) {
    const rel = relative(HOME, path);
    let lineNo = 0;
    try {
      for await (const line of readLines(path)) {
        lineNo++;
        if ((!line.includes('"role":"user"') && !line.includes('"role": "user"') && !line.includes('"role":"assistant"') && !line.includes('"role": "assistant"')) || (!line.includes('"type":"user"') && !line.includes('"type": "user"') && !line.includes('"type":"assistant"') && !line.includes('"type": "assistant"'))) continue;
        let obj;
        try { obj = JSON.parse(line); } catch { continue; }
        const message = claudeMessageFromObject(obj);
        if (message) yield { source: 'claude_project', loc: `${rel}:${lineNo}`, timestamp: obj.timestamp, text: message.text, role: message.role };
      }
    } catch {}
  }
}

async function* iterClaudeProjectRecordsFast(paths) {
  if (!findExecutable('rg')) {
    yield* iterClaudeProjectRecords(paths);
    return;
  }
  for await (const { filePath, lineNo, raw } of iterRgJsonlLines(paths, '"role"\\s*:\\s*"(?:user|assistant)"')) {
    if (!raw.includes('"type":"user"') && !raw.includes('"type": "user"') && !raw.includes('"type":"assistant"') && !raw.includes('"type": "assistant"')) continue;
    let obj;
    try { obj = JSON.parse(raw); } catch { continue; }
    const message = claudeMessageFromObject(obj);
    if (message) yield { source: 'claude_project', loc: `${relative(HOME, filePath)}:${lineNo}`, timestamp: obj.timestamp, text: message.text, role: message.role };
  }
}

async function* iterClaudePasteCacheRecords(paths) {
  for (const path of paths) {
    const st = await statSafe(path);
    if (!st?.isFile()) continue;
    try {
      const text = await readFile(path, 'utf8');
      if (text.trim()) yield { source: 'claude_paste_cache', loc: `${relative(HOME, path)}:1`, timestamp: null, text, role: 'user' };
    } catch {}
  }
}

async function* iterCodexHistoryRecords() {
  for (const name of ['history.jsonl', 'transcription-history.jsonl']) {
    const path = join(HOME, '.codex', name);
    if (!existsSync(path)) continue;
    let lineNo = 0;
    try {
      for await (const line of readLines(path)) {
        lineNo++;
        let obj;
        try { obj = JSON.parse(line); } catch { continue; }
        const text = obj.text || '';
        if (String(text).trim()) yield { source: 'codex_history', loc: `.codex/${name}:${lineNo}`, timestamp: obj.ts ?? obj.createdAtMs, text, role: 'user' };
      }
    } catch {}
  }
}

function humanishCodexText(raw) {
  let text = String(raw ?? '').trim();
  if (!text || text.startsWith('<environment_context>')) return '';
  if (text.includes('## My request for Codex:')) text = text.split('## My request for Codex:', 2)[1].trim();
  const rejectPrefixes = [
    '# AGENTS.md', '# Cloud.md', '## Memory Writing Agent:', 'You are implementing ',
    'Run a real verification pass ', 'Continue work in /', 'Pipedream Connect Triggers',
    'Howdy Eval System', '#!/usr/bin/env', '{ "tools"', '[$',
  ];
  if (rejectPrefixes.some((prefix) => text.startsWith(prefix))) return '';
  if (text.length > 2500 && !CODEX_KEEP_HINT.test(text)) return '';
  if (text.length > 1500 && CODEX_CODE_LINE.test(text)) {
    if (!CODEX_KEEP_HINT.test(text.slice(0, 500))) return '';
  }
  return text;
}

async function* iterCodexSessionRecords(paths) {
  for (const path of paths) {
    const rel = relative(HOME, path);
    let lineNo = 0;
    try {
      for await (const line of readLines(path)) {
        lineNo++;
        if ((!line.includes('"role":"user"') && !line.includes('"role": "user"') && !line.includes('"role":"assistant"') && !line.includes('"role": "assistant"')) || (!line.includes('"type":"response_item"') && !line.includes('"type": "response_item"'))) continue;
        let obj;
        try { obj = JSON.parse(line); } catch { continue; }
        const payload = obj && typeof obj.payload === 'object' ? obj.payload : {};
        const role = normalizeRole(payload.role);
        if (obj.type !== 'response_item' || payload.type !== 'message' || !role) continue;
        const rawText = role === 'user' ? textFromTypedContent(payload.content, 'input_text') : textFromAnyContent(payload.content);
        const text = role === 'user' ? humanishCodexText(rawText) : String(rawText ?? '').trim();
        if (text) yield { source: 'codex_session_humanish', loc: `${rel}:${lineNo}`, timestamp: obj.timestamp, text, role };
      }
    } catch {}
  }
}

async function* iterCodexSessionRecordsFast(paths) {
  const rg = findExecutable('rg');
  if (!rg || !paths.length) {
    yield* iterCodexSessionRecords(paths);
    return;
  }

  const child = spawn(rg, ['-n', '-H', '--no-heading', '-e', '"role"\\s*:\\s*"(?:user|assistant)"', ...paths], {
    stdio: ['ignore', 'pipe', 'ignore'],
  });
  const rl = createInterface({ input: child.stdout, crlfDelay: Infinity });

  for await (const line of rl) {
    const marker = line.indexOf(':{');
    if (marker === -1) continue;
    const prefix = line.slice(0, marker);
    const colon = prefix.lastIndexOf(':');
    if (colon === -1) continue;
    const filePath = prefix.slice(0, colon);
    const lineNo = prefix.slice(colon + 1);
    const raw = `{${line.slice(marker + 2)}`;
    if (!raw.includes('"type":"response_item"') && !raw.includes('"type": "response_item"')) continue;

    let obj;
    try { obj = JSON.parse(raw); } catch { continue; }
    const payload = obj && typeof obj.payload === 'object' ? obj.payload : {};
    const role = normalizeRole(payload.role);
    if (obj.type !== 'response_item' || payload.type !== 'message' || !role) continue;
    const rawText = role === 'user' ? textFromTypedContent(payload.content, 'input_text') : textFromAnyContent(payload.content);
    const text = role === 'user' ? humanishCodexText(rawText) : String(rawText ?? '').trim();
    if (!text) continue;
    yield {
      source: 'codex_session_humanish',
      loc: `${relative(HOME, filePath)}:${lineNo}`,
      timestamp: obj.timestamp,
      text,
      role,
    };
  }

  await new Promise((resolve) => child.once('close', resolve));
}

function getAmpThreadsDir() {
  return join(process.env.XDG_DATA_HOME ?? join(HOME, '.local', 'share'), 'amp', 'threads');
}

async function* iterAmpRecords(paths) {
  for (const path of paths) {
    const threadId = path.split('/').pop()?.replace(/\.json$/, '') ?? 'unknown';
    const thread = await readJsonSafe(path);
    if (!Array.isArray(thread?.messages)) continue;
    let idx = 0;
    for (const msg of thread.messages) {
      idx++;
      const role = normalizeRole(msg?.role);
      if (!role) continue;
      const text = textFromAnyContent(msg.content);
      if (!text.trim()) continue;
      yield {
        source: 'amp_thread',
        loc: `${relative(HOME, path)}:${idx}`,
        timestamp: msg.timestamp ?? msg.createdAt,
        text,
        role,
        session: threadId,
      };
    }
  }
}

function getVSCodeGlobalStoragePaths() {
  if (process.platform === 'darwin') {
    return [
      join(HOME, 'Library', 'Application Support', 'Code', 'User', 'globalStorage'),
      join(HOME, 'Library', 'Application Support', 'Code - Insiders', 'User', 'globalStorage'),
      join(HOME, 'Library', 'Application Support', 'Cursor', 'User', 'globalStorage'),
    ];
  }
  if (process.platform === 'linux') {
    const configBase = process.env.XDG_CONFIG_HOME ?? join(HOME, '.config');
    return [
      join(configBase, 'Code', 'User', 'globalStorage'),
      join(configBase, 'Code - Insiders', 'User', 'globalStorage'),
      join(configBase, 'Cursor', 'User', 'globalStorage'),
    ];
  }
  const appData = process.env.APPDATA ?? join(HOME, 'AppData', 'Roaming');
  return [
    join(appData, 'Code', 'User', 'globalStorage'),
    join(appData, 'Code - Insiders', 'User', 'globalStorage'),
    join(appData, 'Cursor', 'User', 'globalStorage'),
  ];
}

async function getClineHistoryFiles() {
  const taskDirs = [];
  const extensionIds = ['saoudrizwan.claude-dev', 'rooveterinaryinc.roo-cline'];
  for (const basePath of getVSCodeGlobalStoragePaths()) {
    for (const extId of extensionIds) {
      const tasksDir = join(basePath, extId, 'tasks');
      if (existsSync(tasksDir)) taskDirs.push(tasksDir);
    }
  }
  const standalone = join(HOME, '.cline', 'data', 'tasks');
  if (existsSync(standalone)) taskDirs.push(standalone);

  const files = [];
  for (const tasksDir of taskDirs) {
    for (const entry of await entriesSafe(tasksDir)) {
      if (!entry.isDirectory()) continue;
      const taskId = entry.name;
      const historyFile = join(tasksDir, taskId, 'api_conversation_history.json');
      if (existsSync(historyFile)) files.push({ path: historyFile, taskId });
    }
  }
  return files;
}

async function* iterClineRecords(files) {
  for (const { path, taskId } of files) {
    const messages = await readJsonSafe(path);
    if (!Array.isArray(messages)) continue;
    let idx = 0;
    for (const msg of messages) {
      idx++;
      const role = normalizeRole(msg?.role);
      if (!role) continue;
      const text = textFromAnyContent(msg.content);
      if (!text.trim()) continue;
      yield {
        source: 'cline_history',
        loc: `${relative(HOME, path)}:${idx}`,
        timestamp: msg.ts ?? msg.timestamp ?? msg.createdAt,
        text,
        role,
        session: taskId,
      };
    }
  }
}

function getOpencodeDatabasePath() {
  const xdgPath = join(process.env.XDG_DATA_HOME ?? join(HOME, '.local', 'share'), 'opencode', 'opencode.db');
  if (existsSync(xdgPath)) return xdgPath;
  if (process.platform === 'darwin') {
    const macPath = join(HOME, 'Library', 'Application Support', 'opencode', 'opencode.db');
    if (existsSync(macPath)) return macPath;
  }
  return null;
}

async function sqliteJson(dbPath, query) {
  const sqlite = findExecutable('sqlite3');
  if (!sqlite) return [];
  return await new Promise((resolve) => {
    const child = spawn(sqlite, ['-readonly', '-json', dbPath, query], { stdio: ['ignore', 'pipe', 'ignore'] });
    let stdout = '';
    child.stdout.setEncoding('utf8');
    child.stdout.on('data', (chunk) => { stdout += chunk; });
    child.once('close', (code) => {
      if (code !== 0 || !stdout.trim()) return resolve([]);
      try {
        const rows = JSON.parse(stdout);
        resolve(Array.isArray(rows) ? rows : []);
      } catch {
        resolve([]);
      }
    });
    child.once('error', () => resolve([]));
  });
}

async function* iterOpencodeRecords(dbPath) {
  if (!dbPath) return;
  const rows = await sqliteJson(dbPath, `
    SELECT
      m.session_id AS session_id,
      m.time_created AS time_created,
      json_extract(m.data, '$.role') AS role,
      json_extract(p.data, '$.text') AS text
    FROM message m
    JOIN part p ON p.message_id = m.id
    WHERE json_extract(m.data, '$.role') IN ('user', 'assistant')
      AND json_extract(p.data, '$.type') = 'text'
    ORDER BY m.time_created ASC
  `);
  let idx = 0;
  for (const row of rows) {
    idx++;
    const role = normalizeRole(row.role);
    const text = row.text || '';
    if (!role || !String(text).trim()) continue;
    yield {
      source: 'opencode_db',
      loc: `${relative(HOME, dbPath)}:${idx}`,
      timestamp: row.time_created,
      text,
      role,
      session: row.session_id,
    };
  }
}

function getZedPaths() {
  if (process.platform === 'darwin') {
    const base = join(HOME, 'Library', 'Application Support', 'Zed');
    return { conversations: join(base, 'conversations'), db: join(base, 'db') };
  }
  const base = join(process.env.XDG_DATA_HOME ?? join(HOME, '.local', 'share'), 'zed');
  return { conversations: join(base, 'conversations'), db: join(base, 'db') };
}

async function* iterZedConversationRecords(paths) {
  for (const path of paths) {
    const conversation = await readJsonSafe(path);
    if (!Array.isArray(conversation?.messages)) continue;
    let idx = 0;
    for (const msg of conversation.messages) {
      idx++;
      const role = normalizeRole(msg?.role);
      if (!role) continue;
      const text = typeof msg.content === 'string' ? msg.content : textFromAnyContent(msg.content);
      if (!text.trim()) continue;
      yield {
        source: 'zed_conversation',
        loc: `${relative(HOME, path)}:${idx}`,
        timestamp: msg.timestamp ?? msg.createdAt,
        text,
        role,
      };
    }
  }
}

async function getZedDbFiles(dbDir) {
  return (await directFiles(dbDir)).filter((path) => path.endsWith('.db')).sort();
}

async function* iterZedDbRecords(dbFiles) {
  for (const dbPath of dbFiles) {
    const tables = await sqliteJson(dbPath, `SELECT name FROM sqlite_master WHERE type='table'`);
    const tableNames = tables.map((row) => row.name).filter(Boolean);
    const msgTable = tableNames.find((name) => name === 'messages' || name === 'thread_messages' || String(name).includes('message'));
    if (!msgTable) continue;
    const columns = await sqliteJson(dbPath, `PRAGMA table_info("${String(msgTable).replaceAll('"', '""')}")`);
    const colNames = columns.map((row) => row.name).filter(Boolean);
    if (!colNames.includes('role')) continue;
    const contentCol = colNames.includes('content') ? 'content' : colNames.includes('body') ? 'body' : colNames.includes('text') ? 'text' : null;
    if (!contentCol) continue;
    const rows = await sqliteJson(dbPath, `SELECT role, "${contentCol}" AS text FROM "${String(msgTable).replaceAll('"', '""')}" WHERE role IN ('user', 'assistant')`);
    let idx = 0;
    for (const row of rows) {
      idx++;
      const role = normalizeRole(row.role);
      const text = row.text || '';
      if (!role || !String(text).trim()) continue;
      yield {
        source: 'zed_db',
        loc: `${relative(HOME, dbPath)}:${idx}`,
        timestamp: null,
        text,
        role,
      };
    }
  }
}

async function scanRecords(records, { agentLabel, serviceLabels, credentialBlock, includeEvents, includeDetails, showValues, roles = DEFAULT_ROLES }) {
  const allowedRoles = new Set(roles);
  let scanned = 0;
  let eventCount = 0;
  let occurrenceCount = 0;
  const events = [];
  const details = [];
  const unique = new Set();
  const uniqueByRole = { user: new Set(), assistant: new Set() };
  const messagesByRole = emptyRoleCounts();
  const occurrencesByRole = emptyRoleCounts();
  const bySource = new Map();
  const kinds = new Map();
  const monthly = new Map();

  for await (const record of records) {
    const role = normalizeRole(record.role) ?? 'user';
    if (!allowedRoles.has(role)) continue;
    scanned++;
    const text = String(record.text);
    if (!SECRET_HINT.test(text)) continue;
    const hits = detectCredentials(text, { serviceLabels, credentialBlock });
    if (!hits.length) continue;

    eventCount++;
    occurrenceCount += hits.length;
    messagesByRole[role]++;
    occurrencesByRole[role] += hits.length;
    const month = ensureMonth(monthly, monthKey(record.timestamp));
    month.messages_with_credentials[role]++;
    month.credential_occurrences[role] += hits.length;

    const eventKinds = new Map();
    for (const { digest, kind, value } of hits) {
      unique.add(digest);
      uniqueByRole[role].add(digest);
      if (!bySource.has(record.source)) bySource.set(record.source, new Set());
      bySource.get(record.source).add(digest);
      kinds.set(kind, (kinds.get(kind) || 0) + 1);
      if (includeEvents) eventKinds.set(kind, (eventKinds.get(kind) || 0) + 1);
      if (includeDetails) {
        details.push({
          coding_agent: agentLabel,
          role,
          date: normalizeTimestamp(record.timestamp),
          key_type: keyTypeFromKind(kind),
          key_value: showValues ? clean(value) : redactValue(value),
          redacted: !showValues,
          detector: kind,
          source: record.source,
          loc: record.loc,
        });
      }
    }
    if (includeEvents) {
      events.push({
        source: record.source,
        loc: record.loc,
        timestamp: record.timestamp,
        role,
        matches: hits.length,
        kinds: Object.fromEntries([...eventKinds.entries()].sort()),
      });
    }
  }

  const result = {
    records_scanned: scanned,
    messages_with_credentials: eventCount,
    messages_with_credentials_by_role: messagesByRole,
    credential_occurrences: occurrenceCount,
    credential_occurrences_by_role: occurrencesByRole,
    distinct_credential_values: unique.size,
    distinct_credential_values_by_role: {
      user: uniqueByRole.user.size,
      assistant: uniqueByRole.assistant.size,
    },
    monthly_breakdown: [...monthly.values()].sort((a, b) => a.month.localeCompare(b.month)),
    distinct_by_source: Object.fromEntries([...bySource.entries()].map(([source, values]) => [source, values.size])),
    counts_by_kind: Object.fromEntries([...kinds.entries()].sort((a, b) => b[1] - a[1])),
  };
  Object.defineProperty(result, '_credential_digests', { value: unique, enumerable: false });
  if (includeEvents) result.events_redacted_metadata = events;
  if (includeDetails) result.credential_details = details;
  return result;
}

function mergeMonthlyBreakdowns(scanResults) {
  const monthly = new Map();
  for (const result of Object.values(scanResults)) {
    for (const row of result.monthly_breakdown ?? []) {
      const target = ensureMonth(monthly, row.month);
      for (const role of DEFAULT_ROLES) {
        target.messages_with_credentials[role] += row.messages_with_credentials?.[role] ?? 0;
        target.credential_occurrences[role] += row.credential_occurrences?.[role] ?? 0;
      }
    }
  }
  return [...monthly.values()].sort((a, b) => a.month.localeCompare(b.month));
}

function mergeRoleCounts(scanResults, field) {
  const counts = emptyRoleCounts();
  for (const result of Object.values(scanResults)) {
    for (const role of DEFAULT_ROLES) counts[role] += result[field]?.[role] ?? 0;
  }
  return counts;
}

function sumResults(scanResults, field) {
  return Object.values(scanResults).reduce((sum, result) => sum + (result[field] ?? 0), 0);
}

function mergeDistinctCredentialCount(scanResults) {
  const digests = new Set();
  for (const result of Object.values(scanResults)) {
    for (const digest of result._credential_digests ?? []) digests.add(digest);
  }
  return digests.size;
}

export async function buildReport({ includeEvents = false, includeDetails = false, showValues = false, parallel = false, agents = ALL_AGENT_KEYS, includeInventory = false, roles = DEFAULT_ROLES } = {}) {
  const selected = new Set((agents?.length ? agents : ALL_AGENT_KEYS).filter((key) => ALL_AGENT_KEYS.includes(key)));
  const selectedRoles = (roles?.length ? roles : DEFAULT_ROLES).filter((role) => VALID_ROLES.has(role));
  const inventory = {};
  const scanOptions = (agentLabel, serviceLabels = true, credentialBlock = false) => ({
    agentLabel,
    serviceLabels,
    credentialBlock,
    includeEvents,
    includeDetails,
    showValues,
    roles: selectedRoles,
  });

  const scannerFactories = {
    pi_agent: async () => {
      const root = join(HOME, '.pi', 'agent', 'sessions');
      const paths = await directJsonlTwoLevel(root);
      if (includeInventory) inventory.pi_top_level_session_files = paths.length;
      return scanRecords(iterPiRecordsFast(paths), scanOptions('pi', false, true));
    },
    claude_code: async () => {
      const projectsRoot = join(HOME, '.claude', 'projects');
      const pasteRoot = join(HOME, '.claude', 'paste-cache');
      const projectPaths = await directJsonlTwoLevel(projectsRoot);
      const pastePaths = await directFiles(pasteRoot);
      if (includeInventory) {
        const nestedPaths = (await recursiveJsonl(projectsRoot)).filter((path) => !projectPaths.includes(path));
        inventory.claude_history_lines = await lineCount(join(HOME, '.claude', 'history.jsonl'));
        inventory.claude_project_direct_files = projectPaths.length;
        inventory.claude_project_nested_files_excluded = nestedPaths.length;
        inventory.claude_paste_cache_files = pastePaths.length;
      }
      return scanRecords((async function* () {
        yield* iterClaudeHistoryRecords();
        yield* iterClaudeProjectRecordsFast(projectPaths);
        yield* iterClaudePasteCacheRecords(pastePaths);
      })(), scanOptions('claude'));
    },
    codex: async () => {
      const sessionPaths = await recursiveJsonl(join(HOME, '.codex', 'sessions'));
      const archivedPaths = (await directFiles(join(HOME, '.codex', 'archived_sessions'))).filter((path) => path.endsWith('.jsonl')).sort();
      if (includeInventory) {
        inventory.codex_history_lines = await lineCount(join(HOME, '.codex', 'history.jsonl'));
        inventory.codex_session_files = sessionPaths.length;
        inventory.codex_archived_session_files = archivedPaths.length;
      }
      return scanRecords((async function* () {
        yield* iterCodexHistoryRecords();
        yield* iterCodexSessionRecordsFast([...sessionPaths, ...archivedPaths]);
      })(), scanOptions('codex'));
    },
    amp: async () => {
      const paths = await directJsonFiles(getAmpThreadsDir());
      if (includeInventory) inventory.amp_thread_files = paths.length;
      return scanRecords(iterAmpRecords(paths), scanOptions('amp'));
    },
    opencode: async () => {
      const dbPath = getOpencodeDatabasePath();
      if (includeInventory) inventory.opencode_db_found = Boolean(dbPath);
      return scanRecords(iterOpencodeRecords(dbPath), scanOptions('opencode'));
    },
    cline: async () => {
      const files = await getClineHistoryFiles();
      if (includeInventory) inventory.cline_history_files = files.length;
      return scanRecords(iterClineRecords(files), scanOptions('cline'));
    },
    zed: async () => {
      const paths = getZedPaths();
      const conversationPaths = await directJsonFiles(paths.conversations);
      const dbFiles = await getZedDbFiles(paths.db);
      if (includeInventory) {
        inventory.zed_conversation_files = conversationPaths.length;
        inventory.zed_db_files = dbFiles.length;
      }
      return scanRecords((async function* () {
        yield* iterZedConversationRecords(conversationPaths);
        yield* iterZedDbRecords(dbFiles);
      })(), scanOptions('zed'));
    },
  };

  const orderedKeys = ALL_AGENT_KEYS.filter((key) => selected.has(key));
  const scanResults = parallel
    ? Object.fromEntries(await Promise.all(orderedKeys.map(async (key) => [key, await scannerFactories[key]()])))
    : {};
  if (!parallel) {
    for (const key of orderedKeys) scanResults[key] = await scannerFactories[key]();
  }

  const report = {
    generated_at: new Date().toISOString(),
    roles_scanned: selectedRoles,
    records_scanned: sumResults(scanResults, 'records_scanned'),
    messages_with_credentials: sumResults(scanResults, 'messages_with_credentials'),
    credential_occurrences: sumResults(scanResults, 'credential_occurrences'),
    distinct_credential_values: mergeDistinctCredentialCount(scanResults),
    monthly_breakdown: mergeMonthlyBreakdowns(scanResults),
    role_breakdown: {
      messages_with_credentials: mergeRoleCounts(scanResults, 'messages_with_credentials_by_role'),
      credential_occurrences: mergeRoleCounts(scanResults, 'credential_occurrences_by_role'),
    },
    ...scanResults,
    notes: [
      'Secret values are redacted unless --show-values is passed.',
      'Counts are heuristic and tuned to avoid code/docs/tool-result false positives.',
      includeEvents ? 'events_redacted_metadata contains only source, location, timestamp, count, and detector kind.' : 'Run with --events to include redacted per-event metadata after the summary sections.',
    ],
  };
  if (includeInventory) report.inventory = inventory;
  return report;
}

function detectText(text) {
  return detectCredentials(String(text ?? ''), { serviceLabels: true, credentialBlock: false })
    .map(({ kind, value }) => ({ kind, key_type: keyTypeFromKind(kind), redacted: redactValue(value) }));
}

export { TOOL_LABELS, ALL_AGENT_KEYS, DEFAULT_ROLES, detectText };
