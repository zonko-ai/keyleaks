#!/usr/bin/env node
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';

const env = {
  ...process.env,
  KEYLEAKS_FORCE_LOADER: '1',
  NO_COLOR: '1',
};

const result = spawnSync(process.execPath, ['bin/keyleaks.js', '--agent', 'codex'], {
  cwd: process.cwd(),
  env,
  encoding: 'utf8',
});

assert.equal(result.status, 0, result.stderr || result.stdout);
assert.match(result.stderr, /agents access keys through envs\.\.\./);
assert.match(result.stderr, /scanning user and assistant responses\.\.\./);
assert.doesNotMatch(result.stdout, /agents access keys through envs/);
assert.doesNotMatch(result.stdout, /scanning user and assistant responses/);

const jsonResult = spawnSync(process.execPath, ['bin/keyleaks.js', '--json', '--agent', 'codex'], {
  cwd: process.cwd(),
  env,
  encoding: 'utf8',
});

assert.equal(jsonResult.status, 0, jsonResult.stderr || jsonResult.stdout);
assert.doesNotMatch(jsonResult.stderr, /agents access keys through envs/);
assert.doesNotMatch(jsonResult.stderr, /scanning user and assistant responses/);
JSON.parse(jsonResult.stdout);

console.log('cli loader ok');
