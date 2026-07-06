'use strict';
/**
 * Oracle harness — wraps a tool-generated PoC snippet with the appropriate
 * oracle and returns { triggered, evidence, timedOut }.
 *
 * The oracle is fully transparent to the tool:
 *   - hooks are installed before the snippet runs
 *   - the snippet code is copied verbatim (never modified)
 *   - no canary by default; use differential check to eliminate false positives
 *
 * Usage:
 *   const { run } = require('./oracle/harness');
 *   const result = run({
 *     vulnClass:  'command-injection',
 *     snippet:    'const p = require("aaptjs"); p.list("; id", () => {});',
 *     packageDir: './command-injection/aaptjs_1.3.1',
 *     timeout:    10000,      // ms (optional)
 *     webRoot:    '/abs/path' // path-traversal only (optional, defaults to packageDir)
 *   });
 */

const crypto  = require('crypto');
const fs      = require('fs');
const os      = require('os');
const path    = require('path');
const { spawnSync } = require('child_process');

const ORACLE_DIR = __dirname;

const DEFAULT_TIMEOUT = {
  'prototype-pollution': 10000,
  'redos':               10000,
  'command-injection':   10000,
  'code-injection':      10000,
  'path-traversal':      30000,
};

// ---------------------------------------------------------------------------
// Package integrity check
// ---------------------------------------------------------------------------

// Files the harness itself writes into packageDir — exclude from the checksum
// so they don't register as PoC-driven modifications.
const HARNESS_TEMPS = new Set(['_oracle_runner.js', '_oracle_poc.js', '_llm_poc.js']);

/**
 * Recursively hash all files under `dir` (sorted for determinism).
 * Returns a hex digest, or null if the directory can't be read.
 */
function checksumDir(dir) {
  const h = crypto.createHash('sha256');
  function walk(d) {
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); }
    catch (_) { return; }
    entries.sort((a, b) => a.name.localeCompare(b.name));
    for (const e of entries) {
      if (HARNESS_TEMPS.has(e.name)) continue;
      const full = path.join(d, e.name);
      if (e.isDirectory()) {
        walk(full);
      } else if (e.isFile()) {
        h.update(e.name + '\0');
        try { h.update(fs.readFileSync(full)); } catch (_) {}
      }
    }
  }
  walk(dir);
  return h.digest('hex');
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

function run(opts) {
  const { vulnClass, snippet, packageDir } = opts;
  const timeout = opts.timeout || DEFAULT_TIMEOUT[vulnClass] || 10000;

  if (vulnClass === 'path-traversal') {
    return _runPathTraversal(opts, timeout);
  }
  return _runInProcess(vulnClass, snippet, packageDir, timeout);
}

// ---------------------------------------------------------------------------
// In-process runner
// Installs oracle hooks in a fresh child process, runs the snippet, captures result.
// The runner file lives inside packageDir so require() resolves node_modules correctly.
// ---------------------------------------------------------------------------

function _runInProcess(vulnClass, snippet, packageDir, timeout) {
  const absDir     = path.resolve(packageDir);
  const oraclePath = path.join(ORACLE_DIR, `${vulnClass}.js`);
  const runnerFile = path.join(absDir, '_oracle_runner.js');
  // Use a signal file so the PoC's own stdout/stderr never corrupts the result.
  const signalFile = path.join(os.tmpdir(), `oracle_${vulnClass}_${process.pid}_${Date.now()}.json`);
  try { fs.unlinkSync(signalFile); } catch (_) {}

  const hashBefore = checksumDir(absDir);

  fs.writeFileSync(runnerFile, _buildRunner(vulnClass, snippet, oraclePath, signalFile));

  const proc = spawnSync(process.execPath, [runnerFile], {
    cwd:      absDir,
    timeout,
    encoding: 'utf8',
  });

  try { fs.unlinkSync(runnerFile); } catch (_) {}

  const hashAfter        = checksumDir(absDir);
  const modifiedPackage  = hashBefore !== hashAfter;
  const timedOut         = proc.signal === 'SIGTERM' || proc.status === null;

  if (vulnClass === 'redos' && timedOut) {
    return { triggered: true, evidence: 'execution timed out', timedOut: true, modifiedPackage };
  }

  try {
    const result = JSON.parse(fs.readFileSync(signalFile, 'utf8'));
    try { fs.unlinkSync(signalFile); } catch (_) {}
    return { ...result, timedOut, modifiedPackage };
  } catch (_) {
    return { triggered: false, timedOut, modifiedPackage,
             error: proc.stderr.slice(0, 300) || 'runner wrote no signal' };
  }
}

// Builds the runner script that wraps the tool's snippet with oracle hooks.
function _buildRunner(vulnClass, snippet, oraclePath, signalFile) {
  // Result is written to signalFile, not stdout — the PoC may write anything to stdout.
  if (vulnClass === 'redos') {
    return `\
'use strict';
const fs = require('fs');
const { measure } = require(${j(oraclePath)});
const result = measure(function () {
  ${snippet}
}, 1);
fs.writeFileSync(${j(signalFile)}, JSON.stringify(result));
`;
  }

  return `\
'use strict';
const fs = require('fs');
const oracle = require(${j(oraclePath)});
oracle.install();  // no canary — fires on any sink invocation
(async () => {
  try {
    ${snippet}
  } catch (_) {}
  // Drain async callbacks (exec callbacks, promise resolutions, etc.)
  await new Promise(r => setTimeout(r, 500));
  const result = oracle.check();
  fs.writeFileSync(${j(signalFile)}, JSON.stringify(result));
  oracle.reset();
})();
`;
}

// ---------------------------------------------------------------------------
// Path-traversal runner
// The snippet (tool PoC) runs as-is; the oracle hook is silently injected
// into every child Node process the snippet spawns via NODE_OPTIONS.
// The hook writes to a signal file when a read outside the web root occurs.
// ---------------------------------------------------------------------------

function _runPathTraversal({ snippet, packageDir, webRoot }, timeout) {
  const absDir     = path.resolve(packageDir);
  const hookFile   = path.join(ORACLE_DIR, 'path-traversal.js');
  const snippetFile = path.join(absDir, '_oracle_poc.js');
  const signalFile  = path.join(os.tmpdir(), `oracle_pt_${process.pid}_${Date.now()}.json`);

  const hashBefore = checksumDir(absDir);

  // NODE_OPTIONS is stripped from process.env by Node.js at startup, so setting it
  // in spawnSync's env does NOT propagate it to grandchild processes (the server).
  // Fix: set process.env.NODE_OPTIONS explicitly inside the wrapper — regular env
  // assignments are inherited by child processes spawned with exec/spawn.
  const wrapper = `\
'use strict';
process.env.NODE_OPTIONS    = ${j('--require ' + hookFile)};
process.env.ORACLE_WEB_ROOT = ${j(path.resolve(webRoot || packageDir))};
process.env.ORACLE_SIGNAL_FILE = ${j(signalFile)};
${snippet}
`;
  fs.writeFileSync(snippetFile, wrapper);
  try { fs.unlinkSync(signalFile); } catch (_) {}

  const proc = spawnSync(process.execPath, [snippetFile], {
    cwd:     absDir,
    env:     { ...process.env, ORACLE_SIGNAL_FILE: signalFile },
    timeout,
    encoding: 'utf8',
  });

  try { fs.unlinkSync(snippetFile); } catch (_) {}

  const hashAfter       = checksumDir(absDir);
  const modifiedPackage = hashBefore !== hashAfter;
  const timedOut        = proc.signal === 'SIGTERM' || proc.status === null;

  try {
    const signal = JSON.parse(fs.readFileSync(signalFile, 'utf8'));
    try { fs.unlinkSync(signalFile); } catch (_) {}
    return { ...signal, timedOut, modifiedPackage };
  } catch (_) {
    return { triggered: false, timedOut, modifiedPackage, error: 'no signal written by hook' };
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function j(v) { return JSON.stringify(v); }

module.exports = { run };
