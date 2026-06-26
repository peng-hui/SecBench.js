'use strict';
/**
 * Path-traversal oracle — server-side fs hook.
 *
 * Designed to be preloaded into the server child process:
 *   NODE_OPTIONS="--require /abs/path/to/path-traversal.js"
 *
 * Hooks all fs read entry-points. When any read resolves to a path
 * outside ORACLE_WEB_ROOT, writes { triggered, evidence } to ORACLE_SIGNAL_FILE.
 *
 * Both env vars must be set by the harness before the server starts.
 */

const fs   = require('fs');
const path = require('path');

const WEB_ROOT   = path.resolve(process.env.ORACLE_WEB_ROOT  || process.cwd());
const SIGNAL_FILE = process.env.ORACLE_SIGNAL_FILE;

function isOutsideRoot(filePath) {
  if (typeof filePath !== 'string') return false;
  try {
    const resolved = fs.realpathSync(filePath);
    return !resolved.startsWith(WEB_ROOT + path.sep) && resolved !== WEB_ROOT;
  } catch (_) {
    // File may not exist yet (traversal attempt on non-existent file) — check normalised path
    const normalised = path.resolve(filePath);
    return !normalised.startsWith(WEB_ROOT + path.sep) && normalised !== WEB_ROOT;
  }
}

function flag(filePath) {
  if (!SIGNAL_FILE) return;
  if (isOutsideRoot(filePath)) {
    try {
      fs.writeFileSync(SIGNAL_FILE, JSON.stringify({ triggered: true, evidence: filePath }));
    } catch (_) {}
  }
}

const READ_OPS = ['readFile', 'readFileSync', 'createReadStream', 'open', 'openSync'];
for (const op of READ_OPS) {
  const orig = fs[op];
  fs[op] = function (p, ...args) {
    flag(p);
    return orig.call(this, p, ...args);
  };
}
