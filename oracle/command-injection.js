'use strict';

const cp = require('child_process');

// All child_process methods that execute shell commands
const METHODS = ['exec', 'execSync', 'execFile', 'execFileSync', 'spawn', 'spawnSync'];
const _originals = {};

let _triggered = false;
let _evidence = null;
let _canary = null;

function install(canary) {
  _triggered = false;
  _evidence = null;
  _canary = canary || process.env.ORACLE_CANARY || null;

  for (const method of METHODS) {
    _originals[method] = cp[method];
    cp[method] = function (...args) {
      const cmd = _extractCmd(method, args);
      // Without canary: any exec call counts (use differential check to remove false positives)
      // With canary: only flag if attacker-controlled canary reached the sink
      if (!_canary || cmd.includes(_canary)) {
        _triggered = true;
        _evidence = cmd.slice(0, 300);
      }
      return _originals[method].apply(this, args);
    };
  }
}

function _extractCmd(method, args) {
  const first = args[0];
  if (typeof first === 'string') return first;
  if (method === 'spawn' || method === 'spawnSync') {
    const argv = Array.isArray(args[1]) ? args[1].join(' ') : '';
    return `${first} ${argv}`;
  }
  return String(first);
}

function check() {
  return { triggered: _triggered, evidence: _evidence };
}

function reset() {
  for (const method of METHODS) {
    if (_originals[method]) cp[method] = _originals[method];
  }
  _triggered = false;
  _evidence = null;
  _canary = null;
}

module.exports = { install, check, reset };
