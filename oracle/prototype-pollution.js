'use strict';

let _snapshot = null;

function install() {
  _snapshot = new Set(Object.getOwnPropertyNames(Object.prototype));
}

function check() {
  const after = Object.getOwnPropertyNames(Object.prototype);
  const added = after.filter(k => !_snapshot.has(k));
  return { triggered: added.length > 0, evidence: added };
}

function reset() {
  if (_snapshot) {
    for (const k of Object.getOwnPropertyNames(Object.prototype)) {
      if (!_snapshot.has(k)) {
        try { delete Object.prototype[k]; } catch (e) {}
      }
    }
  }
  _snapshot = null;
}

module.exports = { install, check, reset };
