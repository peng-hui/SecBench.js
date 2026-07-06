'use strict';

const vm = require('vm');

const VM_METHODS = ['runInNewContext', 'runInThisContext', 'runInContext'];
const _originals = {};

const _origEval = global.eval;
const _origFunction = global.Function;

let _triggered = false;
let _evidence = null;
let _canary = null;

function install(canary) {
  _triggered = false;
  _evidence = null;
  _canary = canary || process.env.ORACLE_CANARY || null;

  function flag(code) {
    const str = String(code);
    if (!_canary || str.includes(_canary)) {
      _triggered = true;
      _evidence = str.slice(0, 300);
    }
  }

  // Hook eval — catches eval('...')
  global.eval = function (code) {
    flag(code);
    return _origEval.call(this, code);
  };

  // Hook Function constructor — catches new Function('...') and Function('...')
  global.Function = function (...args) {
    if (args.length > 0) flag(args[args.length - 1]);
    return new _origFunction(...args);
  };
  Object.setPrototypeOf(global.Function, _origFunction);
  global.Function.prototype = _origFunction.prototype;

  // Hook vm methods
  for (const method of VM_METHODS) {
    _originals[method] = vm[method];
    vm[method] = function (code, ...rest) {
      if (typeof code === 'string') flag(code);
      return _originals[method].call(vm, code, ...rest);
    };
  }
}

function check() {
  return { triggered: _triggered, evidence: _evidence };
}

function reset() {
  global.eval = _origEval;
  global.Function = _origFunction;
  for (const method of VM_METHODS) {
    if (_originals[method]) vm[method] = _originals[method];
  }
  _triggered = false;
  _evidence = null;
  _canary = null;
}

module.exports = { install, check, reset };
