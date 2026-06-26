#!/usr/bin/env node
'use strict';
/**
 * CLI wrapper around oracle/harness.js.
 * Reads the PoC snippet from a file, runs the oracle, prints JSON to stdout.
 *
 * Usage:
 *   node oracle/run.js \
 *     --class      command-injection \
 *     --package-dir ./command-injection/aaptjs_1.3.1 \
 *     --snippet-file /path/to/poc.js \
 *     [--timeout 10000] \
 *     [--web-root /abs/path]
 *
 * Exit codes:
 *   0  triggered (vulnerability confirmed)
 *   1  not triggered or error
 */

const fs   = require('fs');
const path = require('path');
const { run } = require('./harness');

function parseArgs(argv) {
  const args = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--')) {
      args[argv[i].slice(2)] = argv[i + 1];
      i++;
    }
  }
  return args;
}

const args = parseArgs(process.argv.slice(2));

const vulnClass   = args['class'];
const packageDir  = args['package-dir'];
const snippetFile = args['snippet-file'];
const timeout     = args['timeout'] ? parseInt(args['timeout']) : undefined;
const webRoot     = args['web-root'];

if (!vulnClass || !packageDir || !snippetFile) {
  process.stderr.write(
    'Usage: node oracle/run.js --class <class> --package-dir <dir> --snippet-file <file>\n'
  );
  process.exit(2);
}

let snippet;
try {
  snippet = fs.readFileSync(snippetFile, 'utf8');
} catch (e) {
  process.stderr.write(`Cannot read snippet file: ${e.message}\n`);
  process.exit(2);
}

const result = run({ vulnClass, snippet, packageDir, timeout, webRoot });

process.stdout.write(JSON.stringify(result, null, 2) + '\n');
process.exit(result.triggered ? 0 : 1);
