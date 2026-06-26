'use strict';

const DEFAULT_THRESHOLD_S = 1;

// Run fn synchronously and measure wall-clock time.
// For snippets that might truly hang, use the harness timeout instead.
function measure(fn, thresholdSeconds) {
  thresholdSeconds = thresholdSeconds || DEFAULT_THRESHOLD_S;
  const start = process.hrtime();
  try { fn(); } catch (e) {}
  const [s, ns] = process.hrtime(start);
  const seconds = s + ns / 1e9;
  return { triggered: seconds > thresholdSeconds, seconds };
}

module.exports = { measure, DEFAULT_THRESHOLD_S };
