#!/usr/bin/env python3
"""
Reads all result JSON files and prints the summary metrics table from GOALS.md.

Conditions compared:
  original     — unobfuscated library source
  obfuscated   — library source after javascript-obfuscator (default settings)
  deobfuscated — obfuscated source run through webcrack, then tested

Metrics:
  Static  — detection rate, classification accuracy, sink API accuracy, localization accuracy
  Dynamic — PoC success rate (TRUE_POSITIVE or PASS), false-positive rate

Usage:
  python3 aggregate_results.py
  python3 aggregate_results.py --by-category
"""

import argparse
import json
import os
from pathlib import Path

ROOT = Path(__file__).parent

CATEGORIES = [
    "prototype-pollution",
    "redos",
    "command-injection",
    "path-traversal",
    "code-injection",
]

# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def load_json(path):
    p = ROOT / path
    if not p.exists():
        return None
    with open(p) as f:
        return json.load(f)


def load_static(path="static_analysis_results.json"):
    data = load_json(path)
    if not data:
        return {}
    # Index by (module_id, state)
    idx = {}
    for r in data.get("results", []):
        idx[(r["module_id"], r["state"])] = r
    return idx


def load_poc_baseline(path="poc_test_results.json"):
    """Returns dict: (category, module) → status."""
    data = load_json(path)
    if not data:
        return {}
    idx = {}
    for cat, entries in data.get("results", {}).items():
        for e in entries:
            idx[(cat, e["module"])] = e["status"]
    return idx


def load_poc_condition(path):
    """Returns dict: (category, module) → status.
    Handles poc_obfuscated_results.json, poc_webcrack_results.json, etc."""
    data = load_json(path)
    if not data:
        return {}
    idx = {}
    for cat, entries in data.get("results", {}).items():
        for e in entries:
            idx[(cat, e["module"])] = e["status"]
    return idx


def load_anon_poc(path, ground_truth_path="oracle/ground_truth.json"):
    """
    Returns dict: (category, module) → status from evaluate_anon_results.json.
    The anonymous results use module_id keys; we translate via ground_truth.
    """
    data     = load_json(path)
    gt_data  = load_json(ground_truth_path)
    if not data or not gt_data:
        return {}
    idx = {}
    for condition, entries in data.get("results", {}).items():
        for e in entries:
            mid  = e.get("module_id")
            info = gt_data.get(mid, {})
            cat  = info.get("category")
            mod  = info.get("module")
            if cat and mod:
                # key includes condition so callers can filter by it
                idx[(condition, cat, mod)] = e["status"]
    return idx


# ---------------------------------------------------------------------------
# Metrics computation
# ---------------------------------------------------------------------------

def static_metrics(static_idx, state, category=None):
    """Compute static detection/classification/localization rates for one state."""
    subset = [
        r for (mid, st), r in static_idx.items()
        if st == state
        and (category is None or r.get("category") == category)
        and not r.get("parse_error")
        and not r.get("timeout")
        and not r.get("error")
    ]
    n = len(subset)
    if n == 0:
        return {"n": 0, "detect": None, "classify": None, "sink_api": None, "locate": None}
    n_detect   = sum(1 for r in subset if r.get("vulnerable_detected"))
    n_classify = sum(1 for r in subset if r.get("type_correct"))
    n_sink_api = sum(1 for r in subset if r.get("sink_api_correct"))
    n_locate   = sum(1 for r in subset if r.get("location_correct"))
    return {
        "n":        n,
        "detect":   n_detect   / n,
        "classify": n_classify / n,
        "sink_api": n_sink_api / n,
        "locate":   n_locate   / n,
    }


def dynamic_metrics(poc_idx, category=None):
    """Compute PoC success rate and false-positive rate."""
    subset = {
        (cat, mod): status
        for (cat, mod), status in poc_idx.items()
        if (category is None or cat == category)
    }
    n = len(subset)
    if n == 0:
        return {"n": 0, "success": None, "fp": None}

    # PASS or TRUE_POSITIVE = success; FALSE_POSITIVE = fp
    n_success = sum(1 for s in subset.values() if s in ("PASS", "TRUE_POSITIVE"))
    n_fp      = sum(1 for s in subset.values() if s == "FALSE_POSITIVE")
    return {
        "n":       n,
        "success": n_success / n,
        "fp":      n_fp      / n,
    }


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def pct(v):
    if v is None:
        return "  N/A  "
    return f"{v:6.1%}"


def row(condition, sm_detect, sm_classify, sm_api, sm_locate, dm_success, dm_fp):
    return (
        f"{condition:<22} "
        f"{pct(sm_detect)} "
        f"{pct(sm_classify)} "
        f"{pct(sm_api)} "
        f"{pct(sm_locate)} "
        f"{pct(dm_success)} "
        f"{pct(dm_fp)}"
    )


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--by-category", action="store_true",
                    help="Print per-category breakdown in addition to overall table")
    args = ap.parse_args()

    static_idx   = load_static()
    poc_baseline = load_poc_baseline()
    poc_obf      = load_poc_condition("poc_obfuscated_results.json")
    poc_webcrack = load_poc_condition("poc_webcrack_results.json")
    poc_deobf    = load_poc_condition("poc_deobfuscated_results.json")

    # ── Overall table ─────────────────────────────────────────────────────
    header = (
        f"{'Condition':<22} "
        f"{'Detect':>7} "
        f"{'Classify':>8} "
        f"{'SinkAPI':>7} "
        f"{'Locate':>7} "
        f"{'DynPoC':>7} "
        f"{'FP rate':>7}"
    )
    sep = "-" * len(header)

    print(f"\n{'='*len(header)}")
    print("OVERALL METRICS (n=50 modules)")
    print(f"{'='*len(header)}")
    print(header)
    print(sep)

    conditions = [
        # (label, static_state, poc_idx)
        ("original",      "original",   poc_baseline),
        ("obfuscated",    "obfuscated", poc_obf),
        ("obf+webcrack",  "webcrack",   poc_webcrack),
        ("obf+synchrony", "obfuscated", poc_deobf),
    ]

    for label, static_state, poc_idx in conditions:
        sm  = static_metrics(static_idx, static_state)
        dm  = dynamic_metrics(poc_idx)
        print(row(label, sm["detect"], sm["classify"], sm["sink_api"], sm["locate"],
                  dm["success"], dm["fp"]))
    print(sep)
    print(f"  Detect   = static vuln_detected rate")
    print(f"  Classify = static type_correct rate")
    print(f"  SinkAPI  = static sink_api_correct rate (built-in API identified)")
    print(f"  Locate   = static sink file+line correct (±{5} lines)")
    print(f"  DynPoC   = PoC triggers on vuln version (PASS/TRUE_POSITIVE)")
    print(f"  FP rate  = PoC triggers on both versions (FALSE_POSITIVE)")

    # ── Anonymous PoC results (evaluate_anon.py) ─────────────────────────────
    anon_idx = load_anon_poc("eval_anon_results.json")
    if anon_idx:
        print(f"\n{'='*len(header)}")
        print("LLM-GENERATED PoC — ANONYMOUS BENCHMARK (no CVE/sink hints given)")
        print(f"{'='*len(header)}")
        print(f"{'Condition':<22} {'DynPoC':>7} {'FP rate':>7}")
        print(f"{'-'*40}")
        for cond_label in ["original", "obfuscated", "webcrack"]:
            subset = {(cat, mod): st for (cond, cat, mod), st in anon_idx.items()
                      if cond == cond_label}
            n = len(subset)
            if n == 0:
                continue
            n_tp = sum(1 for s in subset.values() if s in ("TRUE_POSITIVE", "PASS"))
            n_fp = sum(1 for s in subset.values() if s == "FALSE_POSITIVE")
            print(f"{cond_label:<22} {pct(n_tp/n)} {pct(n_fp/n)}")
        print(f"{'-'*40}")
        print("  DynPoC = PoC triggers using only vuln class + source (no sink hint)")

    if not args.by_category:
        return

    # ── Per-category breakdown ─────────────────────────────────────────────
    for cat in CATEGORIES:
        print(f"\n{'='*len(header)}")
        print(f"CATEGORY: {cat.upper()}")
        print(f"{'='*len(header)}")
        print(header)
        print(sep)
        for label, static_state, poc_idx in conditions:
            sm = static_metrics(static_idx, static_state, category=cat)
            dm = dynamic_metrics(poc_idx, category=cat)
            print(row(label, sm["detect"], sm["classify"], sm["sink_api"], sm["locate"],
                      dm["success"], dm["fp"]))
        print(sep)


if __name__ == "__main__":
    main()
