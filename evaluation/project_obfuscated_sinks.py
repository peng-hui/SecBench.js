#!/usr/bin/env python3
"""
Derive sink positions in obfuscated library source using API-name matching.

javascript-obfuscator renames user-defined identifiers but cannot rename
built-in API names (fs.readFile, exec, eval, __proto__, etc.).  This script
scans the obfuscated source for calls to the known category-level sink APIs
and records the first match as the obfuscated sink location.

Output: oracle/obfuscated_ground_truth.json
  — same schema as oracle/ground_truth.json but with:
      sink_file, sink_line, sink_col  →  positions in the OBFUSCATED source
      sink_file_orig, sink_line_orig, sink_col_orig  →  original positions (kept for reference)

Usage:
  python3 project_obfuscated_sinks.py

The obfuscated benchmark is read from static-benchmark-obfuscated/.
"""

import json
import os
import re
from pathlib import Path

ROOT = Path(__file__).parent

GT_ORIG  = ROOT / "oracle" / "ground_truth.json"
GT_OBF   = ROOT / "oracle" / "obfuscated_ground_truth.json"
OBF_DIR  = ROOT / "static-benchmark" / "obfuscated"

# API patterns to search for per category.
# Each entry is (call_regex, string_literal_regex).
# call_regex: matches the actual call site (may not survive obfuscation).
# string_literal_regex: matches the API name as a string literal in obfuscator
#   string arrays (survives obfuscation — obfuscator can't hide the string value).
API_PATTERNS = {
    # prototype-pollution
    "__proto__":             (r'__proto__',                  r'[\'"]__proto__[\'"]'),
    "constructor.prototype": (r'constructor\s*\.\s*prototype',r'[\'"]prototype[\'"]'),
    # redos — look for regex method calls
    "RegExp.exec":           (r'\.exec\s*\(',               r'[\'"]exec[\'"]'),
    "RegExp.test":           (r'\.test\s*\(',               r'[\'"]test[\'"]'),
    "String.match":          (r'\.match\s*\(',              r'[\'"]match[\'"]'),
    "String.replace":        (r'\.replace\s*\(',            r'[\'"]replace[\'"]'),
    "String.search":         (r'\.search\s*\(',             r'[\'"]search[\'"]'),
    "String.split":          (r'\.split\s*\(',              r'[\'"]split[\'"]'),
    # command-injection
    "child_process.exec":    (r'\.exec\s*\(',               r'[\'"]exec[\'"]'),
    "child_process.execSync":(r'\.execSync\s*\(',           r'[\'"]execSync[\'"]'),
    "child_process.spawn":   (r'\.spawn\s*\(',              r'[\'"]spawn[\'"]'),
    "child_process.spawnSync":(r'\.spawnSync\s*\(',         r'[\'"]spawnSync[\'"]'),
    # path-traversal
    "fs.readFile":           (r'\.readFile\s*\(',           r'[\'"]readFile[\'"]'),
    "fs.readFileSync":       (r'\.readFileSync\s*\(',       r'[\'"]readFileSync[\'"]'),
    "fs.createReadStream":   (r'\.createReadStream\s*\(',   r'[\'"]createReadStream[\'"]'),
    # code-injection
    "eval":                  (r'\beval\s*\(',               r'[\'"]eval[\'"]'),
    "new Function":          (r'\bnew\s+Function\s*\(',     r'[\'"]Function[\'"]'),
    "vm.runInNewContext":     (r'\.runInNewContext\s*\(',   r'[\'"]runInNewContext[\'"]'),
    "vm.runInThisContext":    (r'\.runInThisContext\s*\(',  r'[\'"]runInThisContext[\'"]'),
}


def find_sink_in_source(js_path: Path, sink_apis: list[str]) -> dict | None:
    """
    Scan a JS file for any of the given sink_api patterns.

    Strategy:
    1. First pass: look for call-site patterns (e.g. `.readFile(`).
       These are precise but may be hidden by obfuscation.
    2. Second pass: look for string-literal patterns (e.g. 'readFile').
       These survive obfuscation because the obfuscator must preserve the value
       of strings that are passed to dynamic property access.

    Returns the first match as {"api", "line", "col", "via"} or None.
    """
    try:
        text = js_path.read_text(errors="ignore")
    except OSError:
        return None

    lines = text.splitlines()

    # Pass 1 — call sites
    for api in sink_apis:
        entry = API_PATTERNS.get(api)
        if not entry:
            continue
        call_pat, _ = entry
        for lineno, line in enumerate(lines, 1):
            m = re.search(call_pat, line)
            if m:
                return {"api": api, "col": m.start() + 1, "line": lineno, "via": "call"}

    # Pass 2 — string literals (obfuscator string arrays)
    # Use the full file text to find the line number of the first string match.
    for api in sink_apis:
        entry = API_PATTERNS.get(api)
        if not entry:
            continue
        _, str_pat = entry
        for lineno, line in enumerate(lines, 1):
            m = re.search(str_pat, line)
            if m:
                return {"api": api, "col": m.start() + 1, "line": lineno, "via": "string"}

    return None


def scan_package_dir(pkg_dir: Path, sink_apis: list[str]) -> dict | None:
    """
    Walk pkg_dir (obfuscated library source), scan each JS file.
    Returns the first hit as {"sink_file": rel_str, "sink_line", "sink_col", "sink_api"}.
    """
    for js_path in sorted(pkg_dir.rglob("*.js")):
        # Skip nested node_modules
        try:
            rel = js_path.relative_to(pkg_dir)
        except ValueError:
            continue
        if "node_modules" in rel.parts:
            continue

        hit = find_sink_in_source(js_path, sink_apis)
        if hit:
            return {
                "sink_file":     str(rel),
                "sink_line":     hit["line"],
                "sink_col":      hit["col"],
                "sink_api_found": hit["api"],
                "sink_via":      hit.get("via", "call"),
            }
    return None


def main():
    with open(GT_ORIG) as f:
        gt = json.load(f)

    obf_gt = {}
    n_found = n_missing = 0

    for mid, info in sorted(gt.items()):
        category = info["category"]
        module   = info["module"]
        pkg_name = module.rsplit("_", 1)[0]

        # The anonymized benchmark copies only the library under module_XX/.
        # But the obfuscated source for our pipeline lives in:
        #   static-benchmark-obfuscated/<category>/<module>/node_modules/<pkg>/
        pkg_dir = OBF_DIR / category / module / "node_modules" / pkg_name
        if not pkg_dir.is_dir():
            # Try the first directory under node_modules
            nm_dir = OBF_DIR / category / module / "node_modules"
            if nm_dir.is_dir():
                pkgs = [d for d in nm_dir.iterdir() if d.is_dir() and not d.name.startswith(".")]
                if pkgs:
                    pkg_dir = pkgs[0]

        sink_apis = info.get("sink_apis", [])
        hit = None
        if pkg_dir.is_dir():
            hit = scan_package_dir(pkg_dir, sink_apis)

        entry = {**info}
        # Keep original positions under _orig keys
        entry["sink_file_orig"] = info.get("sink_file")
        entry["sink_line_orig"] = info.get("sink_line")
        entry["sink_col_orig"]  = info.get("sink_col")

        if hit:
            entry["sink_file"] = hit["sink_file"]
            entry["sink_line"] = hit["sink_line"]
            entry["sink_col"]  = hit["sink_col"]
            entry["sink_api_found"] = hit["sink_api_found"]
            entry["sink_via"]  = hit.get("sink_via", "call")
            via = hit.get("sink_via", "call")
            status = f"→ {hit['sink_file']}:{hit['sink_line']} ({hit['sink_api_found']}, {via})"
            n_found += 1
        else:
            entry["sink_file"] = None
            entry["sink_line"] = None
            entry["sink_col"]  = None
            entry["sink_api_found"] = None
            status = "NOT FOUND"
            n_missing += 1

        obf_gt[mid] = entry
        print(f"  {mid}  {category}/{module}  {status}")

    with open(GT_OBF, "w") as f:
        json.dump(obf_gt, f, indent=2)

    print(f"\nDone: {n_found} sinks found, {n_missing} not found")
    print(f"Output: {GT_OBF}")


if __name__ == "__main__":
    main()
