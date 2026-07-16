#!/usr/bin/env python3
"""
Extract the enclosing function name at each sink location and add
'sink_function' to oracle/ground_truth.json.

Uses a regex walk-backward heuristic — accurate for most npm JS styles.
Run once; safe to re-run (idempotent, overwrites existing sink_function).
"""

import json
import os
import re
import sys
from pathlib import Path

ROOT        = Path(__file__).parent
BENCH_ROOT  = ROOT.parent / "benchmark"
GT_PATH     = ROOT / "oracle" / "ground_truth.json"

# Patterns that mark the start of a named function scope, from most specific
# to least.  We capture the function name in group 1.
_FUNC_PATTERNS = [
    # class method / object method shorthand: methodName(...) {
    re.compile(r"^\s*(?:async\s+)?\*?\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\("),
    # function declaration/expression: function name(
    re.compile(r"(?:^|[\s(;{,])"
               r"(?:async\s+)?function\s*\*?\s*([A-Za-z_$][A-Za-z0-9_$]+)\s*\("),
    # assigned function/arrow: const/let/var name = [async] (?) => | function(
    re.compile(r"(?:const|let|var)\s+([A-Za-z_$][A-Za-z0-9_$]*)\s*="
               r"\s*(?:async\s+)?(?:function|\(|[A-Za-z_$][A-Za-z0-9_$]*)"),
    # object property: key: [async] function(
    re.compile(r"([A-Za-z_$][A-Za-z0-9_$]*)\s*:\s*(?:async\s+)?function\s*\("),
    # exported: module.exports.name = ...  /  exports.name = ...
    re.compile(r"(?:module\.exports|exports)\.([A-Za-z_$][A-Za-z0-9_$]*)\s*="),
]


def _try_extract_name(line: str) -> str | None:
    """Return the function name found on this line, or None."""
    for pat in _FUNC_PATTERNS:
        m = pat.search(line)
        if m:
            name = m.group(1)
            # Filter out reserved words that sneak through
            if name not in {"if", "for", "while", "switch", "catch", "return",
                            "true", "false", "null", "new", "typeof", "in",
                            "of", "do", "else", "try", "var", "let", "const"}:
                return name
    return None


def find_enclosing_function(src_lines: list[str], sink_line: int) -> str:
    """
    Walk backward from sink_line (1-indexed) tracking brace depth to find
    the enclosing function name.  Returns '__file_scope__' if none found.
    """
    # Convert to 0-indexed
    idx = min(sink_line - 1, len(src_lines) - 1)

    # Track net brace depth relative to the sink line as we go up.
    # A line that opens '{' at depth -N means we may have entered a block.
    depth = 0
    for i in range(idx, -1, -1):
        line = src_lines[i]
        opens  = line.count("{")
        closes = line.count("}")
        depth += closes - opens  # going up, so closes increase our "entry depth"

        # When depth <= 0 we're outside the block that contains the sink.
        # A function-defining line that opens a block here is a candidate.
        if depth <= 0:
            name = _try_extract_name(line)
            if name:
                return name
            # Keep scanning — might be a nested block opener without a name

    return "__file_scope__"


def resolve_src_path(module_dir: Path, sink_file: str) -> Path | None:
    """Find the actual source file.  sink_file is relative to the package root."""
    pkg_dir = module_dir / "node_modules"

    # 1. Direct path attempts
    for candidate in [
        module_dir / "node_modules" / sink_file,
        module_dir / sink_file,
    ]:
        if candidate.exists():
            return candidate

    # 2. Under any immediate package dir
    if pkg_dir.exists():
        for pkg in pkg_dir.iterdir():
            if pkg.is_dir() and pkg.name != ".bin":
                candidate = pkg / sink_file
                if candidate.exists():
                    return candidate

    # 3. Recursive search by basename (catches lib/compile/util.js etc.)
    basename = Path(sink_file).name
    # Use .js fallback for .ts files (compiled output)
    basenames = {basename, Path(basename).stem + ".js"}
    if pkg_dir.exists():
        for pkg in pkg_dir.iterdir():
            if not pkg.is_dir() or pkg.name == ".bin":
                continue
            for f in pkg.rglob("*"):
                if f.name in basenames and "node_modules" not in f.relative_to(pkg).parts:
                    return f
    return None


def process_entry(mid: str, info: dict) -> str:
    category   = info["category"]
    module_name = info["module"]
    sink_file  = info.get("sink_file")
    sink_line  = info.get("sink_line")

    if not sink_file or not sink_line:
        return "__unknown__"

    module_dir = BENCH_ROOT / category / module_name
    src_path   = resolve_src_path(module_dir, sink_file)

    if src_path is None:
        print(f"  [{mid}] WARN: cannot find {sink_file} under {module_dir}")
        return "__unknown__"

    try:
        src = src_path.read_text(errors="ignore").splitlines()
    except Exception as e:
        print(f"  [{mid}] WARN: read error {e}")
        return "__unknown__"

    name = find_enclosing_function(src, sink_line)
    return name


def main():
    with open(GT_PATH) as f:
        gt = json.load(f)

    print(f"Processing {len(gt)} ground truth entries...")
    changed = 0
    for mid in sorted(gt.keys()):
        info  = gt[mid]
        fname = process_entry(mid, info)
        old   = info.get("sink_function")
        info["sink_function"] = fname
        if old != fname:
            changed += 1
            status = "NEW" if old is None else f"UPDATED ({old} → {fname})"
            print(f"  {mid} ({info['module']:30s})  {fname}  [{status}]")

    with open(GT_PATH, "w") as f:
        json.dump(gt, f, indent=2)

    print(f"\nDone. {changed} entries updated. Saved to {GT_PATH}")


if __name__ == "__main__":
    main()
