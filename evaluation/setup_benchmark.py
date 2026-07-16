#!/usr/bin/env python3
"""
Build the three-tier static analysis benchmark in one pass.

Two modes:
  --mode sample  (default)  50-module stratified sample → static-benchmark/
  --mode full               all ~600 modules            → static-benchmark-full/

Output structure (under static-benchmark/ or static-benchmark-full/):
  <bench-dir>/
  ├── original/
  │   ├── module_01/   package.json (deps only) + node_modules/<pkg>/ (original source)
  │   └── ...
  ├── obfuscated/
  │   ├── module_01/   package.json (deps only) + node_modules/<pkg>/ (obfuscated)
  │   └── ...
  └── webcrack/
      ├── module_01/   package.json (deps only) + node_modules/<pkg>/ (webcrack output)
      └── ...

oracle/ground_truth.json        (sample mode)
oracle/ground_truth_full.json   (full mode)
  module_XX → category, sink, CVE, etc.  (never in agent dirs)

Prerequisites:
  python3 install_all.py        # install node_modules for all benchmark modules (once)

Usage:
  python3 setup_benchmark.py                         # fresh run (all 3 tiers)
  python3 setup_benchmark.py --tiers original        # original tier only
  python3 setup_benchmark.py --tiers obfuscated webcrack  # remaining tiers
  python3 setup_benchmark.py --mode full             # all ~595 modules
  python3 setup_benchmark.py --resume                # skip already-built modules
  python3 setup_benchmark.py --seed 42               # fixed shuffle (reproducible IDs)
"""

import argparse
import json
import os
import random
import shutil
import subprocess
import tempfile

ROOT       = os.path.dirname(os.path.abspath(__file__))
BENCH_ROOT = os.path.normpath(os.path.join(ROOT, "..", "benchmark"))

TIERS = ["original", "obfuscated", "obf_cff"]

# Extra flags per obfuscation tier (on top of javascript-obfuscator defaults)
OBF_FLAGS = {
    "obfuscated": [],
    "obf_cff":    ["--control-flow-flattening", "true",
                   "--control-flow-flattening-threshold", "1"],
}

SELECTED = {
    "prototype-pollution": [
        "deep-extend_0.5.0", "assign-deep_1.0.0", "101_1.0.0",
        "deap_1.0.0", "deep-defaults_1.0.5", "bodymen_1.0.0",
        "changeset_0.1.0", "copy-props_2.0.4",
        "arr-flatten-unflatten_1.1.4", "brikcss-merge_1.3.0",
    ],
    "redos": [
        "ajv_5.2.2", "ansi-regex_4.1.0", "ansi-html_0.0.7",
        "axios_0.21.0", "brace-expansion_1.1.6", "browserslist_4.16.4",
        "charset_1.0.0", "checkit_0.7.0", "clean-css_4.1.10",
        "amqp-match_0.0.0",
    ],
    "command-injection": [
        "aaptjs_1.3.1", "blamer_0.1.13", "async-git_1.13.1",
        "arpping_2.0.0", "bestzip_2.1.6", "connection-tester_0.2.0",
        "command-exists_1.2.2", "codecov_3.6.4",
        "adb-driver_0.1.8", "clamscan_1.2.0",
    ],
    "path-traversal": [
        "angular-http-server_1.0.0", "aso-server_0.4.3",
        "api-proxy_0.0.2", "asset-cache_0.0.6", "augustine_0.2.3",
        "basic-static_2.0.2", "canvas-designer_1.2.1", "bitty_0.1.0",
        "crud-file-server_0.7.0", "atropa-ide_0.2.2-2",
    ],
    "code-injection": [
        "node-serialize_0.0.3", "mathjs_3.10.3", "js-yaml_3.13.0",
        "marsdb_0.6.11", "djv_2.0.0", "hot-formula-parser_3.0.0",
        "is-my-json-valid_2.20.0", "jsen_0.6.6",
        "json-ptr_2.0.0", "access-policy_3.1.0",
    ],
}

VULN_TYPE = {
    "prototype-pollution": "Prototype Pollution",
    "redos":               "ReDoS",
    "command-injection":   "Command Injection",
    "path-traversal":      "Path Traversal",
    "code-injection":      "Arbitrary Code Injection",
}

SINK_APIS = {
    "prototype-pollution": ["__proto__", "constructor.prototype"],
    "redos":               ["RegExp.exec", "RegExp.test", "String.match",
                            "String.replace", "String.search", "String.split"],
    "command-injection":   ["child_process.exec", "child_process.execSync",
                            "child_process.spawn", "child_process.spawnSync"],
    "path-traversal":      ["fs.readFile", "fs.readFileSync", "fs.createReadStream"],
    "code-injection":      ["eval", "new Function", "vm.runInNewContext",
                            "vm.runInThisContext"],
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def src_dir(category, module):
    return os.path.join(BENCH_ROOT, category, module)


def tier_dir(bench_dir, tier, mid):
    return os.path.join(bench_dir, tier, mid)


def get_pkg_name(category, module):
    path = os.path.join(src_dir(category, module), "package.json")
    with open(path) as f:
        return list(json.load(f)["dependencies"].keys())[0]


def load_metadata(category, module):
    """Read sink/CVE fields from original benchmark package.json."""
    path = os.path.join(src_dir(category, module), "package.json")
    with open(path) as f:
        pkg = json.load(f)
    sink_str = pkg.get("sink", pkg.get("sinkLocation", ""))
    sink_file = sink_line = sink_col = None
    if sink_str:
        parts = sink_str.split(":")
        try:
            sink_file = parts[0] if parts else None
            sink_line = int(parts[1]) if len(parts) > 1 else None
            sink_col  = int(parts[2]) if len(parts) > 2 else None
        except (ValueError, IndexError):
            sink_file = sink_str
    return {
        "cve":           pkg.get("id", ""),
        "fixed_version": pkg.get("fixedVersion", ""),
        "fix_commit":    pkg.get("fixCommit", ""),
        "sink":          sink_str,
        "sink_file":     sink_file,
        "sink_line":     sink_line,
        "sink_col":      sink_col,
    }


def find_js_files(pkg_dir):
    js_files = []
    for dirpath, dirnames, filenames in os.walk(pkg_dir):
        dirnames[:] = [d for d in dirnames if d != "node_modules"]
        for fname in filenames:
            if fname.endswith(".js"):
                js_files.append(os.path.join(dirpath, fname))
    return js_files


def obfuscate_file(path, extra_flags=None):
    fd, tmp = tempfile.mkstemp(suffix=".js")
    os.close(fd)
    try:
        cmd = ["javascript-obfuscator", path, "--output", tmp] + (extra_flags or [])
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if r.returncode == 0:
            shutil.move(tmp, path)
            return True
        return False
    except subprocess.TimeoutExpired:
        return False
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def obfuscate_pkg(pkg_dir, extra_flags=None):
    js_files = find_js_files(pkg_dir)
    n_ok = sum(1 for f in js_files if obfuscate_file(f, extra_flags))
    return n_ok, len(js_files)


def webcrack_pkg(pkg_dir):
    n_ok = n_fail = 0
    for js_path in find_js_files(pkg_dir):
        try:
            r = subprocess.run(
                ["webcrack", js_path],
                capture_output=True, text=True, timeout=60,
            )
            if r.returncode == 0 and r.stdout.strip():
                with open(js_path, "w") as f:
                    f.write(r.stdout)
                n_ok += 1
            else:
                n_fail += 1
        except subprocess.TimeoutExpired:
            n_fail += 1
    return n_ok, n_fail


def copy_module(src, dst, pkg_name, deps_only_pkg_json=True):
    """Copy src → dst, keeping only package.json with dependencies field."""
    if os.path.exists(dst):
        shutil.rmtree(dst)
    shutil.copytree(src, dst, ignore=shutil.ignore_patterns("*.test.js"))
    if deps_only_pkg_json:
        orig_pkg = json.loads(open(os.path.join(src, "package.json")).read())
        clean = {"dependencies": orig_pkg.get("dependencies", {})}
        with open(os.path.join(dst, "package.json"), "w") as f:
            json.dump(clean, f, indent=2)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def discover_all_modules():
    """Return [(category, module_name)] for every module in benchmark/."""
    entries = []
    for cat in VULN_TYPE:
        cat_dir = os.path.join(BENCH_ROOT, cat)
        if not os.path.isdir(cat_dir):
            continue
        for name in sorted(os.listdir(cat_dir)):
            if os.path.isdir(os.path.join(cat_dir, name)):
                entries.append((cat, name))
    return entries


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode",   choices=["sample", "full"], default="sample",
                    help="'sample' = 50-module stratified set (default); "
                         "'full' = all modules in benchmark/")
    ap.add_argument("--tiers", nargs="+", choices=TIERS, default=TIERS,
                    help="Which tiers to build (default: all three). "
                         "E.g. --tiers original")
    ap.add_argument("--seed",   type=int, default=None,
                    help="Random seed for module ID shuffle (omit for random)")
    ap.add_argument("--resume", action="store_true",
                    help="Skip modules where all requested tiers already exist")
    args = ap.parse_args()
    tiers = args.tiers

    if args.mode == "full":
        bench_dir = os.path.join(ROOT, "static-benchmark-full")
        gt_path   = os.path.join(ROOT, "oracle", "ground_truth_full.json")
        id_fmt    = "module_{:03d}"
        entries   = discover_all_modules()
    else:
        bench_dir = os.path.join(ROOT, "static-benchmark")
        gt_path   = os.path.join(ROOT, "oracle", "ground_truth.json")
        id_fmt    = "module_{:02d}"
        entries   = [(cat, mod) for cat, mods in SELECTED.items() for mod in mods]

    rng = random.Random(args.seed)
    rng.shuffle(entries)

    # Assign module IDs — reuse existing ground truth IDs if resuming
    if args.resume and os.path.exists(gt_path):
        with open(gt_path) as f:
            existing_gt = json.load(f)
        reverse = {(v["category"], v["module"]): mid for mid, v in existing_gt.items()}
        mapping = {}
        for cat, mod in entries:
            mid = reverse.get((cat, mod), id_fmt.format(len(mapping) + 1))
            try:
                meta = load_metadata(cat, mod)
            except Exception:
                meta = {}
            mapping[mid] = {
                "category":  cat,
                "module":    mod,
                "vuln_type": VULN_TYPE.get(cat, cat),
                "sink_apis": SINK_APIS.get(cat, []),
                **meta,
            }
    else:
        mapping = {}
        for i, (cat, mod) in enumerate(entries, 1):
            mid = id_fmt.format(i)
            try:
                meta = load_metadata(cat, mod)
            except Exception:
                meta = {}
            mapping[mid] = {
                "category":  cat,
                "module":    mod,
                "vuln_type": VULN_TYPE.get(cat, cat),
                "sink_apis": SINK_APIS.get(cat, []),
                **meta,
            }

    # Create requested tier directories
    for tier in tiers:
        os.makedirs(os.path.join(bench_dir, tier), exist_ok=True)

    print(f"Mode: {args.mode}  |  {len(mapping)} modules  |  tiers: {', '.join(tiers)}\n")
    ok = failed = skipped = 0

    for mid, info in sorted(mapping.items()):
        cat = info["category"]
        mod = info["module"]
        src = src_dir(cat, mod)

        tier_paths = {t: tier_dir(bench_dir, t, mid) for t in tiers}

        if args.resume and all(os.path.isdir(p) for p in tier_paths.values()):
            print(f"  {mid}  [{cat}/{mod}]  SKIP (exists)")
            skipped += 1
            continue

        print(f"  {mid}  [{cat}/{mod}]", end="", flush=True)

        try:
            pkg_name = get_pkg_name(cat, mod)
        except Exception as e:
            print(f"  SKIP ({e})")
            failed += 1
            continue

        # Require node_modules to be pre-installed by install_all.py
        src_nm = os.path.join(src, "node_modules", pkg_name)
        if not os.path.isdir(src_nm):
            print(f"  SKIP (node_modules missing — run install_all.py first)")
            failed += 1
            continue

        if "original" in tiers:
            copy_module(src, tier_paths["original"], pkg_name)
            print("  orig✓", end="", flush=True)

        if "obfuscated" in tiers:
            copy_module(src, tier_paths["obfuscated"], pkg_name)
            n_ok, n_total = obfuscate_pkg(
                os.path.join(tier_paths["obfuscated"], "node_modules", pkg_name))
            print(f"  obf({n_ok}/{n_total})✓", end="", flush=True)

        if "obf_cff" in tiers:
            copy_module(src, tier_paths["obf_cff"], pkg_name)
            flags = OBF_FLAGS["obf_cff"]
            n_ok, n_total = obfuscate_pkg(
                os.path.join(tier_paths["obf_cff"], "node_modules", pkg_name), flags)
            print(f"  cff({n_ok}/{n_total})✓", end="", flush=True)


        print()
        ok += 1

    # Save ground truth — skip if --resume and no new modules were added
    # (avoids accidentally reshuffling the module→package mapping)
    save_gt = True
    if args.resume and os.path.exists(gt_path):
        existing_keys = set(json.load(open(gt_path)).keys())
        if set(mapping.keys()) == existing_keys:
            save_gt = False  # nothing new; preserve existing GT as-is
    if save_gt:
        os.makedirs(os.path.dirname(gt_path), exist_ok=True)
        with open(gt_path, "w") as f:
            json.dump(mapping, f, indent=2)

    bench_name = os.path.basename(bench_dir)
    print(f"\n{'='*60}")
    print(f"Done: {ok} built, {skipped} skipped, {failed} failed")
    print(f"\nOutput:")
    for tier in tiers:
        n = sum(1 for mid in mapping if os.path.isdir(tier_dir(bench_dir, tier, mid)))
        print(f"  {bench_name}/{tier}/   ({n} modules)")
    print(f"  oracle/{os.path.basename(gt_path)}")


if __name__ == "__main__":
    main()
