#!/usr/bin/env python3
"""
Creates anonymized flat benchmark directories from the existing copies:

  static-benchmark-anon-original/
    module_01/ ... module_50/   (neutral names, no category folders)

  static-benchmark-anon-obfuscated/
    module_01/ ... module_50/

  oracle/ground_truth.json       (mapping kept in oracle/ — agent NEVER sees it)

The agent sees only:
  - module_XX/ directory name (no hint)
  - package.json with only {"dependencies": {"pkg": "version"}} (pkg name kept
    since that's realistic — in practice you know what you're analyzing)
  - library source files

The evaluation script reads oracle/ground_truth.json to score results.
Ground truth lives in oracle/ alongside the dynamic harness — never in a path
the agent can reach.
"""

import os, shutil, json, random, subprocess, tempfile

ROOT      = os.path.dirname(os.path.abspath(__file__))
SRC_ORIG  = os.path.join(ROOT, "static-benchmark-original")   # cleaned copies (no PoC, no metadata)
SRC_OBF   = os.path.join(ROOT, "static-benchmark-obfuscated") # obfuscated copies
SRC_DATA  = ROOT                                               # original benchmark — sink data source (NEVER copied to agent dirs)
DST_ORIG  = "/tmp/js-eval-original"
DST_OBF   = "/tmp/js-eval-obfuscated"
DST_WCK   = "/tmp/js-eval-webcrack"  # obfuscated source run through webcrack deobfuscator
GT_PATH   = os.path.join(ROOT, "oracle", "ground_truth.json") # in oracle/ — agent never sees it

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

# Known dangerous APIs per category — used as the static oracle for obfuscated evaluation
# (line numbers shift after obfuscation; API names survive it)
SINK_API = {
    "prototype-pollution": ["__proto__", "constructor.prototype"],
    "redos":               ["RegExp.exec", "RegExp.test", "String.match", "String.replace", "String.search", "String.split"],
    "command-injection":   ["child_process.exec", "child_process.execSync", "child_process.spawn", "child_process.spawnSync"],
    "path-traversal":      ["fs.readFile", "fs.readFileSync", "fs.createReadStream"],
    "code-injection":      ["eval", "new Function", "vm.runInNewContext", "vm.runInThisContext"],
}


def parse_sink(sink_str):
    """Parse 'file.js:line:col' → (file, line, col). Returns Nones if malformed."""
    if not sink_str:
        return None, None, None
    parts = sink_str.split(":")
    try:
        if len(parts) == 3:
            return parts[0], int(parts[1]), int(parts[2])
        elif len(parts) == 2:
            return parts[0], int(parts[1]), None
        else:
            return sink_str, None, None
    except ValueError:
        return sink_str, None, None


def load_original_metadata(category, module):
    """Read sink, CVE id, fixedVersion from the original benchmark package.json."""
    pkg_path = os.path.join(SRC_DATA, category, module, "package.json")
    if not os.path.exists(pkg_path):
        return {}
    with open(pkg_path) as f:
        pkg = json.load(f)
    sink_str = pkg.get("sink", "")
    sink_file, sink_line, sink_col = parse_sink(sink_str)
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
    """Walk pkg_dir, return .js files excluding nested node_modules."""
    js_files = []
    for dirpath, dirnames, filenames in os.walk(pkg_dir):
        if "node_modules" in dirnames:
            dirnames.remove("node_modules")
        for fname in filenames:
            if fname.endswith(".js"):
                js_files.append(os.path.join(dirpath, fname))
    return js_files


def webcrack_module(module_dir):
    """
    Run webcrack on every JS file inside module_dir/node_modules/<pkg>/.
    Writes deobfuscated code back in place.
    Returns (n_ok, n_fail).
    """
    nm_dir = os.path.join(module_dir, "node_modules")
    if not os.path.isdir(nm_dir):
        return 0, 0
    # Find the top-level package directory (first non-dotfile subdir)
    pkgs = [d for d in os.listdir(nm_dir)
            if not d.startswith(".") and os.path.isdir(os.path.join(nm_dir, d))]
    n_ok = n_fail = 0
    for pkg in pkgs:
        pkg_dir = os.path.join(nm_dir, pkg)
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


def main():
    # Build flat ordered list and shuffle so module IDs carry no ordering hint
    entries = []
    for category, modules in SELECTED.items():
        for module in modules:
            entries.append((category, module))
    random.shuffle(entries)

    # Assign neutral IDs: module_01 ... module_50
    mapping = {}
    for i, (category, module) in enumerate(entries, 1):
        mid  = f"module_{i:02d}"
        meta = load_original_metadata(category, module)
        mapping[mid] = {
            "category":    category,
            "module":      module,
            "vuln_type":   VULN_TYPE[category],
            "sink_apis":   SINK_API[category],
            **meta,
        }

    # Create destination dirs
    for d in [DST_ORIG, DST_OBF, DST_WCK]:
        if os.path.exists(d):
            shutil.rmtree(d)
        os.makedirs(d)

    print(f"Creating anonymized benchmark ({len(mapping)} modules)...\n")
    ok      = 0
    missing = []

    for mid, info in mapping.items():
        category = info["category"]
        module   = info["module"]

        src_orig = os.path.join(SRC_ORIG, category, module)
        src_obf  = os.path.join(SRC_OBF,  category, module)
        dst_orig = os.path.join(DST_ORIG, mid)
        dst_obf  = os.path.join(DST_OBF,  mid)
        dst_wck  = os.path.join(DST_WCK,  mid)

        if not os.path.isdir(src_orig) or not os.path.isdir(src_obf):
            print(f"  {mid}  MISSING — {category}/{module}")
            missing.append(f"{category}/{module}")
            continue

        shutil.copytree(src_orig, dst_orig)
        shutil.copytree(src_obf,  dst_obf)
        shutil.copytree(src_obf,  dst_wck)   # start from obfuscated copy

        # Apply webcrack in-place to the webcrack directory
        n_ok, n_fail = webcrack_module(dst_wck)

        sink_display = info.get("sink") or "unknown"
        print(f"  {mid}  {category}/{module}  sink={sink_display}  webcrack={n_ok}ok/{n_fail}fail")
        ok += 1

    # Save ground truth — never written inside benchmark dirs
    os.makedirs(os.path.dirname(GT_PATH), exist_ok=True)
    with open(GT_PATH, "w") as f:
        json.dump(mapping, f, indent=2)

    print(f"\nDone: {ok}/50 modules copied")
    if missing:
        print(f"Missing ({len(missing)}): {', '.join(missing)}")
    print(f"\nOutput:")
    print(f"  {DST_ORIG}/   (original,    module_01..module_50)  ← agent runs here")
    print(f"  {DST_OBF}/   (obfuscated,  module_01..module_50)  ← agent runs here")
    print(f"  {DST_WCK}/   (webcracked,  module_01..module_50)  ← agent runs here")
    print(f"  {GT_PATH}")
    print(f"  └─ ground truth in oracle/ — agent never sees it")
    print(f"\nFields in ground_truth.json per module:")
    print(f"  category, module, vuln_type, sink_apis")
    print(f"  cve, fixed_version, fix_commit")
    print(f"  sink, sink_file, sink_line, sink_col")


if __name__ == "__main__":
    main()
