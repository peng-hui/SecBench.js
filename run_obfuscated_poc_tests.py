#!/usr/bin/env python3
"""
Step 1 - Obfuscate the vulnerable library, then run the original POC test.

For each of the 50 selected modules:
  1. Read package.json to find the vulnerable package name
  2. Obfuscate all .js files inside node_modules/<pkg>/ in-place
     (skipping nested node_modules subdirs inside the package)
  3. Run the original unmodified test file against the obfuscated library
  4. Record pass/fail vs baseline

No restore is done here — deobfuscation runs next on the already-obfuscated files.
"""

import subprocess
import os
import json
import tempfile
import shutil

ROOT = os.path.dirname(os.path.abspath(__file__))

SELECTED = {
    "prototype-pollution": [
        "deep-extend_0.5.0",
        "assign-deep_1.0.0",
        "101_1.0.0",
        "deap_1.0.0",
        "deep-defaults_1.0.5",
        "bodymen_1.0.0",
        "changeset_0.1.0",
        "copy-props_2.0.4",
        "arr-flatten-unflatten_1.1.4",
        "brikcss-merge_1.3.0",
    ],
    "redos": [
        "ajv_5.2.2",
        "ansi-regex_4.1.0",
        "ansi-html_0.0.7",
        "axios_0.21.0",
        "brace-expansion_1.1.6",
        "browserslist_4.16.4",
        "charset_1.0.0",
        "checkit_0.7.0",
        "clean-css_4.1.10",
        "amqp-match_0.0.0",
    ],
    "command-injection": [
        "aaptjs_1.3.1",
        "blamer_0.1.13",
        "async-git_1.13.1",
        "arpping_2.0.0",
        "bestzip_2.1.6",
        "connection-tester_0.2.0",
        "command-exists_1.2.2",
        "codecov_3.6.4",
        "adb-driver_0.1.8",
        "clamscan_1.2.0",
    ],
    "path-traversal": [
        "angular-http-server_1.0.0",
        "aso-server_0.4.3",
        "api-proxy_0.0.2",
        "asset-cache_0.0.6",
        "augustine_0.2.3",
        "basic-static_2.0.2",
        "canvas-designer_1.2.1",
        "bitty_0.1.0",
        "crud-file-server_0.7.0",
        "atropa-ide_0.2.2-2",
    ],
    "code-injection": [
        "node-serialize_0.0.3",
        "mathjs_3.10.3",
        "js-yaml_3.13.0",
        "marsdb_0.6.11",
        "djv_2.0.0",
        "hot-formula-parser_3.0.0",
        "is-my-json-valid_2.20.0",
        "jsen_0.6.6",
        "json-ptr_2.0.0",
        "access-policy_3.1.0",
    ],
}


def get_pkg_name(category, module):
    """Return the vulnerable package name from the module's package.json."""
    path = os.path.join(ROOT, category, module, "package.json")
    with open(path) as f:
        data = json.load(f)
    return list(data["dependencies"].keys())[0]


def find_js_files(pkg_dir):
    """Walk pkg_dir, return all .js files excluding any nested node_modules."""
    js_files = []
    for dirpath, dirnames, filenames in os.walk(pkg_dir):
        # Don't descend into node_modules inside the package
        if "node_modules" in dirnames:
            dirnames.remove("node_modules")
        for fname in filenames:
            if fname.endswith(".js"):
                js_files.append(os.path.join(dirpath, fname))
    return js_files


def obfuscate_file(src):
    """Obfuscate src in-place via a temp file. Returns (ok, error_msg)."""
    fd, tmp = tempfile.mkstemp(suffix=".js")
    os.close(fd)
    try:
        r = subprocess.run(
            ["javascript-obfuscator", src, "--output", tmp],
            capture_output=True, text=True, timeout=60,
        )
        if r.returncode != 0:
            return False, r.stderr[:200]
        shutil.move(tmp, src)
        return True, ""
    except subprocess.TimeoutExpired:
        return False, "timeout"
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def obfuscate_package(pkg_dir):
    """Obfuscate all .js files in the package. Returns (n_ok, n_fail, errors)."""
    js_files = find_js_files(pkg_dir)
    n_ok = n_fail = 0
    errors = []
    for f in js_files:
        ok, err = obfuscate_file(f)
        if ok:
            n_ok += 1
        else:
            n_fail += 1
            errors.append(f"{os.path.basename(f)}: {err}")
    return n_ok, n_fail, errors


def find_test_file(category, module):
    module_dir = os.path.join(ROOT, category, module)
    for f in os.listdir(module_dir):
        if f.endswith(".test.js"):
            return f
    return None


def run_test(category, module, test_file):
    module_dir = os.path.join(ROOT, category, module)
    timeout = 120 if category == "redos" else 90

    if category == "path-traversal":
        cmd = ["jest", test_file, "--no-coverage", "--forceExit", "--testTimeout=30000"]
        cwd = module_dir
    else:
        rel = os.path.join(category, module, test_file)
        cmd = ["jest", rel, "--no-coverage", "--forceExit", "--testTimeout=30000"]
        cwd = ROOT

    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    passed = r.returncode == 0
    output = r.stdout + r.stderr
    errors = [l.strip()[:120] for l in output.split("\n")
              if any(k in l for k in ["●", "Cannot find", "SyntaxError", "expect(", "Error:"])]
    return passed, errors[:4]


def main():
    # Load baseline results for comparison
    baseline = {}
    bp = os.path.join(ROOT, "poc_test_results.json")
    if os.path.exists(bp):
        with open(bp) as f:
            raw = json.load(f)
        for cat, entries in raw["results"].items():
            baseline[cat] = {e["module"]: e["status"] for e in entries}

    results = {}
    total_pass = total_fail = total_error = 0

    for category, modules in SELECTED.items():
        print(f"\n{'='*60}")
        print(f"Category: {category.upper()}")
        print(f"{'='*60}")
        results[category] = []

        for module in modules:
            module_dir = os.path.join(ROOT, category, module)
            test_file = find_test_file(category, module)
            baseline_status = baseline.get(category, {}).get(module, "?")

            print(f"  [{module}]", end="", flush=True)

            # Locate vulnerable package
            try:
                pkg_name = get_pkg_name(category, module)
            except Exception as e:
                print(f"  SKIP (can't read package.json: {e})")
                results[category].append({"module": module, "status": "SKIP", "baseline": baseline_status})
                total_error += 1
                continue

            pkg_dir = os.path.join(module_dir, "node_modules", pkg_name)
            if not os.path.isdir(pkg_dir):
                print(f"  SKIP (node_modules/{pkg_name} not found)")
                results[category].append({"module": module, "status": "SKIP", "pkg": pkg_name, "baseline": baseline_status})
                total_error += 1
                continue

            # Obfuscate the library
            js_files = find_js_files(pkg_dir)
            print(f"  obfuscating {pkg_name} ({len(js_files)} .js files)...", end="", flush=True)
            n_ok, n_fail, obf_errors = obfuscate_package(pkg_dir)
            if n_fail > 0:
                print(f" ({n_ok} ok, {n_fail} failed)", end="", flush=True)
            else:
                print(f" ok", end="", flush=True)

            # Run original test against obfuscated library
            print(f"  running test...", end="", flush=True)
            try:
                passed, errors = run_test(category, module, test_file)
                status = "PASS" if passed else "FAIL"
                flag = ""
                if baseline_status == "PASS" and status == "FAIL":
                    flag = "  <-- BROKEN BY OBFUSCATION"
                elif baseline_status == "FAIL" and status == "PASS":
                    flag = "  <-- FIXED BY OBFUSCATION"
                print(f"  {status}{flag}")
                for e in errors:
                    print(f"    > {e}")
                results[category].append({
                    "module": module, "pkg": pkg_name,
                    "js_files_obfuscated": n_ok, "js_files_failed": n_fail,
                    "status": status, "baseline": baseline_status,
                })
                if passed: total_pass += 1
                else: total_fail += 1
            except subprocess.TimeoutExpired:
                print(f"  TIMEOUT")
                results[category].append({"module": module, "pkg": pkg_name, "status": "TIMEOUT", "baseline": baseline_status})
                total_error += 1

    # Summary
    print(f"\n\n{'='*60}")
    print("SUMMARY  (baseline → after obfuscating library)")
    print(f"{'='*60}")
    print(f"{'Category':<25} {'Module':<35} {'Baseline':<10} {'Obfuscated'}")
    print(f"{'-'*25} {'-'*35} {'-'*10} {'-'*10}")
    for category, entries in results.items():
        for e in entries:
            flag = ""
            if e.get("baseline") == "PASS" and e["status"] == "FAIL":
                flag = "  <- BROKEN"
            elif e.get("baseline") == "FAIL" and e["status"] == "PASS":
                flag = "  <- FIXED"
            print(f"{category:<25} {e['module']:<35} {e.get('baseline','?'):<10} {e['status']}{flag}")

    print(f"\nTotal: {total_pass} PASS, {total_fail} FAIL, {total_error} ERROR/SKIP")

    out = os.path.join(ROOT, "poc_obfuscated_results.json")
    with open(out, "w") as f:
        json.dump({"results": results,
                   "summary": {"pass": total_pass, "fail": total_fail, "error": total_error}}, f, indent=2)
    print(f"Results saved to: {out}")


if __name__ == "__main__":
    main()
