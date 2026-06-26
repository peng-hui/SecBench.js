#!/usr/bin/env python3
"""
Step 2 (revised) - Deobfuscate vulnerable libraries using webcrack, then run POC tests.

For each of the 50 selected modules:
  1. Re-install the vulnerable package (restores original clean source)
  2. Obfuscate with javascript-obfuscator (re-creates obfuscated state)
  3. Deobfuscate with webcrack (writes to stdout — capture and write back in place)
  4. Run original POC test
  5. Record pass/fail vs baseline and obfuscated results
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
    path = os.path.join(ROOT, category, module, "package.json")
    with open(path) as f:
        data = json.load(f)
    return list(data["dependencies"].keys())[0]


def find_js_files(pkg_dir):
    """All .js files in package, excluding nested node_modules."""
    js_files = []
    for dirpath, dirnames, filenames in os.walk(pkg_dir):
        if "node_modules" in dirnames:
            dirnames.remove("node_modules")
        for fname in filenames:
            if fname.endswith(".js"):
                js_files.append(os.path.join(dirpath, fname))
    return js_files


def reinstall_package(module_dir, pkg_name):
    """Force reinstall of the vulnerable package to restore original files."""
    pkg_dir = os.path.join(module_dir, "node_modules", pkg_name)
    if os.path.isdir(pkg_dir):
        shutil.rmtree(pkg_dir)
    r = subprocess.run(
        ["npm", "install", "--legacy-peer-deps", "--prefer-offline"],
        cwd=module_dir, capture_output=True, text=True, timeout=120,
    )
    if r.returncode != 0:
        r = subprocess.run(
            ["npm", "install", "--legacy-peer-deps"],
            cwd=module_dir, capture_output=True, text=True, timeout=120,
        )
    return r.returncode == 0


def obfuscate_file(src):
    fd, tmp = tempfile.mkstemp(suffix=".js")
    os.close(fd)
    try:
        r = subprocess.run(
            ["javascript-obfuscator", src, "--output", tmp],
            capture_output=True, text=True, timeout=60,
        )
        if r.returncode == 0:
            shutil.move(tmp, src)
            return True
        return False
    except subprocess.TimeoutExpired:
        return False
    finally:
        if os.path.exists(tmp):
            os.remove(tmp)


def deobfuscate_file_webcrack(src):
    """
    Run webcrack on src — it writes deobfuscated code to stdout.
    Capture stdout and write back to src in place.
    Returns (ok, error_msg).
    """
    try:
        r = subprocess.run(
            ["webcrack", src],
            capture_output=True, text=True, timeout=120,
        )
        if r.returncode == 0 and r.stdout.strip():
            with open(src, "w") as f:
                f.write(r.stdout)
            return True, ""
        return False, (r.stderr or "no output")[:200]
    except subprocess.TimeoutExpired:
        return False, "timeout"


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
              if any(k in l for k in ["●", "Cannot find", "SyntaxError",
                                       "ReferenceError", "Error:"])]
    return passed, errors[:4]


def load_results(path):
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        raw = json.load(f)
    return {cat: {e["module"]: e["status"] for e in entries}
            for cat, entries in raw["results"].items()}


def main():
    baseline   = load_results(os.path.join(ROOT, "poc_test_results.json"))
    obfuscated = load_results(os.path.join(ROOT, "poc_obfuscated_results.json"))

    results = {}
    total_pass = total_fail = total_error = 0

    for category, modules in SELECTED.items():
        print(f"\n{'='*60}")
        print(f"Category: {category.upper()}")
        print(f"{'='*60}")
        results[category] = []

        for module in modules:
            module_dir = os.path.join(ROOT, category, module)
            test_file  = find_test_file(category, module)
            base_s = baseline.get(category, {}).get(module, "?")
            obf_s  = obfuscated.get(category, {}).get(module, "?")

            print(f"  [{module}]", end="", flush=True)

            try:
                pkg_name = get_pkg_name(category, module)
            except Exception as e:
                print(f"  SKIP ({e})")
                results[category].append({"module": module, "status": "SKIP",
                                          "baseline": base_s, "obfuscated": obf_s})
                total_error += 1
                continue

            pkg_dir = os.path.join(module_dir, "node_modules", pkg_name)

            # 1. Reinstall to restore original
            print(f"  reinstalling {pkg_name}...", end="", flush=True)
            if not reinstall_package(module_dir, pkg_name):
                print(f"  REINSTALL_FAIL")
                results[category].append({"module": module, "status": "REINSTALL_FAIL",
                                          "baseline": base_s, "obfuscated": obf_s})
                total_error += 1
                continue

            # 2. Obfuscate
            js_files = find_js_files(pkg_dir)
            print(f"  obfuscating ({len(js_files)} files)...", end="", flush=True)
            n_obf = sum(1 for f in js_files if obfuscate_file(f))
            print(f"  {n_obf} ok", end="", flush=True)

            # 3. Deobfuscate with webcrack
            print(f"  deobfuscating...", end="", flush=True)
            js_files = find_js_files(pkg_dir)
            n_ok = n_fail = 0
            deobf_errors = []
            for f in js_files:
                ok, err = deobfuscate_file_webcrack(f)
                if ok:
                    n_ok += 1
                else:
                    n_fail += 1
                    deobf_errors.append(f"{os.path.basename(f)}: {err[:60]}")
            status_str = f"({n_ok} ok, {n_fail} failed)" if n_fail else f"{n_ok} ok"
            print(f"  {status_str}", end="", flush=True)

            # 4. Run test
            print(f"  running test...", end="", flush=True)
            try:
                passed, errors = run_test(category, module, test_file)
                status = "PASS" if passed else "FAIL"
                flag = ""
                if obf_s == "PASS" and status == "FAIL":
                    flag = "  <-- BROKEN BY DEOBFUSCATION"
                elif obf_s == "FAIL" and status == "PASS":
                    flag = "  <-- RESTORED BY DEOBFUSCATION"
                print(f"  {status}{flag}")
                for e in errors:
                    print(f"    > {e}")
                results[category].append({
                    "module": module, "pkg": pkg_name,
                    "js_files_obfuscated": n_obf,
                    "js_files_deobfuscated": n_ok, "js_files_failed": n_fail,
                    "status": status, "baseline": base_s, "obfuscated": obf_s,
                })
                if passed: total_pass += 1
                else: total_fail += 1
            except subprocess.TimeoutExpired:
                print(f"  TIMEOUT")
                results[category].append({"module": module, "pkg": pkg_name,
                                          "status": "TIMEOUT",
                                          "baseline": base_s, "obfuscated": obf_s})
                total_error += 1

    # Summary
    print(f"\n\n{'='*70}")
    print("SUMMARY  (baseline → obfuscated → deobfuscated/webcrack)")
    print(f"{'='*70}")
    print(f"{'Category':<25} {'Module':<35} {'Base':<6} {'Obf':<6} {'Deobf'}")
    print(f"{'-'*25} {'-'*35} {'-'*6} {'-'*6} {'-'*12}")
    for category, entries in results.items():
        for e in entries:
            flag = ""
            if e.get("obfuscated") == "PASS" and e["status"] == "FAIL":
                flag = "  <- BROKEN"
            elif e.get("obfuscated") == "FAIL" and e["status"] == "PASS":
                flag = "  <- RESTORED"
            print(f"{category:<25} {e['module']:<35} {e.get('baseline','?'):<6} "
                  f"{e.get('obfuscated','?'):<6} {e['status']}{flag}")

    print(f"\nTotal: {total_pass} PASS, {total_fail} FAIL, {total_error} ERROR/SKIP")

    out = os.path.join(ROOT, "poc_webcrack_results.json")
    with open(out, "w") as f:
        json.dump({"results": results,
                   "summary": {"pass": total_pass, "fail": total_fail,
                                "error": total_error}}, f, indent=2)
    print(f"Results saved to: {out}")


if __name__ == "__main__":
    main()
