#!/usr/bin/env python3
"""
Runs 10 POC tests from each vulnerability category and reports pass/fail.
Categories: prototype-pollution, redos, command-injection, path-traversal, code-injection
"""

import subprocess
import os
import sys
import json
import time

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


def find_test_file(category, module):
    module_dir = os.path.join(ROOT, category, module)
    for f in os.listdir(module_dir):
        if f.endswith(".test.js"):
            return f
    return None


def install_deps(category, module):
    module_dir = os.path.join(ROOT, category, module)
    node_modules = os.path.join(module_dir, "node_modules")
    if os.path.exists(node_modules):
        return True, "already installed"
    result = subprocess.run(
        ["npm", "install", "--legacy-peer-deps", "--prefer-offline"],
        cwd=module_dir,
        capture_output=True,
        text=True,
        timeout=120,
    )
    if result.returncode != 0:
        # try without --prefer-offline
        result = subprocess.run(
            ["npm", "install", "--legacy-peer-deps"],
            cwd=module_dir,
            capture_output=True,
            text=True,
            timeout=120,
        )
    return result.returncode == 0, result.stderr[-500:] if result.returncode != 0 else "ok"


def run_test(category, module, test_file):
    # ReDoS tests can be slow, give more time
    timeout = 120 if category == "redos" else 60
    # Path traversal tests start servers and use relative ./node_modules paths,
    # so they must run from the module directory, not root.
    if category == "path-traversal":
        timeout = 90
        run_dir = os.path.join(ROOT, category, module)
        cmd = ["jest", test_file, "--no-coverage", "--forceExit", "--testTimeout=30000"]
    else:
        run_dir = ROOT
        rel_test_path = os.path.join(category, module, test_file)
        cmd = ["jest", rel_test_path, "--no-coverage", "--forceExit", "--testTimeout=30000"]

    result = subprocess.run(
        cmd,
        cwd=run_dir,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    passed = result.returncode == 0
    # Extract summary line
    output = result.stdout + result.stderr
    summary = ""
    for line in output.split("\n"):
        if "PASS" in line or "FAIL" in line or "Tests:" in line or "✓" in line or "✗" in line or "×" in line:
            summary += line.strip() + " | "
    return passed, summary[:300], output


def main():
    results = {}
    total_pass = 0
    total_fail = 0
    total_error = 0

    for category, modules in SELECTED.items():
        print(f"\n{'='*60}")
        print(f"Category: {category.upper()}")
        print(f"{'='*60}")
        results[category] = []

        for module in modules:
            module_dir = os.path.join(ROOT, category, module)
            if not os.path.exists(module_dir):
                print(f"  [{module}]  SKIP - directory not found")
                results[category].append({"module": module, "status": "SKIP", "reason": "dir not found"})
                total_error += 1
                continue

            test_file = find_test_file(category, module)
            if not test_file:
                print(f"  [{module}]  SKIP - no test file found")
                results[category].append({"module": module, "status": "SKIP", "reason": "no test file"})
                total_error += 1
                continue

            # Install deps
            print(f"  [{module}]  installing deps...", end="", flush=True)
            try:
                ok, msg = install_deps(category, module)
                if not ok:
                    print(f"  INSTALL_FAIL: {msg[:100]}")
                    results[category].append({"module": module, "status": "INSTALL_FAIL", "reason": msg[:200]})
                    total_error += 1
                    continue
            except subprocess.TimeoutExpired:
                print("  INSTALL_TIMEOUT")
                results[category].append({"module": module, "status": "INSTALL_TIMEOUT"})
                total_error += 1
                continue

            # Run test
            print(f" running test...", end="", flush=True)
            try:
                passed, summary, full_output = run_test(category, module, test_file)
                status = "PASS" if passed else "FAIL"
                print(f"  {status}")
                if not passed:
                    # show brief error
                    for line in full_output.split("\n"):
                        if "●" in line or "Error" in line or "expect" in line.lower():
                            print(f"    > {line.strip()[:120]}")
                results[category].append({
                    "module": module,
                    "status": status,
                    "test_file": test_file,
                    "summary": summary,
                })
                if passed:
                    total_pass += 1
                else:
                    total_fail += 1
            except subprocess.TimeoutExpired:
                print("  TIMEOUT")
                results[category].append({"module": module, "status": "TIMEOUT"})
                total_error += 1

    # Summary table
    print(f"\n\n{'='*60}")
    print("SUMMARY")
    print(f"{'='*60}")
    print(f"{'Category':<25} {'Module':<35} {'Status'}")
    print(f"{'-'*25} {'-'*35} {'-'*10}")
    for category, entries in results.items():
        for e in entries:
            print(f"{category:<25} {e['module']:<35} {e['status']}")
    print(f"\nTotal: {total_pass} PASS, {total_fail} FAIL, {total_error} ERROR/SKIP")

    # Save results to JSON
    out_path = os.path.join(ROOT, "poc_test_results.json")
    with open(out_path, "w") as f:
        json.dump({"results": results, "summary": {"pass": total_pass, "fail": total_fail, "error": total_error}}, f, indent=2)
    print(f"\nResults saved to: {out_path}")


if __name__ == "__main__":
    main()
