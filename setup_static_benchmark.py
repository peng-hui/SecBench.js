#!/usr/bin/env python3
"""
Creates two static analysis benchmark copies from the 50 selected modules:

  static-benchmark-original/    — original library source, no POC test files
  static-benchmark-obfuscated/  — obfuscated library source, no POC test files

Steps per module:
  1. Reinstall vulnerable package  →  restore original source
  2. Copy to static-benchmark-original/   (exclude *.test.js)
  3. Obfuscate all .js files in the library in-place
  4. Copy to static-benchmark-obfuscated/ (exclude *.test.js)
  5. Reinstall again               →  restore original (leave source clean)
"""

import os
import shutil
import subprocess
import json
import tempfile

ROOT = os.path.dirname(os.path.abspath(__file__))
DEST_ORIG = os.path.join(ROOT, "static-benchmark-original")
DEST_OBF  = os.path.join(ROOT, "static-benchmark-obfuscated")

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
        return list(json.load(f)["dependencies"].keys())[0]


def reinstall_pkg(module_dir, pkg_name):
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


def find_js_files(pkg_dir):
    js_files = []
    for dirpath, dirnames, filenames in os.walk(pkg_dir):
        if "node_modules" in dirnames:
            dirnames.remove("node_modules")
        for fname in filenames:
            if fname.endswith(".js"):
                js_files.append(os.path.join(dirpath, fname))
    return js_files


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


def obfuscate_package(pkg_dir):
    js_files = find_js_files(pkg_dir)
    n_ok = sum(1 for f in js_files if obfuscate_file(f))
    return n_ok, len(js_files)


def copy_module(src_dir, dst_dir):
    """Copy module to dst, excluding *.test.js files."""
    def ignore(dir, contents):
        return [f for f in contents if f.endswith(".test.js")]
    if os.path.exists(dst_dir):
        shutil.rmtree(dst_dir)
    shutil.copytree(src_dir, dst_dir, ignore=ignore)


def verify(dst_dir, pkg_name):
    has_test = any(f.endswith(".test.js") for f in os.listdir(dst_dir))
    has_lib  = os.path.isdir(os.path.join(dst_dir, "node_modules", pkg_name))
    return not has_test and has_lib


def main():
    for d in [DEST_ORIG, DEST_OBF]:
        os.makedirs(d, exist_ok=True)

    total = ok_orig = ok_obf = failed = 0

    for category, modules in SELECTED.items():
        print(f"\n{'='*60}")
        print(f"Category: {category.upper()}")
        print(f"{'='*60}")
        for d in [DEST_ORIG, DEST_OBF]:
            os.makedirs(os.path.join(d, category), exist_ok=True)

        for module in modules:
            total += 1
            src_dir  = os.path.join(ROOT, category, module)
            dst_orig = os.path.join(DEST_ORIG, category, module)
            dst_obf  = os.path.join(DEST_OBF,  category, module)

            print(f"  [{module}]", end="", flush=True)

            try:
                pkg_name = get_pkg_name(category, module)
            except Exception as e:
                print(f"  SKIP ({e})")
                failed += 1
                continue

            pkg_dir = os.path.join(src_dir, "node_modules", pkg_name)

            # 1. Reinstall → original source
            print(f"  restore...", end="", flush=True)
            if not reinstall_pkg(src_dir, pkg_name):
                print(f"  REINSTALL FAILED")
                failed += 1
                continue

            # 2. Copy original
            print(f"  copy-orig...", end="", flush=True)
            copy_module(src_dir, dst_orig)
            if verify(dst_orig, pkg_name):
                ok_orig += 1
                print(f"  OK", end="", flush=True)
            else:
                print(f"  ORIG VERIFY FAIL", end="", flush=True)

            # 3. Obfuscate library in-place
            print(f"  obfuscate...", end="", flush=True)
            n_ok, n_total = obfuscate_package(pkg_dir)
            print(f"  ({n_ok}/{n_total} files)", end="", flush=True)

            # 4. Copy obfuscated
            print(f"  copy-obf...", end="", flush=True)
            copy_module(src_dir, dst_obf)
            if verify(dst_obf, pkg_name):
                ok_obf += 1
                print(f"  OK", end="", flush=True)
            else:
                print(f"  OBF VERIFY FAIL", end="", flush=True)

            # 5. Reinstall again → leave source clean
            print(f"  restore...", end="", flush=True)
            reinstall_pkg(src_dir, pkg_name)
            print(f"  done")

    # Summary
    print(f"\n{'='*60}")
    print(f"DONE:  {total} modules processed")
    print(f"  static-benchmark-original/    {ok_orig}/50 OK")
    print(f"  static-benchmark-obfuscated/  {ok_obf}/50 OK")
    if failed:
        print(f"  FAILED: {failed}")
    print(f"\nOutput directories:")
    print(f"  {DEST_ORIG}")
    print(f"  {DEST_OBF}")
    print(f"\nStructure (each):")
    for category in SELECTED:
        print(f"  {category}/  ({len(SELECTED[category])} modules, "
              f"no *.test.js, library in node_modules/)")


if __name__ == "__main__":
    main()
