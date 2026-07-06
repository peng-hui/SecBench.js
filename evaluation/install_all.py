#!/usr/bin/env python3
"""
One-time dependency installer for all benchmark modules.

Iterates every module in benchmark/<category>/<module>/ and runs
  npm install --legacy-peer-deps
skipping any module whose node_modules/<pkg>/ already exists.

Run this once before setup_benchmark.py so the tier builder can copy
pre-installed node_modules instead of invoking npm at build time.

Usage:
  python3 install_all.py               # install all 600 modules
  python3 install_all.py --category command-injection
  python3 install_all.py --force       # reinstall even if node_modules exists
  python3 install_all.py --jobs 4      # parallel installs (default: 1)
"""

import argparse
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

ROOT       = Path(__file__).parent
BENCH_ROOT = ROOT.parent / "benchmark"

CATEGORIES = [
    "prototype-pollution",
    "redos",
    "command-injection",
    "path-traversal",
    "code-injection",
]


def get_pkg_name(module_dir: Path) -> str | None:
    pkg_json = module_dir / "package.json"
    if not pkg_json.exists():
        return None
    try:
        deps = json.loads(pkg_json.read_text()).get("dependencies", {})
        return next(iter(deps)) if deps else None
    except Exception:
        return None


def needs_install(module_dir: Path, pkg_name: str, force: bool) -> bool:
    if force:
        return True
    return not (module_dir / "node_modules" / pkg_name).is_dir()


def install_module(module_dir: Path, pkg_name: str) -> tuple[str, bool, str]:
    label = f"{module_dir.parent.name}/{module_dir.name}"
    for extra in (["--prefer-offline"], []):
        try:
            r = subprocess.run(
                ["npm", "install", "--legacy-peer-deps"] + extra,
                cwd=module_dir,
                capture_output=True,
                text=True,
                timeout=180,
            )
            if r.returncode == 0:
                return label, True, ""
        except subprocess.TimeoutExpired:
            return label, False, "timeout"
        except Exception as e:
            return label, False, str(e)
    return label, False, r.stderr[-200:] if r.stderr else "unknown error"


def collect_modules(categories: list[str]) -> list[tuple[Path, str]]:
    """Return [(module_dir, pkg_name)] for every installable module."""
    items = []
    for cat in categories:
        cat_dir = BENCH_ROOT / cat
        if not cat_dir.is_dir():
            print(f"  WARNING: {cat_dir} not found", file=sys.stderr)
            continue
        for mod_dir in sorted(cat_dir.iterdir()):
            if not mod_dir.is_dir():
                continue
            pkg_name = get_pkg_name(mod_dir)
            if pkg_name:
                items.append((mod_dir, pkg_name))
    return items


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--category", choices=CATEGORIES, default=None,
                    help="Install only one category (default: all)")
    ap.add_argument("--force", action="store_true",
                    help="Reinstall even if node_modules already exists")
    ap.add_argument("--jobs", type=int, default=1,
                    help="Parallel install workers (default: 1)")
    args = ap.parse_args()

    cats = [args.category] if args.category else CATEGORIES
    all_modules = collect_modules(cats)

    to_install = [(d, p) for d, p in all_modules if needs_install(d, p, args.force)]
    already    = len(all_modules) - len(to_install)

    print(f"Benchmark modules : {len(all_modules)}")
    print(f"Already installed : {already}")
    print(f"To install        : {len(to_install)}")
    if not to_install:
        print("Nothing to do.")
        return

    print(f"Workers           : {args.jobs}\n")

    ok = failed = 0
    failures = []

    if args.jobs == 1:
        for i, (mod_dir, pkg_name) in enumerate(to_install, 1):
            label = f"{mod_dir.parent.name}/{mod_dir.name}"
            print(f"  [{i:3d}/{len(to_install)}] {label} ... ", end="", flush=True)
            _, success, err = install_module(mod_dir, pkg_name)
            if success:
                print("ok")
                ok += 1
            else:
                print(f"FAILED  {err}")
                failed += 1
                failures.append((label, err))
    else:
        with ThreadPoolExecutor(max_workers=args.jobs) as pool:
            futs = {pool.submit(install_module, d, p): (d, p)
                    for d, p in to_install}
            done = 0
            for fut in as_completed(futs):
                done += 1
                label, success, err = fut.result()
                status = "ok" if success else f"FAILED  {err}"
                print(f"  [{done:3d}/{len(to_install)}] {label} ... {status}")
                if success:
                    ok += 1
                else:
                    failed += 1
                    failures.append((label, err))

    print(f"\n{'='*60}")
    print(f"Done: {ok} installed, {already} skipped (already done), {failed} failed")
    if failures:
        print(f"\nFailed modules:")
        for label, err in failures:
            print(f"  {label}: {err}")


if __name__ == "__main__":
    main()
