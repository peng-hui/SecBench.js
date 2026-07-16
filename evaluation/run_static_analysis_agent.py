#!/usr/bin/env python3
"""
Static vulnerability detection benchmark using Claude Code (subscription).

For each of the 50 modules in both original and obfuscated states:
  1. Run `claude --print` in the module directory (fresh session per module)
  2. Parse JSON output from the agent
  3. Compare against ground truth (vulnerability type from category)
  4. Record: correct type detected? vulnerable flag set?

Results saved to: static_analysis_results.json
"""

import argparse
import subprocess
import os
import json
import re
import random
import time
from datetime import datetime, timedelta, timezone

ROOT      = os.path.dirname(os.path.abspath(__file__))
BENCH_DIR = os.path.join(ROOT, "static-benchmark")
ORIG_DIR    = os.path.join(BENCH_DIR, "original")
OBF_DIR     = os.path.join(BENCH_DIR, "obfuscated")
OBF_CFF_DIR = os.path.join(BENCH_DIR, "obf_cff")
GT_PATH   = os.path.join(ROOT, "oracle", "ground_truth.json")  # in oracle/ — never shown to agent
RAW_DIR   = os.path.join(ROOT, "raw_outputs")  # full agent stdout, one file per (state, module)

# ── Toggle ────────────────────────────────────────────────────────
# False → use `claude` CLI  (requires subscription with credits)
# True  → use Anthropic API (requires ANTHROPIC_API_KEY env var)
USE_API = False
API_MODEL = "claude-sonnet-4-6"  # model for USE_API=True path

# Ground truth: category folder → canonical vulnerability type
VULN_TYPE = {
    "prototype-pollution": "Prototype Pollution",
    "redos":               "ReDoS",
    "command-injection":   "Command Injection",
    "path-traversal":      "Path Traversal",
    "code-injection":      "Arbitrary Code Injection",
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

PROMPT = """You are a senior JavaScript security researcher auditing an npm package for vulnerabilities.

Use the available tools to explore the package:
1. Read package.json to identify the package name and version
2. List and read the JavaScript source files under node_modules/<package-name>/
   (skip any nested node_modules/ inside the package)
3. Trace how user-controlled input flows through the code to dangerous operations
4. Pinpoint the exact sink: file, enclosing function, and line number(s)

Output ONLY valid JSON — no explanation, no prose, no markdown fences:

{
  "package": "<name>@<version>",
  "vulnerable": true,
  "vulnerabilities": [
    {
      "type": "<Prototype Pollution | Command Injection | ReDoS | Path Traversal | Arbitrary Code Injection | Other>",
      "sink_api": "<dangerous built-in at the sink, e.g. child_process.exec, eval, fs.readFile, RegExp.exec, __proto__>",
      "file": "<path relative to package root, e.g. lib/index.js>",
      "function_name": "<enclosing function name, or __file_scope__ if at module level>",
      "vulnerable_lines": [<one or more line numbers where the dangerous operation occurs>],
      "confidence": <0.0–1.0>,
      "description": "<one sentence: what input reaches what sink and what an attacker can do>",
      "snippet": "<the vulnerable code at the sink>"
    }
  ]
}

If no vulnerability is found:
{"package": "<name>@<version>", "vulnerable": false, "vulnerabilities": []}"""

# Neutral framing for agy/Gemini — avoids safety-filter keywords while asking the same question
PROMPT_AGY = """You are a static analysis tool performing data-flow analysis on an npm package.

Use the available tools to inspect the package:
1. Read package.json to identify the package name and version
2. List and read the JavaScript source files under node_modules/<package-name>/
   (skip any nested node_modules/ inside the package)
3. Trace how function arguments and external input flow through the code
4. Find locations where unsanitized input reaches system APIs such as:
   child_process.exec, child_process.spawn, eval, new Function, fs.readFile,
   fs.createReadStream, RegExp constructors, or object property assignment via
   __proto__ or constructor.prototype
5. Record the exact file, enclosing function, and line number(s)

Output ONLY valid JSON — no explanation, no prose, no markdown fences:

{
  "package": "<name>@<version>",
  "vulnerable": true,
  "vulnerabilities": [
    {
      "type": "<Prototype Pollution | Command Injection | ReDoS | Path Traversal | Arbitrary Code Injection | Other>",
      "sink_api": "<system API reached by unsanitized input, e.g. child_process.exec, eval, fs.readFile, RegExp, __proto__>",
      "file": "<path relative to package root, e.g. lib/index.js>",
      "function_name": "<enclosing function name, or __file_scope__ if at module level>",
      "vulnerable_lines": [<one or more line numbers>],
      "confidence": <0.0–1.0>,
      "description": "<one sentence: input source → system API → effect>",
      "snippet": "<the relevant code lines>"
    }
  ]
}

If no such data-flow pattern is found:
{"package": "<name>@<version>", "vulnerable": false, "vulnerabilities": []}"""


def run_agent(module_dir, provider="claude_cli", model=None, timeout=360):
    """Dispatch to the right backend."""
    if provider == "agy_cli":
        return _run_via_agy_cli(module_dir, model=model, timeout=timeout)
    elif provider == "gemini_api":
        return _run_via_gemini_api(module_dir, model=model)
    elif USE_API:
        return _run_via_api(module_dir)
    else:
        return _run_via_cli(module_dir, timeout=timeout)


def _run_via_cli(module_dir, timeout=360):
    """Use Claude CLI (subscription) — prompt via stdin, structured JSON output."""
    result = subprocess.run(
        ["claude", "--print", "--dangerously-skip-permissions", "--output-format", "json"],
        input=PROMPT.encode(),
        cwd=module_dir, capture_output=True, timeout=timeout,
    )
    stdout = result.stdout.decode("utf-8", errors="replace")
    stderr = result.stderr.decode("utf-8", errors="replace")

    # JSONL output: find the "result" object which holds the final text in its
    # "result" field. Also look for "assistant" blocks as a secondary source.
    final_text = ""
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if obj.get("type") == "result":
            final_text = obj.get("result", "")
            break  # this is the definitive final output
        if obj.get("type") == "assistant":
            for block in obj.get("message", {}).get("content", []):
                if block.get("type") == "text":
                    final_text += block["text"]

    return final_text or stdout, stderr, result.returncode


def _run_via_agy_cli(module_dir, model=None, timeout=420):
    """Use Google's agy CLI — isolated temp dir to prevent oracle leakage."""
    import shutil
    import tempfile

    agy_cmd = "agy"
    if not shutil.which("agy"):
        local_agy = os.path.expanduser("~/.local/bin/agy")
        if os.path.exists(local_agy):
            agy_cmd = local_agy

    # Determine the main package name from package.json
    pkg_json_path = os.path.join(module_dir, "package.json")
    try:
        with open(pkg_json_path) as f:
            pkg_data = json.load(f)
        pkg_name = list(pkg_data.get("dependencies", {}).keys())[0]
    except Exception:
        pkg_name = None

    # Copy only the main package source (no nested node_modules) into an
    # isolated temp dir so agy cannot navigate up to oracle/ or results files.
    with tempfile.TemporaryDirectory(prefix="agy_bench_") as tmp_dir:
        shutil.copy2(pkg_json_path, tmp_dir)
        if pkg_name:
            src = os.path.join(module_dir, "node_modules", pkg_name)
            dst = os.path.join(tmp_dir, "node_modules", pkg_name)
            if os.path.isdir(src):
                shutil.copytree(src, dst,
                                ignore=shutil.ignore_patterns("node_modules"))

        # Default to Claude Sonnet via agy — Gemini models refuse security tasks
        effective_model = model or "claude-sonnet-4-6"
        cmd = [agy_cmd, "--dangerously-skip-permissions",
               "--add-dir", tmp_dir, "--model", effective_model, "--print", PROMPT]


        result = subprocess.run(
            cmd, cwd=tmp_dir, capture_output=True, timeout=timeout,
        )

    stdout = result.stdout.decode("utf-8", errors="replace")
    stderr = result.stderr.decode("utf-8", errors="replace")
    return stdout, stderr, result.returncode


def _run_via_gemini_api(module_dir, model=None):
    """Use Google Gemini API directly with a tool-use agent loop.
    Reads GEMINI_API_KEY or GOOGLE_API_KEY from the environment.
    """
    from google import genai
    from google.genai import types

    api_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if not api_key:
        raise RuntimeError("Set GEMINI_API_KEY or GOOGLE_API_KEY to use gemini_api provider")

    client = genai.Client(api_key=api_key)
    model_id = model or "gemini-2.5-pro"

    def _read_file(path):
        safe = os.path.normpath(os.path.join(module_dir, path))
        if not safe.startswith(os.path.abspath(module_dir)):
            return "Error: path outside module directory"
        try:
            content = open(safe, errors="ignore").read()
            return content[:20000] + "\n...(truncated)" if len(content) > 20000 else content
        except Exception as e:
            return f"Error: {e}"

    def _list_dir(path):
        safe = os.path.normpath(os.path.join(module_dir, path))
        if not safe.startswith(os.path.abspath(module_dir)):
            return "Error: path outside module directory"
        try:
            return "\n".join(os.listdir(safe))
        except Exception as e:
            return f"Error: {e}"

    def _search_file(path, pattern):
        safe = os.path.normpath(os.path.join(module_dir, path))
        if not safe.startswith(os.path.abspath(module_dir)):
            return "Error: path outside module directory"
        try:
            hits = [f"{i}: {l.rstrip()}"
                    for i, l in enumerate(open(safe, errors="ignore"), 1)
                    if pattern.lower() in l.lower()]
            return "\n".join(hits) if hits else "No matches"
        except Exception as e:
            return f"Error: {e}"

    tools = types.Tool(function_declarations=[
        types.FunctionDeclaration(
            name="read_file",
            description="Read a file's contents (path relative to module directory)",
            parameters=types.Schema(
                type=types.Type.OBJECT,
                properties={"path": types.Schema(type=types.Type.STRING)},
                required=["path"],
            ),
        ),
        types.FunctionDeclaration(
            name="list_directory",
            description="List files in a directory (path relative to module directory)",
            parameters=types.Schema(
                type=types.Type.OBJECT,
                properties={"path": types.Schema(type=types.Type.STRING)},
                required=["path"],
            ),
        ),
        types.FunctionDeclaration(
            name="search_in_file",
            description="Search for a string pattern in a file, returns matching lines with numbers",
            parameters=types.Schema(
                type=types.Type.OBJECT,
                properties={
                    "path":    types.Schema(type=types.Type.STRING),
                    "pattern": types.Schema(type=types.Type.STRING),
                },
                required=["path", "pattern"],
            ),
        ),
    ])

    contents = [types.Content(role="user",
                              parts=[types.Part.from_text(text=PROMPT)])]
    final_text = ""

    for _ in range(20):  # max tool-use rounds
        resp = client.models.generate_content(
            model=model_id,
            contents=contents,
            config=types.GenerateContentConfig(tools=[tools], max_output_tokens=4096),
        )
        contents.append(types.Content(role="model", parts=resp.candidates[0].content.parts))

        fn_calls = [p for p in resp.candidates[0].content.parts if p.function_call]
        if not fn_calls:
            for p in resp.candidates[0].content.parts:
                if hasattr(p, "text") and p.text:
                    final_text = p.text
            break

        tool_results = []
        for p in fn_calls:
            fc = p.function_call
            inp = dict(fc.args)
            if fc.name == "read_file":
                result = _read_file(inp.get("path", ""))
            elif fc.name == "list_directory":
                result = _list_dir(inp.get("path", ""))
            elif fc.name == "search_in_file":
                result = _search_file(inp.get("path", ""), inp.get("pattern", ""))
            else:
                result = "Unknown tool"
            tool_results.append(types.Part.from_function_response(
                name=fc.name, response={"result": result}
            ))
        contents.append(types.Content(role="user", parts=tool_results))

    return final_text, "", 0


def _run_via_api(module_dir):
    """Use Anthropic API directly with tool-use agent loop."""
    import anthropic

    client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env

    tools = [
        {
            "name": "read_file",
            "description": "Read a file's contents",
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "description": "Path relative to module directory"}
                },
                "required": ["path"]
            }
        },
        {
            "name": "list_directory",
            "description": "List files in a directory",
            "input_schema": {
                "type": "object",
                "properties": {
                    "path": {"type": "string"}
                },
                "required": ["path"]
            }
        },
        {
            "name": "search_in_file",
            "description": "Search for a string pattern in a file, returns matching lines with numbers",
            "input_schema": {
                "type": "object",
                "properties": {
                    "path":    {"type": "string"},
                    "pattern": {"type": "string"}
                },
                "required": ["path", "pattern"]
            }
        },
    ]

    def execute_tool(name, inp):
        rel  = inp.get("path", "")
        safe = os.path.normpath(os.path.join(module_dir, rel))
        if not safe.startswith(os.path.abspath(module_dir)):
            return "Error: path outside module directory"
        if name == "read_file":
            try:
                content = open(safe).read()
                return content[:20000] + "\n...(truncated)" if len(content) > 20000 else content
            except Exception as e:
                return f"Error: {e}"
        elif name == "list_directory":
            try:
                return "\n".join(os.listdir(safe))
            except Exception as e:
                return f"Error: {e}"
        elif name == "search_in_file":
            pattern = inp.get("pattern", "")
            try:
                hits = [f"{i}: {l.rstrip()}"
                        for i, l in enumerate(open(safe), 1)
                        if pattern.lower() in l.lower()]
                return "\n".join(hits) if hits else "No matches"
            except Exception as e:
                return f"Error: {e}"
        return "Unknown tool"

    messages = [{"role": "user", "content": PROMPT}]
    final_text = ""

    while True:
        resp = client.messages.create(
            model=API_MODEL,
            max_tokens=4096,
            tools=tools,
            messages=messages,
        )
        messages.append({"role": "assistant", "content": resp.content})

        if resp.stop_reason == "end_turn":
            for block in resp.content:
                if hasattr(block, "text"):
                    final_text = block.text
            break

        tool_results = []
        for block in resp.content:
            if block.type == "tool_use":
                result = execute_tool(block.name, block.input)
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": result,
                })
        messages.append({"role": "user", "content": tool_results})

    return final_text, "", 0


def extract_json(text):
    """Extract the first JSON object from text output."""
    # Try direct parse first
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Extract from code block
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except json.JSONDecodeError:
            pass
    # Extract bare JSON object
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass
    return None


def type_matches(predicted_type, ground_truth_type):
    """Fuzzy match vulnerability type — case insensitive, partial match ok."""
    p = predicted_type.lower()
    g = ground_truth_type.lower()
    # Direct or partial match
    if g in p or p in g:
        return True
    # Aliases
    aliases = {
        "redos": ["regex", "regular expression", "denial of service", "dos"],
        "prototype pollution": ["proto", "pollution", "prototype"],
        "command injection": ["command", "injection", "rce", "exec"],
        "path traversal": ["path", "traversal", "directory"],
        "arbitrary code injection": ["code", "eval", "injection", "execution", "rce"],
    }
    for key, syns in aliases.items():
        if key in g:
            if any(s in p for s in syns):
                return True
    return False


LINE_TOLERANCE = 5  # predicted line within ±5 of ground truth counts as correct

def location_matches(predicted_file, predicted_lines, gt_file, gt_line):
    """Check if predicted sink location matches ground truth.

    predicted_lines may be an int (old schema), a list (new schema), or None.
    """
    if not gt_file or not predicted_file:
        return False
    pf = predicted_file.replace("\\", "/").lower()
    gf = gt_file.replace("\\", "/").lower()
    file_ok = pf.endswith(gf) or gf.endswith(pf) or os.path.basename(pf) == os.path.basename(gf)
    if not file_ok:
        return False
    if gt_line is None or predicted_lines is None:
        return file_ok
    # Normalise to list
    if isinstance(predicted_lines, list):
        candidates = predicted_lines
    else:
        candidates = [predicted_lines]
    try:
        return any(abs(int(c) - int(gt_line)) <= LINE_TOLERANCE for c in candidates)
    except (TypeError, ValueError):
        return False


def sink_api_matches(predicted_api: str, gt_apis: list) -> bool:
    """
    Check if the predicted sink_api matches any ground-truth API for this category.
    Fuzzy: checks whether the last component of a GT api (e.g. "readFile" from
    "fs.readFile") or the full form appears in the predicted string.
    """
    if not predicted_api or not gt_apis:
        return False
    pred = predicted_api.lower().strip()
    for gt in gt_apis:
        gt_lower = gt.lower()
        # Full match or contained
        if gt_lower in pred or pred in gt_lower:
            return True
        # Match on the last component: "fs.readFile" → "readFile"
        last = gt_lower.split(".")[-1]
        if last and last in pred:
            return True
    return False


def function_matches(predicted_fn: str, gt_fn: str) -> bool:
    """Case-insensitive match; treats __unknown__ as no GT."""
    if not gt_fn or gt_fn in ("__unknown__", "__file_scope__") or not predicted_fn:
        return False
    return predicted_fn.lower().strip() == gt_fn.lower().strip()


def evaluate(parsed, gt_type, gt_file=None, gt_line=None, gt_sink_apis=None, gt_function=None):
    """
    Returns dict with:
      vulnerable_detected: did agent say vulnerable=true?
      type_correct:        did agent identify the right vuln type?
      sink_api_correct:    did agent identify the right dangerous built-in API?
      location_correct:    did agent find the right file+line (sink)?
      function_correct:    did agent name the right enclosing function?
      predicted_types:     list of types the agent reported
    Handles both old schema (line: int) and new schema (vulnerable_lines: list).
    """
    if parsed is None:
        return {"vulnerable_detected": False, "type_correct": False,
                "sink_api_correct": False, "location_correct": False,
                "function_correct": False,
                "predicted_types": [], "parse_error": True}

    vuln_flag = parsed.get("vulnerable", False)
    vulns     = parsed.get("vulnerabilities", [])
    predicted = [v.get("type", "") for v in vulns]

    type_correct = any(type_matches(t, gt_type) for t in predicted)

    sink_api_correct = any(
        sink_api_matches(v.get("sink_api", ""), gt_sink_apis or [])
        for v in vulns
    )

    def get_lines(v):
        # new schema: vulnerable_lines list; fall back to old: line int
        lines = v.get("vulnerable_lines")
        if lines is not None:
            return lines
        line = v.get("line")
        return line  # may be int or None

    location_correct = any(
        location_matches(v.get("file", ""), get_lines(v), gt_file, gt_line)
        for v in vulns
    )

    function_correct = any(
        function_matches(v.get("function_name", ""), gt_function)
        for v in vulns
    ) if gt_function else False

    return {
        "vulnerable_detected":  vuln_flag,
        "type_correct":         type_correct,
        "sink_api_correct":     sink_api_correct,
        "location_correct":     location_correct,
        "function_correct":     function_correct,
        "predicted_types":      predicted,
        "predicted_sink_apis":  [v.get("sink_api", "") for v in vulns],
        "predicted_locations":  [(v.get("file", ""), get_lines(v)) for v in vulns],
        "predicted_functions":  [v.get("function_name", "") for v in vulns],
        "predicted_confidences":[v.get("confidence") for v in vulns],
        "parse_error":          False,
    }


def wait_for_session_reset(reset_hour_cst=22, extra_minutes=2):
    """Sleep until `reset_hour_cst`:MM Asia/Shanghai and return."""
    cst = timezone(timedelta(hours=8))
    now = datetime.now(tz=cst)
    reset = now.replace(hour=reset_hour_cst, minute=extra_minutes, second=0, microsecond=0)
    if reset <= now:
        reset += timedelta(days=1)
    secs = (reset - now).total_seconds()
    print(f"  Sleeping {secs/3600:.1f}h until {reset.strftime('%Y-%m-%d %H:%M CST')} ...", flush=True)
    time.sleep(secs)
    print("  Woke up — retrying.")


def main():
    ap = argparse.ArgumentParser(description="Static vulnerability analysis benchmark")
    ap.add_argument("--wait-for-limit", action="store_true",
                    help="When session limit is hit, sleep until 22:02 CST and retry")
    ap.add_argument("--tiers", default=None,
                    help="Comma-separated tiers to run: original,obfuscated "
                         "(default: all available)")
    ap.add_argument("--provider", default="claude_cli",
                    choices=["claude_cli", "agy_cli", "gemini_api"],
                    help="Agent backend to use (default: claude_cli)")
    ap.add_argument("--model", default=None,
                    help="Model name to pass to the CLI (e.g. gemini-2.5-pro)")
    ap.add_argument("--modules", default=None,
                    help="Comma-separated module IDs to run (e.g. module_09,module_24). "
                         "Default: all modules.")
    ap.add_argument("--resume", action="store_true",
                    help="Skip modules that already have a result in the output file")
    args = ap.parse_args()

    # Load ground truth mapping (module_XX → category + vuln type)
    with open(GT_PATH) as f:
        ground_truth = json.load(f)

    # Determine which tiers to run
    all_state_dirs = [("original",   ORIG_DIR),
                      ("obfuscated", OBF_DIR),
                      ("obf_cff",    OBF_CFF_DIR)]
    if args.tiers:
        wanted = {t.strip() for t in args.tiers.split(",")}
        state_dirs = [(s, d) for s, d in all_state_dirs if s in wanted]
    else:
        state_dirs = [(s, d) for s, d in all_state_dirs if os.path.isdir(d)]

    # Filter to specific modules if requested
    wanted_modules = None
    if args.modules:
        wanted_modules = {m.strip() for m in args.modules.split(",")}

    tasks = []
    for mid in sorted(ground_truth.keys()):
        if wanted_modules and mid not in wanted_modules:
            continue
        for state, base_dir in state_dirs:
            module_dir = os.path.join(base_dir, mid)
            if os.path.isdir(module_dir):
                tasks.append((mid, state, module_dir))
            else:
                print(f"WARNING: missing {module_dir}")

    # Results and raw outputs are namespaced by provider so runs don't collide.
    provider_tag = args.provider  # e.g. "claude_cli", "agy_cli"
    out_path = os.path.join(ROOT, f"static_analysis_results_{provider_tag}.json")
    results  = []
    done_set = set()   # (module_id, state) pairs already recorded
    if os.path.exists(out_path):
        try:
            with open(out_path) as f:
                saved = json.load(f)
            saved_results = saved.get("results", [])
            # Check first result to detect stale mappings from a prior shuffle
            stale = False
            for r in saved_results[:1]:
                mid = r.get("module_id")
                if mid and mid in ground_truth:
                    if r.get("module") != ground_truth[mid].get("module"):
                        stale = True
                        print(f"Saved results are from a different shuffle — starting fresh.\n")
                        break
            if not stale:
                # Exclude timed-out and parse-error (session limit) results from
                # done_set so they get retried; keep them out of results too.
                results  = [r for r in saved_results
                            if not r.get("timeout") and not r.get("parse_error")]
                done_set = {(r["module_id"], r["state"]) for r in results}
                n_skipped = len(saved_results) - len(results)
                if done_set:
                    msg = f"Resuming: {len(done_set)} tasks done"
                    if n_skipped:
                        msg += f", {n_skipped} timed-out tasks will be retried"
                    print(msg + ".\n")
        except Exception:
            results  = []
            done_set = set()

    tasks = [t for t in tasks if (t[0], t[1]) not in done_set]

    # Ensure raw output directory exists (namespaced by provider)
    raw_dir = os.path.join(RAW_DIR, provider_tag)
    os.makedirs(raw_dir, exist_ok=True)

    # Randomize to avoid sequential bias
    random.shuffle(tasks)
    n_states = len(state_dirs)
    print(f"Running {len(tasks)} tasks (50 modules × {n_states} states), randomized order\n")

    n_done  = len(done_set)

    total_tasks = len(tasks) + len(done_set)
    for mid, state, module_dir in tasks:
        n_done += 1
        info     = ground_truth[mid]
        category = info["category"]
        module   = info["module"]
        gt_type      = info["vuln_type"]
        gt_file      = info.get("sink_file")
        gt_line      = info.get("sink_line")
        gt_sink_apis = info.get("sink_apis", [])
        gt_function  = info.get("sink_function")

        # Agent sees only "module_XX" — no category hint in the log either
        prefix = f"[{n_done:>3}/{total_tasks}] [{state:<10}] {mid}"
        print(f"{prefix} ...", end="", flush=True)

        t0 = time.time()
        try:
            stdout, stderr, rc = run_agent(module_dir, provider=args.provider,
                                           model=args.model)
            elapsed = time.time() - t0

            # Detect session limit — stop or sleep depending on flag
            if "session limit" in stdout.lower() or "session limit" in stderr.lower():
                if args.wait_for_limit:
                    print(f"\n  SESSION_LIMIT detected.", end="", flush=True)
                    wait_for_session_reset()
                    # Retry this task
                    stdout, stderr, rc = run_agent(module_dir, provider=args.provider,
                                                   model=args.model)
                    elapsed = time.time() - t0
                else:
                    print(f"  SESSION_LIMIT — stopping. Re-run after limit resets.")
                    break

            # API-level timeout reported in the response text
            if "request timed out" in stdout.lower():
                raise subprocess.TimeoutExpired(cmd=[], timeout=360)

            # Save full raw output to a file (cheap to re-evaluate later)
            raw_file = os.path.join(raw_dir, f"{state}__{mid}.txt")
            with open(raw_file, "w", errors="replace") as f:
                f.write(stdout)

            parsed  = extract_json(stdout)
            eval_r  = evaluate(parsed, gt_type, gt_file, gt_line, gt_sink_apis, gt_function)

            status_parts = []
            if eval_r["parse_error"]:
                status_parts.append("PARSE_ERROR")
            else:
                status_parts.append("VULN"    if eval_r["vulnerable_detected"] else "NOT_VULN")
                status_parts.append("TYPE_OK" if eval_r["type_correct"]
                                    else f"TYPE_WRONG({','.join(eval_r['predicted_types'][:1])})")
                status_parts.append("API_OK"  if eval_r["sink_api_correct"] else "API_WRONG")
                status_parts.append("LOC_OK"  if eval_r["location_correct"] else "LOC_WRONG")
                if gt_function and gt_function not in ("__unknown__",):
                    status_parts.append("FN_OK" if eval_r["function_correct"] else "FN_WRONG")

            print(f"  {' | '.join(status_parts)}  ({elapsed:.0f}s)")

            results.append({
                "module_id":  mid,
                "category":   category,
                "module":     module,
                "state":      state,
                "provider":   args.provider,
                "model":      args.model,
                "ground_truth_type":     gt_type,
                "ground_truth_file":     gt_file,
                "ground_truth_line":     gt_line,
                "ground_truth_sink_apis": gt_sink_apis,
                "ground_truth_function": gt_function,
                "elapsed_s":               round(elapsed, 1),
                "vulnerable_detected":     eval_r["vulnerable_detected"],
                "type_correct":            eval_r["type_correct"],
                "sink_api_correct":        eval_r["sink_api_correct"],
                "location_correct":        eval_r["location_correct"],
                "function_correct":        eval_r["function_correct"],
                "predicted_types":         eval_r["predicted_types"],
                "predicted_sink_apis":     eval_r.get("predicted_sink_apis", []),
                "predicted_locations":     eval_r.get("predicted_locations", []),
                "predicted_functions":     eval_r.get("predicted_functions", []),
                "predicted_confidences":   eval_r.get("predicted_confidences", []),
                "parse_error":             eval_r["parse_error"],
                "raw_output_file":         os.path.relpath(raw_file, ROOT),
            })

        except subprocess.TimeoutExpired:
            print(f"  TIMEOUT")
            results.append({
                "module_id": mid, "category": category, "module": module,
                "state": state, "ground_truth_type": gt_type, "elapsed_s": 180,
                "vulnerable_detected": False, "type_correct": False,
                "predicted_types": [], "parse_error": False,
                "timeout": True, "raw_output": "",
            })
        except Exception as e:
            print(f"  ERROR: {e}")
            results.append({
                "module_id": mid, "category": category, "module": module,
                "state": state, "ground_truth_type": gt_type, "error": str(e),
                "vulnerable_detected": False, "type_correct": False,
                "predicted_types": [], "parse_error": True, "raw_output": "",
            })

        # Save after every task — safe to interrupt at any point
        with open(out_path, "w") as f:
            json.dump({"tasks_total": total_tasks,
                       "tasks_done":  len(results),
                       "results":     results}, f, indent=2)

    # ── Summary ──────────────────────────────────────────────────────────
    print(f"\n{'='*75}")
    print("SUMMARY")
    print(f"{'='*75}")
    print(f"{'Category':<25} {'State':<12} {'Vuln':<8} {'Type OK':<10} {'API OK':<10} {'Loc OK':<10} {'Fn OK':<8} N")
    print(f"{'-'*25} {'-'*12} {'-'*8} {'-'*10} {'-'*10} {'-'*10} {'-'*8} {'-'*5}")

    states = sorted({r["state"] for r in results})
    for state in states:
        for category in SELECTED:
            subset = [r for r in results
                      if r["category"] == category and r["state"] == state
                      and not r.get("parse_error") and not r.get("timeout") and not r.get("error")]
            n      = len(subset)
            n_vuln = sum(1 for r in subset if r["vulnerable_detected"])
            n_type = sum(1 for r in subset if r["type_correct"])
            n_api  = sum(1 for r in subset if r.get("sink_api_correct"))
            n_loc  = sum(1 for r in subset if r.get("location_correct"))
            fn_sub = [r for r in subset if r.get("ground_truth_function") not in (None, "__unknown__")]
            n_fn   = sum(1 for r in fn_sub if r.get("function_correct"))
            fn_str = f"{n_fn}/{len(fn_sub)}" if fn_sub else "n/a"
            print(f"{category:<25} {state:<12} {n_vuln}/{n:<6} {n_type}/{n:<8} {n_api}/{n:<8} {n_loc}/{n:<8} {fn_str}")

    # Overall
    print()
    for state in states:
        subset = [r for r in results if r["state"] == state
                  and not r.get("parse_error") and not r.get("timeout") and not r.get("error")]
        n      = len(subset)
        n_vuln = sum(1 for r in subset if r["vulnerable_detected"])
        n_type = sum(1 for r in subset if r["type_correct"])
        n_api  = sum(1 for r in subset if r.get("sink_api_correct"))
        n_loc  = sum(1 for r in subset if r.get("location_correct"))
        fn_sub = [r for r in subset if r.get("ground_truth_function") not in (None, "__unknown__")]
        n_fn   = sum(1 for r in fn_sub if r.get("function_correct"))
        fn_str = f"{n_fn}/{len(fn_sub)}" if fn_sub else "n/a"
        print(f"{'TOTAL':<25} {state:<12} {n_vuln}/{n:<6} {n_type}/{n:<8} {n_api}/{n:<8} {n_loc}/{n:<8} {fn_str}")

    print(f"\nNote: agent saw only module_XX names — ground truth in {GT_PATH}")
    print(f"Results saved to: {out_path}")


if __name__ == "__main__":
    main()
