# Research Goals: LLM Vulnerability Detection Under JavaScript Obfuscation

## Research Question

How does JavaScript code obfuscation affect the ability of LLMs and LLM-based agents to detect vulnerabilities — both statically (via source analysis) and dynamically (via PoC generation and execution)?

## Dataset

**SecBench.js** — 600 server-side JavaScript vulnerabilities across 5 categories:

| Category | Count |
|---|---|
| Prototype Pollution | 192 |
| ReDoS | 98 |
| Command Injection | 101 |
| Path Traversal | 169 |
| Arbitrary Code Injection | 40 |

Working sample: **50 modules** (10 per category), defined in `SELECTED` in each script.  
Ground truth: `ground_truth.json` — maps each module to its category, vuln type, and sink location.

---

## Repository Organization

The repo is structured in three benchmark tiers plus an evaluation layer:

```
benchmark/
├── 1-original/              # Raw benchmark — PoC test files + full metadata
│   ├── prototype-pollution/ #   package.json has CVE id, advisory links, fixCommit, sink location
│   ├── command-injection/   #   Used for: dynamic PoC execution, sink extraction
│   ├── path-traversal/
│   ├── redos/
│   └── code-injection/
│
├── 2-cleaned/               # LLM-visible benchmark — library source only, no hints
│   ├── prototype-pollution/ #   package.json stripped to dependencies only
│   ├── command-injection/   #   No PoC test file, no CVE, no sink, no advisory links
│   ├── path-traversal/      #   Currently: static-benchmark-original/ (to be renamed)
│   ├── redos/
│   └── code-injection/
│
└── 3-obfuscated/            # One subdirectory per obfuscation tool/variant
    ├── javascript-obfuscator-default/   # Currently: static-benchmark-obfuscated/
    │   ├── prototype-pollution/
    │   └── ...
    ├── javascript-obfuscator-high/      # Higher entropy, control-flow flattening
    └── terser/                          # Minifier-style obfuscation (future)

evaluation/
├── oracles/
│   ├── ground_truth.json                # Static oracle: category, sink_api, sink_line (original)
│   └── sink-extraction/                 # Dynamic oracle: per-category API-wrapping instrumentation
│       ├── command-injection/sink-extraction-setup.js
│       ├── path-traversal/sink-extraction-setup.js
│       ├── prototype-pollution/sink-extraction-setup.js  ← needs fixing
│       ├── redos/sink-extraction-setup.js
│       └── code-injection/sink-extraction-setup.js       ← eval not wired
├── static/
│   ├── run_static_analysis.py           # LLM reads 2-cleaned or 3-obfuscated source
│   └── results/
└── dynamic/
    ├── evaluate.py                      # LLM generates PoC; runs against 1-original
    ├── run_poc_tests.py                 # Run existing PoCs on original library
    ├── run_obfuscated_poc_tests.py      # Run existing PoCs on obfuscated library
    └── results/
```

### What each tier contains and why

**1-original**: The full benchmark as-is. The `package.json` contains `sink`, `id` (CVE), `links`, `fixedVersion`, `fixCommit` — everything needed to understand the vulnerability. This is the ground truth source and is used for dynamic PoC execution. It must **never** be shown directly to the LLM for static evaluation (it would be cheating).

**2-cleaned**: The library source files inside `node_modules/`, with a `package.json` stripped to only `dependencies`. No PoC test file. No metadata that hints at the vulnerability type or location. This is what the LLM sees for static analysis on unobfuscated code. Currently staged as `static-benchmark-original/`.

**3-obfuscated**: Derived from 2-cleaned by running an obfuscation tool on the library files inside `node_modules/<pkg>/`. Multiple subdirectories, one per tool or configuration variant. Currently one variant staged as `static-benchmark-obfuscated/`. Each variant is self-contained (library files replaced in-place).

---

## Phase 1 — Baseline Detection (No Obfuscation)

Establish how well LLMs detect vulnerabilities on original, unobfuscated code.

### 1A. Static Detection (source analysis only)

- **Task**: Give the LLM the vulnerable package's JS source files; ask it to identify whether a vulnerability is present and what type/location.
- **Script**: `run_static_analysis_agent.py` (uses Claude CLI or Anthropic API)
- **Metrics**:
  - Detection rate: fraction of modules where the LLM correctly flags a vulnerability
  - Classification accuracy: fraction where the correct vulnerability type is identified
  - Localization accuracy: fraction where the sink file/line is approximately correct
- **Oracle**: `ground_truth.json` (category + sink location)
- **Output**: `static_analysis_results.json`

### 1B. Dynamic Detection (PoC generation + execution)

- **Task**: Give the LLM the source code and vulnerability class; ask it to write a JavaScript PoC. Run the PoC against the vulnerable package and check if the exploit triggers.
- **Script**: `evaluate.py`
- **Oracle**: The PoC must produce a distinct behavioral signal on the vulnerable version but NOT on the patched version (differential testing). Per-category signals:
  - Prototype Pollution: `Object.prototype` has an injected property after the call
  - ReDoS: execution time exceeds a threshold (e.g. 2 seconds) on the crafted input
  - Command Injection: a controlled side-effect executes (e.g. file written, echo captured)
  - Path Traversal: a file outside the web root is served/read
  - Arbitrary Code Injection: injected JS executes (return value or side-effect)
- **Metrics**: PoC success rate (triggered on vuln version), false-positive rate (triggered on patched version)
- **Output**: `poc_test_results.json`

---

## Phase 2 — Obfuscation Methods

Apply obfuscation to the vulnerable library source and re-run both detection modes.

### Obfuscation Techniques to Evaluate

| Method | Tool | What it does |
|---|---|---|
| **javascript-obfuscator** | `javascript-obfuscator` npm package | Renames identifiers, encodes strings, adds dead code, splits strings, flattens control flow |
| **Webcrack deobfuscation (inverse)** | `webcrack` npm package | Deobfuscation tool — useful to test whether deobfuscation first helps the LLM recover |
| *(Future)* Semantic-preserving transforms | babel plugins | Inline functions, rename vars to meaningless names, restructure control flow without full obfuscation |

### What is Obfuscated

- **Library source only**: the vulnerable npm package files inside `node_modules/<pkg>/` are obfuscated in-place.
- The test/PoC file is **not** obfuscated — the attacker's code is readable; only the target library is opaque.
- The obfuscated benchmarks live in `static-benchmark-obfuscated/`.

### Scripts

- `run_obfuscated_poc_tests.py` — obfuscate library, run original PoC test, record pass/fail
- `run_deobfuscated_poc_tests.py` — deobfuscate with webcrack, then re-run PoC test
- `run_deobfuscated_webcrack_poc_tests.py` — variant using webcrack output directly

---

## Phase 3 — Evaluation Under Obfuscation

Re-run Phase 1 experiments on obfuscated code and measure the degradation.

### 3A. Static Detection on Obfuscated Code

- Feed the obfuscated library source to the LLM and repeat Phase 1A.
- **Key challenge**: After obfuscation, identifier names, string literals, and control flow structures change. The ground truth sink location (`sink_file:sink_line` in `ground_truth.json`) becomes stale.

#### Oracle Problem: Updating Ground Truth After Obfuscation

The original `ground_truth.json` records sink positions in the unobfuscated source. Three approaches to re-derive a valid oracle for obfuscated code:

**Approach A — Source maps (primary, recommended)**

`javascript-obfuscator` supports `sourceMap: true`. At obfuscation time, emit the source map alongside the obfuscated file. The map translates original `(file, line, col)` → obfuscated `(file, line, col)` deterministically, so the original ground truth can be mechanically re-projected onto the obfuscated version.

- Requires controlling the obfuscation step (we do — `run_obfuscated_poc_tests.py`).
- Works even if the PoC fails to trigger post-obfuscation.
- Implementation: extend `run_obfuscated_poc_tests.py` to save source maps; add a projection script that reads the map and writes an `obfuscated_ground_truth.json`.

**Approach B — Re-run dynamic sink extractor (cross-check)**

The existing `sink-extraction-setup.js` wraps built-in APIs at runtime and captures the call stack. Running the PoC against the obfuscated library with this setup produces a new stack trace whose top frame is the new sink location.

- Uses existing tooling with minimal change.
- Limitation: only works if the PoC still triggers on the obfuscated library (obfuscation should preserve behavior, but control-flow flattening can cause issues).
- Use as a cross-check against Approach A.

**Approach C — AST scan for known sink APIs (fallback)**

Obfuscation renames user-defined identifiers but cannot rename built-in APIs (`fs.readFile`, `child_process.exec`, `RegExp.exec`, etc.). Parse the obfuscated AST (with `esprima`/`acorn`) and locate calls to the known sink API for each vulnerability category. This gives the obfuscated sink line without needing source maps or a working PoC.

- Limitation: some obfuscators use indirect property access (`require("fs")["readFile"]`) or encode the string `"readFile"` — check whether `javascript-obfuscator` does this for built-in method names.

#### What to Evaluate Against LLM Output

Rather than asking the LLM to output a line number (fragile for obfuscated code), ask it to output:
1. `vulnerable: bool`
2. `vuln_type: string` — the vulnerability category
3. `sink_api: string` — the dangerous built-in it identified (e.g. `"fs.readFile"`, `"child_process.exec"`)
4. `sink_snippet: string` — the actual code fragment it considers the sink

Evaluation then checks `sink_api` against a category-level ground truth table of known sinks (not a line number), which is robust across obfuscation. Line-level localization is only measured on original code.

- **Metrics**: Detection rate, classification accuracy, sink API identification rate — all reported as delta vs. baseline.
- Localization (line-level) is measured on original code only and dropped for obfuscated evaluation.

### 3B. Dynamic Detection on Obfuscated Code

- Feed the LLM the obfuscated source and ask it to generate a PoC.
- **Key challenge**: The PoC oracle only cares whether the exploit triggers at runtime — obfuscation of the library does not change runtime behavior (by design). So the same differential oracle from Phase 1B applies without modification.
- **Metrics**: PoC success rate on obfuscated library, compared to baseline.
- **Insight to capture**: If static comprehension degrades but the exploit still triggers, the LLM may be reasoning about behavior abstractly rather than reading code literally.

---

## Phase 4 — Analysis and Findings

### Questions to Answer

1. **Static gap**: By how much does obfuscation reduce static detection rate? Is the drop uniform across vuln categories or does it affect some categories more (e.g., does prototype pollution identification rely more on identifier names like `__proto__`)?
2. **Dynamic gap**: Does obfuscation affect PoC generation success? If not, why — is the LLM ignoring the library source and reasoning from the category hint alone?
3. **Deobfuscation recovery**: Does running webcrack before giving code to the LLM restore static detection rates? By how much?
4. **Oracle validity**: Are there false positives in the dynamic oracle (PoC triggers on patched version)? What causes them?
5. **Category breakdown**: Which of the 5 vuln classes is most/least affected by obfuscation?

### Metrics Summary Table (target output format)

| Condition | Static detect rate | Static classify rate | Dynamic PoC rate | FP rate |
|---|---|---|---|---|
| Original (baseline) | | | | |
| Obfuscated | | | | |
| Obfuscated + deobfuscated | | | | |

---

## Oracle Design Notes

### Static Oracle

- **Ground truth source**: `ground_truth.json` (category, sink file, sink line)
- **Evaluation**: Parse LLM JSON output for `vulnerable: bool`, `vuln_type: str`, `sink_location: str`
- **Matching rules**:
  - Detection: `vulnerable == true`
  - Classification: normalized vuln type string matches ground truth category
  - Localization (original only): sink file matches AND line is within ±5 lines
- **Post-obfuscation**: Drop localization metric; use category match only

### Dynamic Oracle

- **Differential testing**: run PoC against vulnerable version, then patched version
  - True positive: triggers on vuln, does NOT trigger on patched
  - False positive: triggers on both versions
  - False negative: triggers on neither
- **Per-category trigger detection** (already partially implemented in `evaluate.py`):
  - Prototype Pollution: check `Object.prototype` for injected key after call
  - ReDoS: wall-clock timeout > threshold
  - Command Injection: subprocess side-effect (sentinel file or stdout capture)
  - Path Traversal: HTTP response contains out-of-root file content
  - Code Injection: return value or global contains injected expression result
- **Timeout**: 30s per PoC run; ReDoS threshold separate (2s regex match time)

---

## Work Items (Ordered)

- [x] Baseline static analysis script (`run_static_analysis_agent.py`)
- [x] Baseline dynamic PoC evaluation (`evaluate.py`)
- [x] Obfuscation pipeline for library source (`run_obfuscated_poc_tests.py`)
- [x] Deobfuscation pipeline (`run_deobfuscated_poc_tests.py`, `run_deobfuscated_webcrack_poc_tests.py`)
- [x] Ground truth file (`oracle/ground_truth.json`) — all 50 sinks populated
- [x] **LLM prompt update for static analysis** — output schema now includes `sink_api` field; `sink_api_correct` metric added to evaluation and summary table
- [x] **Post-obfuscation sink oracle** — `project_obfuscated_sinks.py` uses call-site + string-literal scan; writes `oracle/obfuscated_ground_truth.json` (39/50 sinks found: 8 via call, 31 via string)
- [x] **Evaluation aggregator** — `aggregate_results.py` reads all result JSONs, shows comparison table; `--by-category` flag for per-category breakdown
- [x] **Per-category breakdown** — implemented in `aggregate_results.py --by-category`
- [x] **Webcrack deobfuscated benchmark** — `setup_anonymous_benchmark.py` now generates `/tmp/js-eval-webcrack/`; `run_static_analysis_agent.py` picks it up automatically
- [x] **Static analysis re-run** — IN PROGRESS (`run_static_analysis_agent.py` running, 150 tasks: original + obfuscated + webcrack, with `sink_api` field in prompt)
- [ ] **Anonymous dynamic PoC evaluation** — `evaluate_anon.py` ready; run with `python3 evaluate_anon.py --all-conditions` to get LLM PoC rates with no CVE/sink hints given
- [ ] **False-positive audit** — current FP rate is 0%; revisit after full runs complete
- [ ] **Write-up** — findings section covering all four research questions above

### Key Findings So Far (partial — static analysis 82/150 tasks done, 2026-06-26)

Current results (n≈25 per state, preliminary):

| Condition | Detect | Classify | SinkAPI | Locate | DynPoC (prior run) |
|---|---|---|---|---|---|
| original | 96% | 84% | 84% | 72% | 98% |
| obfuscated | 100% | 84% | 84% | 8% | 96% |
| obf+webcrack | 100% | 89% | 89% | 33% | 98% |
| obf+synchrony | 100% | 84% | 84% | 8% | 8% |

Preliminary observations:
- **Detection**: Near-perfect (96–100%) across all conditions. Obfuscation does NOT hide the presence of a vulnerability.
- **Classification**: ~84% across all conditions (not significantly affected by obfuscation). Systematic misclassification exists independent of obfuscation.
- **SinkAPI**: Tracks with classification (same modules fail). Obfuscation encodes built-in API names in string arrays for 11/50 packages, but LLM infers them abstractly anyway.
- **Localization**: Major drop: 72% original → 8% obfuscated. Webcrack partially restores (33%). This is the primary obfuscation impact on static analysis.
- **Dynamic PoC**: 98% → 96% → 98% → 8% (synchrony deobfuscator fails). Obfuscation barely affects PoC generation.
- **FP rate**: 0% across all conditions.

Systematic misclassification patterns (obfuscation-independent):
- `clean-css_4.1.10` (ReDoS): classified as Prototype Pollution in ALL 3 states — inherent code-pattern confusion
- `axios_0.21.0` (ReDoS): classified as Prototype Pollution in 2/3 states
- Two code-injection modules classified as Prototype Pollution across states
- One prototype pollution module classified as ReDoS on webcrack
- Root cause: LLM over-classifies as Prototype Pollution; ReDoS/code-injection code patterns are ambiguous

Persistent timeouts (excluded from analysis):
- `checkit_0.7.0` (1062 transitive dep files via lodash), `ajv_5.2.2`, `is-my-json-valid_2.20.0`, `browserslist_4.16.4` — all large JSON-schema/utility packages
