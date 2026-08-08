# Implementation Plan — Parent/Child Process & Filepath Analysis

Source briefing: *Parent/Child Process & Filepath Analysis Module* (2026-08-08).
This document translates that briefing into concrete changes against the current
codebase, and records the two architecture decisions the briefing left open.

**Out of scope** (per briefing §8): command-line content analysis, WAF payload
decode, Custom Search JSON API, cross-session correlation, and wiring
`aggregated_verdict` into [`ioc/confidence_scorer.py`](../ioc/confidence_scorer.py).

---

## 0. Current State

The four input fields already exist — [`app.py:603-618`](../app.py#L603-L618) inside
`_render_context_expander()`. They are currently **pure passthrough**: the only
consumer is the AI prompt builder at
[`ui/components/ai_panel.py:272-286`](../ui/components/ai_panel.py#L272-L286),
which appends them as free text. There is no detection logic of any kind.

Session-state keys (note: Context is `raw_log`, not `context`):

| Briefing field | Input-tab key | Result-tab twin |
|---|---|---|
| File Path | `file_path` | `result_file_path` |
| Parent Process | `parent_process` | `result_parent_process` |
| Child Process | `child_process` | `result_child_process` |
| Context | `raw_log` | `result_raw_log` |

Snapshot Input → Result happens in `_snapshot_input_context_to_result()`
([`app.py:311-320`](../app.py#L311-L320)), driven by `_INPUT_CONTEXT_KEYS`
([`app.py:304-308`](../app.py#L304-L308)). All four keys are already listed there —
no change needed.

---

## 1. Architecture Decisions

### D1 — Run gate: allow a process-only run

**Problem.** The whole enrichment block is gated on the main IOC box:

```python
# app.py:1056
if run_requested and raw.strip():
```

If the analyst fills only Parent + Child and leaves the IOC box empty, nothing
runs. Briefing §5.7 assumes UI-layer validation of "at least one field", but does
not account for this gate.

**Decision: relax the gate, keep provider lookups IOC-driven.**

```python
if run_requested and (raw.strip() or _has_process_input()):
```

When `raw` is empty, `items` is `[]`, every `_payload(p)` returns `[]`, so
`provider_flags` is all-`False` and `run_provider_lookups` starts zero threads —
the existing orchestrator needs **no change**. `summarize_results([])` returns an
empty summary and `rows == []`, which the Table/JSON renderers already handle.
Process analysis then runs locally and contributes its own rows (see §5).

Rejected alternative: a separate "Process" analysis mode next to
Triage / Path Probe. It duplicates the whole Run/Result plumbing for a module
that is meant to enrich the same event, not replace it.

### D2 — Flag injection: parallel list, not a provider

**Problem.** `extract_ioc_flags()`
([`ioc/flags/__init__.py:27-40`](../ioc/flags/__init__.py#L27-L40)) has a hardcoded
signature of 11 provider dicts and is keyed per-IOC. Process flags come from no
provider and are per-*run*, not per-IOC.

**Decision: do not touch `extract_ioc_flags()`.** Emit process flags as their own
list using the same `_flag()` shape from
[`ioc/flags/base.py:8`](../ioc/flags/base.py#L8). Both downstream consumers are
already generic over `list[dict]`:

- `flags_to_ai_context(flags)` — works on any flag list as-is.
- `flags_summary_for_evidence(flags)` — works, but see the naming hazard below.

This leaves all three existing `extract_ioc_flags()` call sites
([`ai_panel.py:331`](../ui/components/ai_panel.py#L331),
[`:419`](../ui/components/ai_panel.py#L419),
[`:960`](../ui/components/ai_panel.py#L960)) untouched.

**Naming hazard — must not be ignored.** `flags_summary_for_evidence()` maps flag
IDs to evidence keys by **substring match**
([`ioc/flags/__init__.py:127-147`](../ioc/flags/__init__.py#L127-L147)). Two
collisions to avoid when naming new flags:

- `"SIGMA"` → `malware_executed`. So the pairing flag must be
  `SUSPICIOUS_PARENT_CHILD_PAIR`, **never** `SIGMA_PAIR_MATCH`.
- `"PROCESS_INJECTION"` → `privilege_escalation`. Avoid that substring.

Conversely, `MASQUERADING_*` currently maps to **no** evidence key, so a
masquerading finding would silently contribute nothing to Threat Analysis. Add
explicit mappings in the same function:

```python
if any(k in fid for k in ("MASQUERADING", "PARENT_CHAIN_CONTAMINATION")):
    ev["persistence_mechanism"] = True   # defense evasion / T1036 foothold
if "SUSPICIOUS_PARENT_CHILD_PAIR" in fid:
    ev["malware_executed"] = True
```

This is an evidence-layer change feeding `analyzeThreat()`, **not** the numeric
confidence scorer — it stays within briefing §8's deferral.

---

## 2. File Layout

```
core/
  process_analyzer.py            # Layer 1 + Layer 4 + aggregation
  lolbas_lookup.py               # Layer 2 loader + matcher
  data/
    known_system_processes.json  # Layer 1 whitelist
    lolbas_binaries.json         # Layer 2 dataset (extracted)
    sigma_parent_child_pairs.json# Layer 4 blocklist (extracted)
  scripts/
    extract_lolbas.py            # offline, from LOLBAS-Project/LOLBAS
    extract_sigma_pairs.py       # offline, from SigmaHQ/sigma
tests/
  test_process_analyzer.py
  test_lolbas_lookup.py
```

Data lives in JSON, not Python constants — per the project rule against
hardcoding threat-feed data. Loaders use `pathlib.Path` and cache via
`functools.lru_cache`.

**Dependencies.** No new runtime dependency.
[`requirements.txt`](../requirements.txt) stays at streamlit / requests /
python-dotenv / pandas:

- **Levenshtein**: implement a ~20-line pure-Python DP in `process_analyzer.py`.
  Against ≤50 whitelist keys of ≤20 chars, `rapidfuzz` buys nothing measurable
  and costs a compiled dependency.
- **PyYAML**: needed only by `scripts/extract_sigma_pairs.py`, which runs offline
  and quarterly. Document it in the script docstring; do not add it to
  `requirements.txt`.

---

## 3. Core Module — `core/process_analyzer.py`

### Data model

```python
@dataclass
class ProcessFilepathInput:
    file_path: str | None = None
    parent_process: str | None = None
    child_process: str | None = None
    context: str | None = None

@dataclass
class FieldAnalysis:
    value: str
    identity_flag: str | None       # LEGITIMATE_SYSTEM_PROCESS | MASQUERADING_WRONG_PATH
                                    # | MASQUERADING_TYPOSQUAT | UNRESOLVED_THIRD_PARTY
    identity_detail: str = ""       # e.g. "expected C:\Windows\System32, saw C:\Users\..."
    lolbas_match: dict | None = None

@dataclass
class ProcessAnalysisResult:
    file_path_analysis: FieldAnalysis | None = None
    parent_process_analysis: FieldAnalysis | None = None
    child_process_analysis: FieldAnalysis | None = None
    hash_verdict: dict | None = None
    pairing_flag: dict | None = None
    chain_contamination: bool = False
    context_passthrough: str | None = None
    aggregated_verdict: str = "Unknown"
    fields_submitted: list[str] = field(default_factory=list)
    flags: list[dict] = field(default_factory=list)   # _flag()-shaped
```

`flags` is added beyond the briefing's §4 struct — it is what feeds the existing
flag system per D2, so it belongs on the result object rather than being
recomputed at each render site.

### Layer 1 — whitelist + Levenshtein

`analyze_identity(name_or_path: str, *, has_path: bool) -> FieldAnalysis`

- Split with `pathlib.PureWindowsPath` — do **not** use `os.path`, the app runs on
  Windows but paths must parse identically regardless of host OS.
- Normalize case-insensitively; expand `%SystemRoot%`/`C:\Windows` equivalence.
- `has_path=False` (parent/child fields) → typosquat check only. `MASQUERADING_WRONG_PATH`
  is unreachable without a path, exactly as briefing §3.1 states.
- Exact name + expected dir → `LEGITIMATE_SYSTEM_PROCESS`
- Exact name + wrong dir → `MASQUERADING_WRONG_PATH` (HIGH)
- No exact match, min Levenshtein ≤ 2 → `MASQUERADING_TYPOSQUAT` (HIGH)
- Otherwise → `UNRESOLVED_THIRD_PARTY` (INFO, not suspicious)

Threshold `LEVENSHTEIN_MAX_DISTANCE = 2` as a module constant so it is tunable
(briefing §9.2). **Known false-positive risk at distance 2**: real pairs like
`csrss.exe`/`cscript.exe` are 4 apart, but short names collide easily — guard by
skipping the fuzzy check when the candidate name length is < 6.

### Layer 4 — parent-child pairing

`match_pairing(parent: str, child: str) -> dict | None`

- Runs **only** when both fields are non-empty (briefing §3.1). Never default the
  missing side.
- Patterns are stored as `*\name.exe` globs; match with `fnmatch` against the
  bare name, since our fields are name-only.
- Preserve `sigma_level` and `sigma_rule_id` on the match — severity is per-rule,
  not uniform.
- **Option A** (pairing-only, drop the CommandLine condition) per briefing's
  recommendation. Every emitted flag detail must carry the string
  `"approximate — Sigma rule <id> also matches on CommandLine"` so an analyst
  reading the ticket knows the match is broader than the source rule.

Chain propagation: if `parent_process_analysis.identity_flag` starts with
`MASQUERADING`, set `chain_contamination = True` and emit
`PARENT_CHAIN_CONTAMINATION`. Depth is capped at 1 by the form (briefing §9.3) —
state that in the module docstring so nobody hunts for a missing recursion.

### Layer 3 — opportunistic hash

Best-effort only. Reuse `HASH_RE` from [`ioc/parser.py:11`](../ioc/parser.py#L11)
— but note it is anchored (`^...$`), so scanning `context` needs an unanchored
variant with word boundaries:

```python
_CONTEXT_HASH_RE = re.compile(r"\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b")
```

`process_analyzer` itself performs **no network I/O** — it returns extracted hash
candidates and lets `app.py` feed them into the existing `items` list so the
normal VT/MalwareBazaar path handles them. This keeps the module pure and unit-
testable, and avoids a second enrichment code path.

### Aggregation

`aggregate_verdict(result) -> str`, precedence per briefing §5:

1. `hash_verdict` present → dominant, return it.
2. Any `MASQUERADING_*` → floor at `Suspicious`.
3. `pairing_flag` with `sigma_level == "high"` → `Suspicious`; → `Malicious` if
   combined with masquerading or chain contamination.
4. LOLBAS alone → no escalation, annotate only.
5. `chain_contamination` → escalate one level.
6. Only one field submitted, nothing matched → `Unknown` (**not** `Benign`).
7. Nothing submitted → caller does not invoke this module at all.

Note rule 6 generalizes: `Benign` is never returned by this module. Absence of
data is `Unknown`, matching the project's existing stance — `summarize_results`
likewise hardcodes `summary["benign"] = 0`
([`ioc/verdict.py:169`](../ioc/verdict.py#L169)).

---

## 4. Layer 2 — `core/lolbas_lookup.py`

`lookup(process_name: str) -> dict | None` returning
`{"binary": ..., "categories": [...], "mitre": [...], "url": ...}`.

The extraction script flattens the LOLBAS YAML corpus to one JSON record per
binary, keeping only name, abuse categories, and the MITRE technique already
present in the dataset. Match on bare filename, case-insensitive.

Per briefing §3 Layer 2, `DUAL_USE_BINARY` is severity **INFO/LOW** and never
escalates a verdict on its own — its detail string should point the analyst at
the command line, which this module deliberately does not analyze.

---

## 5. Integration Points

### 5.1 `app.py` — run the analysis

Inside the enrichment block, after `run_provider_lookups` / before
`st.session_state["run_results"] = {...}` ([`app.py:1128`](../app.py#L1128)):

```python
_proc_result = analyze_process_event(ProcessFilepathInput(
    file_path=file_path or None,
    parent_process=parent_process or None,
    child_process=child_process or None,
    context=raw_log or None,
))
```

Add `"process_analysis": _proc_result` to the `run_results` dict. It is a
dataclass — store it as `asdict()` so the JSON renderer and `st.session_state`
round-trip cleanly.

Also apply the D1 gate change at [`app.py:1056`](../app.py#L1056), plus a
`_has_process_input()` helper.

### 5.2 Table output — reuse the existing row schema

No schema change needed. Emit one synthetic row per submitted field into `rows`,
using the columns already produced by
[`ioc/verdict.py:151-167`](../ioc/verdict.py#L151-L167):

| Column | Value |
|---|---|
| `Artifact` | the field value (`C:\...\x.exe`, or `winword.exe → cmd.exe`) |
| `Type` | `file_path` / `process` / `parent_child_pair` |
| `Verdict` | per-field verdict — picks up existing color styling |
| `Confidence` | `High` / `Med` / `Low` from flag severity |
| `Primary Evidence` | flag label |
| `Next Action` | `Review` |
| `Sources` | `Local (whitelist / LOLBAS / Sigma)` |
| `ConfidenceScore` | `None` — deferred per briefing §8 |
| `ActiveProviders` | `[]` — the renderer already handles list/None at [`output_renderer.py:194-197`](../ui/components/output_renderer.py#L194-L197) |

Set **every** key explicitly, including the `ConfidenceScore` family, so
`pd.DataFrame(rows)` does not produce ragged NaN columns when mixed with real
IOC rows.

### 5.3 JSON output

[`output_renderer.py:254`](../ui/components/output_renderer.py#L254) becomes:

```python
st.json({"summary": summary, "rows": rows,
         "process_analysis": run_results.get("process_analysis")})
```

### 5.4 AI narrative

In `_build_prompt()`
([`ai_panel.py:272-286`](../ui/components/ai_panel.py#L272-L286)), keep the
existing passthrough lines and append the analysis beneath them:

- `flags_to_ai_context(process_flags)` for the matched flags.
- An explicit **"Checks skipped (field not provided): ..."** line derived from
  `fields_submitted`. Briefing §4 calls this out and it matters: without it the
  model will imply certainty about fields the analyst never filled.
- Keep `context_passthrough` exactly as-is — unparsed, per briefing §2.

Also feed `process_flags` through `flags_summary_for_evidence()` at
[`ai_panel.py:419-429`](../ui/components/ai_panel.py#L419-L429) so Threat
Analysis sees the process evidence, using the mappings added in D2.

---

## 6. Build Order

| # | Step | Depends on | Status |
|---|---|---|---|
| 1 | `known_system_processes.json` (~40 entries, Sysinternals-sourced) | — | done (67 entries) |
| 2 | `process_analyzer.py` Layer 1 + Levenshtein + tests | 1 | done |
| 3 | `extract_lolbas.py` → `lolbas_binaries.json`, `lolbas_lookup.py` + tests | — | done (240 binaries) |
| 4 | `extract_sigma_pairs.py` → `sigma_parent_child_pairs.json` | — | done (1874 pairs) |
| 5 | Layer 4 pairing + chain propagation + tests | 2, 4 | done |
| 6 | Aggregation + flag emission + tests | 2, 3, 5 | done |
| 7 | D2 evidence-mapping change in `ioc/flags/__init__.py` | 6 | pending |
| 8 | D1 run-gate change + `app.py` wiring | 6 | pending |
| 9 | Table / JSON / AI-prompt surfacing | 8 | pending |

Steps 1-6 landed as 139 tests across `tests/test_process_analyzer.py`,
`tests/test_lolbas_lookup.py` and `tests/test_sigma_pairs.py`.

**Deviations from this plan, decided during implementation:**

- LOLBAS needed no YAML parsing or repo clone — the project publishes its whole
  corpus as one JSON document, so `extract_lolbas.py` has no PyYAML dependency.
- The fuzzy-match guard became a *length-scaled threshold* on the filename stem
  (distance ≤1 below 6 chars, ≤2 at or above) rather than a hard skip. Every
  `.exe` filename is already ≥5 chars, so the originally planned guard would
  almost never have fired.
- Added extension-swap detection (`svchost.com` vs `svchost.exe`), which
  Levenshtein-on-filename misses at distance 3.
- `has_path` became auto-detected from the value instead of passed per field, so
  a full path pasted into Parent Process is still path-checked.
- **LOLBAS no longer emits a flag on a masquerading field.** Briefing §3 Layer 2
  states the lookup is "only meaningful on processes that passed Layer 1". The
  first implementation ran it unconditionally, producing a `DUAL_USE_BINARY`
  flag reading *"not malicious by itself"* directly beneath a masquerading flag
  on the same field, and crediting the real binary's abuse categories to a file
  that is not it. The lookup still runs, but for a masquerading field it targets
  the **impersonated** binary (`matched_process`, since a typosquat like
  `regsvr33.exe` is itself absent from LOLBAS) and is folded into the
  masquerading flag's detail. MITRE tags stay `T1036.005` only — the
  impersonated tool's techniques describe what it *can* do, not what happened.
- **`path_constrained` was added alongside `commandline_constrained`.** The
  briefing only flagged the dropped CommandLine condition, but many rules —
  including the highest-value Office one — instead pin a *directory*. Tracking
  only CommandLine mislabelled those matches as faithful reproductions of their
  source rule. Only 289 of 1874 pairs (15%) are fully faithful; the matcher now
  prefers those at equal severity.

Steps 1-6 are pure functions with no Streamlit dependency and are fully unit-
testable. Steps 7-9 touch shared code — do them last, once the analyzer's
behavior is pinned by tests.

**Sanity-check after step 4**: verify the extraction actually pulled the
high-value patterns listed in briefing §3 Layer 4 (Office → shell, browsers →
shell, script engines → PowerShell, `mshta.exe` → any, `wmiprvse.exe`/`java.exe`
→ shell, nested `powershell.exe`). If a category is missing, the filter is wrong.

---

## 7. Open Items Carried Forward

- **Chain contamination reaches `Malicious` very readily.** Briefing §5.5 says
  chain contamination escalates one level above the standalone verdict — but
  contamination only ever fires when the parent is masquerading, which §5.2
  already floors at `Suspicious`. So *any* masquerading parent plus *any*
  submitted child lands on `Malicious`, from name-only data with no hash. This
  is implemented as specified and tested, but it is the aggregation rule most
  likely to need softening once real alerts run through it.
- **Only 15% of Sigma pairings are exact.** 1155 of 1874 pairs come from rules
  that also required a CommandLine match, 583 from rules that also pinned a
  directory. Layer 4 surfaces this per match via `approximate_note`, but the
  overall false-positive rate of Option A remains unmeasured against real data.
- **§9.2** Levenshtein threshold ≤2 is a starting guess; needs tuning against
  real data. The stem-length threshold above is a mitigation, not a validation.
- **§9.3** Chain depth capped at 1 by the form. Deeper ancestry needs a UI change.
- **§9.7** No dedicated hash field, so Layer 3 stays opportunistic. Revisit if
  hash-bearing process events turn out to be common.
- Option A's false-positive rate is unmeasured until the Sigma table exists.
  Re-evaluate Option B only after seeing step 4's output volume.
