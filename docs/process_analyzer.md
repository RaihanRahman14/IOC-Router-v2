# Process & Filepath Analysis

Answers three questions about the endpoint fields an EDR alert carries:

1. **Is this binary really what its name claims?** — path baseline and typosquat detection.
2. **Is it a binary attackers routinely borrow?** — LOLBAS dual-use lookup.
3. **Is this parent→child combination known-suspicious?** — Sigma-derived pairing.

Implemented in [`core/process_analyzer.py`](../core/process_analyzer.py) and
[`core/lolbas_lookup.py`](../core/lolbas_lookup.py). Surfaced as Threat
Indicators, ticket table rows, and structured context in the AI narrative.

**No network I/O.** Every layer is a pure function of its input plus the datasets
in [`core/data/`](../core/data).

---

## Input

Four independent, optional fields from the Context panel. Each layer runs only
when its own inputs are present, and nothing is ever inferred about a field the
analyst left blank.

```python
ProcessFilepathInput(
    file_path      = r"C:\Users\Public\a.exe",
    parent_process = "winword.exe",
    child_process  = "cmd.exe",
    context        = "free text from the Context field",
)
```

A run may proceed on these alone, with the IOC box empty. When that happens no
provider lookups start at all — every provider flag comes out false and no worker
threads are created — so a process-only run costs nothing.

`checks_skipped` records which layers did not run and why, so downstream ticket
generation never implies certainty about an unchecked field.

---

## Layer 1 — Identity

`analyze_identity()` against `known_system_processes.json` (66 Windows binaries
and their expected directories).

| Outcome | Meaning | Severity |
|---|---|---|
| `LEGITIMATE_SYSTEM_PROCESS` | Known binary, in an expected directory | — |
| `MASQUERADING_WRONG_PATH` | Known name, wrong directory | HIGH |
| `MASQUERADING_TYPOSQUAT` | Near-miss on a known name (`scvhost.exe`) | HIGH |
| `UNRESOLVED_THIRD_PARTY` | Not in the whitelist — normal for most software | INFO |

Paths are parsed with `PureWindowsPath` so they behave identically regardless of
the host OS, normalised case-insensitively, with `%SystemRoot%` / `%windir%` /
`\SystemRoot` expanded and NT prefixes (`\??\`) stripped.

Typosquat detection uses Levenshtein distance over the filename **stem**, with a
length-scaled threshold — distance ≤1 below 6 characters, ≤2 at or above — because
short names collide by chance far more easily than long ones. Extension swaps
(`svchost.com` vs `svchost.exe`) are detected separately, since Levenshtein over
the stem misses them entirely.

`has_path` is auto-detected from the value, so a full path pasted into the Parent
Process field is still path-checked. Without a path, `MASQUERADING_WRONG_PATH` is
simply unreachable — the layer degrades to a typosquat check rather than guessing.

---

## Layer 2 — LOLBAS dual-use lookup

`lolbas_binaries.json` — 240 binaries with their documented abuse categories and
MITRE ids, matched on bare filename.

A match is **not** a maliciousness signal. LOLBAS binaries are extremely common
in benign activity; the finding is INFO severity and never escalates a verdict on
its own. It means the *command line* deserves review — which is
[the sibling module's](cmdline_analyzer.md) job, and where argument-level
confirmation actually happens.

The lookup does not fire independently on a masquerading field. A
`DUAL_USE_BINARY` flag reading *"not malicious by itself"* directly beneath a
masquerading flag on the same field is a contradiction, and it would credit the
real binary's abuse categories to a file that demonstrably is not it. Instead the
lookup targets the **impersonated** binary and is folded into the masquerading
flag's detail — a typosquat like `regsvr33.exe` is itself absent from LOLBAS.
MITRE tags stay `T1036.005` only: the impersonated tool's techniques describe what
it *can* do, not what happened.

---

## Layer 3 — Opportunistic hash extraction

Best-effort only. Hash-shaped substrings are pulled out of the free-text Context
field and returned as candidates; this module never resolves them. `app.py` merges
them into the normal IOC list so the existing VirusTotal / MalwareBazaar path
enriches them, rather than creating a second lookup path here.

There is no dedicated hash field, so this layer stays opportunistic by design.

---

## Layer 4 — Parent→child pairing

`sigma_parent_child_pairs.json` — 1,874 pairings extracted offline from SigmaHQ
`process_creation` rules. Sigma is never evaluated at runtime; there is no rule
engine, and the app only reads the generated JSON.

Runs **only when both** names are present. The missing side is never guessed or
defaulted. Patterns are stored as `*\name.exe` globs and matched with `fnmatch`
against the bare name.

Each record preserves its `sigma_level`, `sigma_rule_id` and source file, so
severity is per-rule rather than uniform and an analyst can read the original
condition. At equal severity the matcher prefers a rule whose whole condition
survived extraction.

### Extraction is partial, and every record says so

The extraction keeps the pairing and drops `CommandLine` and directory
conditions. Only **289 of 1,874 pairs (15%)** reproduce their source rule exactly:
1,155 come from rules that also required a CommandLine match, 583 from rules that
also pinned a directory. Every affected record carries
`commandline_constrained` / `path_constrained`, and every emitted flag says so in
its detail, so a ticket never presents an approximate match as a faithful one.

Unlike the CommandLine dataset, these approximate records **are** allowed to match
on their own. A parent→child pair is inherently specific — `winword.exe` →
`cmd.exe` means something even without the rule's other conditions — whereas a
CommandLine fragment frequently is not. Requiring full fidelity here would discard
8 of 12 real detections. See [the divergence note](#divergence-from-the-command-line-module).

### Chain contamination

If the parent is masquerading, `chain_contamination` is set and
`PARENT_CHAIN_CONTAMINATION` is emitted — a child inherits doubt about its parent.
Depth is capped at 1 by the form; there is no missing recursion to hunt for.

---

## Verdict aggregation

Never returns **Benign**. Absence of evidence is `Unknown`, consistent with
`ioc/verdict.py` hardcoding the benign count to 0.

| # | Condition | Verdict |
|---|---|---|
| 1 | A resolved hash verdict is present | dominant — returned as-is |
| 2 | Any `MASQUERADING_*` | floor at Suspicious |
| 3 | Pairing at `high`/`critical` | Suspicious; **Malicious** with masquerading or chain contamination |
| 4 | LOLBAS match alone | annotate only |
| 5 | Chain contamination | escalate one level |
| 6 | Something submitted, nothing matched | Unknown |

---

## Output

- **Flags** — `_flag()`-shaped, feeding the existing flag system. All three
  process flags map to the `malware_executed` evidence key ("Compromise"), not
  `persistence_mechanism`: impersonating a binary or spawning a shell from Office
  says something ran that should not have, but says nothing about a persistence
  mechanism being installed. A prevented Device Action still caps the resulting
  Threat State at "Intrusion Attempt", which is the safety valve that makes this
  defensible.
- **Rows** — one per submitted field, plus a pair row whenever the pairing layer
  ran. The pair row is emitted **even on a clean result**: a check that ran and
  found nothing is information the analyst needs, and silence would read as "not
  checked". These live in `run_results["process_rows"]`, not `rows` — three
  consumers of that list assume one entry per atomic IOC, so merging would desync
  the session hero counts from the table.
- **AI prompt** — findings plus an explicit *"checks NOT performed"* list.

Flag ids avoid the substrings the evidence mapper reserves. The pairing flag is
`SUSPICIOUS_PARENT_CHILD_PAIR` rather than `SIGMA_PAIR_MATCH` for exactly this
reason — `SIGMA` maps straight to `malware_executed`, and the mapping should be
declared, not inherited by accident.

---

## Calibration

```bash
python core/scripts/try_process_analyzer.py --parent winword.exe --child cmd.exe
python core/scripts/try_process_analyzer.py --file-path "C:\Temp\scvhost.exe"
python core/scripts/try_process_analyzer.py --demo
```

Corpus: [`tests/fixtures/process_corpus.json`](../tests/fixtures/process_corpus.json)
— 14 known-bad pairings, 28 known-good. Gate:
[`tests/test_process_calibration.py`](../tests/test_process_calibration.py).

**Current: 14/14 as recorded. Benign escalation 2/28, both documented below.**

The corpus contract distinguishes two things a benign pair may do:

| Field | Meaning |
|---|---|
| `tolerated` | May match a rule, but must **not** escalate the verdict above Unknown. Annotating a common pair is acceptable noise. |
| `known_defect` | Escalates today and should not. Locked so it cannot spread — removing an entry is the fix. |

### Defect found and fixed — information-free globs

One rule ("Suspicious Binary In User Directory Spawned From Office Application")
constrained its child by *path*. Extraction reduced that to a basename, leaving
the child glob **`*.exe`** — which matches every executable in existence. Seven
records, all HIGH severity.

The damage went beyond noise. Being HIGH, it also *outranked* the rules that
genuinely describe Office spawning a shell, so `winword.exe → cmd.exe` was
reported under the wrong title. Fixing it corrected the label as well:
that pair now matches "Suspicious Microsoft Office Child Process".

Such globs are now filtered in `load_parent_child_pairs()` — so the shipped
dataset needs no regeneration — and refused by the extractor so a future
regeneration cannot reintroduce them.

### Defect found and NOT fixed — `java.exe` / `javaw.exe` → `cmd.exe`

Both escalate to `Suspicious` under "Webshell Detection With Command Line
Keywords". `java.exe` sits in that rule's parent list beside `w3wp.exe`,
`nginx.exe` and `php-cgi.exe` because Java web servers exist — but it is also
every desktop Java application and every Gradle or Maven build step. The rule used
a CommandLine keyword to tell a webshell from a build, and that is exactly the
condition the extraction dropped.

**Why it is not fixed:** the obvious remedy — refusing to escalate on
`commandline_constrained` rules — would also silence `w3wp.exe`, `nginx.exe` and
`php-cgi.exe`, whose escalating pairings are **100% commandline-constrained** and
are true positives. That flag is therefore not a usable proxy for
"untrustworthy". Suppressing by parent name instead would be a guess fitted to 28
samples, and `java.exe` still has 23 escalating pairings from fully faithful rules
that might simply take over.

The honest options, in preference order:

1. When the analyst *did* supply a command line and the command-line module found
   nothing in it, do not escalate a `commandline_constrained` pairing — the
   symmetric form of the rule-ID join, evidence-based rather than a name list.
   Costs nothing when no command line is supplied, which is when this fires.
2. Re-extract with the CommandLine keyword retained per pair, so the pairing can
   be scored against it.

---

## Divergence from the command-line module

The two modules deliberately treat partial Sigma extraction differently, and this
should not be "made consistent":

| | This module | [Command line](cmdline_analyzer.md) |
|---|---|---|
| Partial records match standalone | **Yes** | **No** |
| Reason | A parent→child pair is inherently specific | A CommandLine fragment often is not (`copy`, `.exe`) |
| Cost of the other choice | 8 of 12 real detections lost | 32 of 32 benign samples falsely flagged |

Both modules keep `sigma_rule_id` on every record, which is what makes the
[rule-ID join](cmdline_analyzer.md#the-rule-id-join) possible: when both match the
same rule in one session, the original multi-field condition has genuinely been
satisfied.

---

## Known limits

- **Chain contamination reaches `Malicious` very readily.** Contamination only
  fires when the parent is masquerading, which already floors at `Suspicious` — so
  *any* masquerading parent plus *any* submitted child lands on `Malicious`, from
  name-only data with no hash. Implemented as specified and tested, but the
  aggregation rule most likely to need softening against real alerts.
- **Levenshtein threshold ≤2 is a starting value.** The length-scaled guard is a
  mitigation, not a validation.
- **Chain depth is capped at 1** by the form. Deeper ancestry needs a UI change.
- **No dedicated hash field**, so Layer 3 stays opportunistic.
- **`acrobat.exe` → `cmd.exe` is not detected** — recorded in the corpus as a known
  gap rather than quietly dropped.

---

## Regenerating the datasets

Offline and committed; the app never fetches at runtime.

```bash
pip install pyyaml          # script-only — deliberately not in requirements.txt

python core/scripts/extract_sigma_pairs.py --download
python core/scripts/extract_lolbas.py
```

Add `--dry-run` to report counts without writing. After regenerating Sigma,
confirm the high-value categories survived: Office → shell, browsers → shell,
script engines → PowerShell, `mshta.exe` → any, `wmiprvse.exe` / `java.exe` →
shell, nested `powershell.exe`. A missing category means the filter is wrong.

LOLBAS needs no YAML parsing or repo clone — the project publishes its whole
corpus as one JSON document.

Sources: [SigmaHQ](https://github.com/SigmaHQ/sigma) (Detection Rule License 1.1) ·
[LOLBAS](https://github.com/LOLBAS-Project/LOLBAS) (CC BY 4.0).

---

## Related

- [Command Line Analysis](cmdline_analyzer.md) — the sibling module, and the other
  half of the rule-ID join.
- [Threat State, Level, and Verdict](threat_state_level_verdict.md) — what the
  emitted evidence keys drive.
