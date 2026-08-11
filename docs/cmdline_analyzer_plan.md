# Implementation Plan — Windows Command Line Analysis

Source briefing: *Windows Command Line Analysis Module* (2026-08-08).
Companion: [`process_analyzer_plan.md`](process_analyzer_plan.md) — the sibling
module, already shipped. This document translates the briefing into concrete
changes against the current codebase and records every decision it left open,
plus four deliberate deviations from it.

**Out of scope** (per briefing §9): WAF payload analysis, Custom Search JSON API,
cross-session correlation, and wiring `aggregated_verdict` into
[`ioc/confidence_scorer.py`](../ioc/confidence_scorer.py).

---

## 0. Current State

The **Command Line** field already exists — [`app.py:610-614`](../app.py#L610-L614),
full-width inside `_render_context_expander()`, directly under Device Action and
above File Path. It is currently pure passthrough, exactly as the four
process/filepath fields were before their module landed.

| Briefing field | Input-tab key | Result-tab twin |
|---|---|---|
| Command Line | `command_line` | `result_command_line` |
| Context | `raw_log` | `result_raw_log` |

Already wired: `_INPUT_CONTEXT_KEYS` ([`app.py:314`](../app.py#L314)),
reset handling ([`app.py:365`](../app.py#L365)), the run gate via
`_has_process_input()` ([`app.py:1074`](../app.py#L1074)), and the AI prompt
passthrough ([`ai_panel.py:281-284`](../ui/components/ai_panel.py#L281-L284)).
No detection logic of any kind exists yet.

### Answers to briefing §10

1. **Field independence — confirmed.** Command Line is a sibling of File Path /
   Parent Process / Child Process inside the same Context expander, submitted by
   the same Run, with no UI-level dependency. It can be submitted alone; the run
   gate already accepts it as the only populated field. No enforced linkage.
2. **`linked_process` cross-reference — automatic.** See D7.
3. **cmd.exe tokenizer from scratch — accepted**, and it is now the *only*
   tokenizer, so the testing budget is larger than the briefing assumed. See D1.
4. **Option A vs B — Option A, same as the process module**, and D6 recovers most
   of Option B's fidelity for free.

---

## 1. Architecture Decisions

### D1 — No PowerShell subprocess. Pure-Python tokenizer for both interpreters.

**Rejected: `System.Management.Automation.Language.Parser`** (briefing §3 Layer 1).
It is not importable from Python; using it means spawning `powershell.exe`/`pwsh`
per analysis. That costs a ~200-700 ms cold process start inside a Streamlit
rerun, makes the module Windows-only in a codebase that is otherwise pure Python
(`requirements.txt` is four lines and the process module shipped with zero new
dependencies), and puts a .NET runtime in the path of a triage tool. To be clear
this is a *portability and cost* objection, not a security one —
`Parser.ParseInput` does not execute what it parses.

`PSScriptAnalyzer` follows it out: the briefing itself notes its rules target
script quality, not security, so it would be a dependency bought purely for AST
access we are not taking.

**Decision:** one hand-written tokenizer in `core/cmdline_parser.py` covering
both interpreters, because the hard part is shared. It must implement, at
minimum:

- double-quote grouping, and the fact that `""` inside quotes is a literal quote;
- cmd.exe caret escaping (`^`), and PowerShell backtick escaping (`` ` ``);
- intra-token quoting — `"po"+"wer"shell` and `pow""ershell` are one token;
- PowerShell `--%` (stop-parsing), after which the remainder is verbatim;
- `,`/`;`/`|`/`&&`/`&` statement separators, so a chained command line yields
  multiple commands rather than one mangled token list.

Interpreter detection stays as briefing §3 describes (leading `powershell` /
`pwsh` invocation, or PowerShell-only syntax markers), defaulting to `cmd`.
The ~50-entry internal cmd.exe command table lives in JSON, not in code, per the
project's no-hardcoded-data rule.

This layer's output is also the analyst-facing "explainshell" block (briefing
§7), so it must degrade gracefully: an unparseable command line yields
`interpreter: "unknown"` and routes to `Unknown`, never to a silent empty result.

### D2 — Deobfuscation never executes the input. PowerDecode is rejected.

**Rejected: PowerDecode** (briefing §3 Layer 2). Its deobfuscation approach is
execution-based — it runs the sample layer by layer to recover each stage, which
is why its own documentation tells you to run it inside an isolated VM. Embedding
it here would mean executing attacker-supplied PowerShell on the analyst's
workstation, triggered by pasting a string into a triage form. That is a
detonation capability, and if we ever want one it belongs in an isolated sandbox
service with its own network controls, not in-process behind a Streamlit widget.
**Verify this against the current PowerDecode source before anyone revisits it** —
the objection stands on how it deobfuscates, not on the tool's intent.

**Rejected: headless CyberChef** — a Node runtime and a per-request server for a
job the iterative decoder covers. The briefing already ranks it a fallback; this
demotes it to "not without a failing test case that justifies it".

**Decision:** `core/cmdline_deobfuscator.py`, pure Python, purely
transformational. Iterative to a fixed point with hard caps
(`MAX_DECODE_ROUNDS = 5`, `MAX_DECODED_BYTES = 1_000_000`) so a decode bomb
cannot hang a rerun. Chain per round: URL-decode → HTML entity → `\uXXXX`/`\xNN`
escapes → base64 (**UTF-16LE first**, then UTF-8 — `-enc` payloads are UTF-16LE
and decoding them as UTF-8 yields NUL-interleaved garbage that then fails every
downstream match).

The string-tricks the briefing wanted PowerDecode for are all foldable without
execution, and this is where the real coverage is:

| Obfuscation | Fold |
|---|---|
| `('c'+'a'+'l'+'c')` | concatenate adjacent quoted literals |
| `` w`r`i`t`e `` | strip backticks outside quotes |
| `[char]99+[char]97` / `[char[]](99,97)-join''` | numeric → char |
| `('{1}{0}'-f'x','ie')` | apply the format operator |
| `$env:ComSpec[4,15]-join''` | **deferred** — needs variable state |

Output records every step: `{was_obfuscated, decoded_command, decode_chain:
list[str], rounds}`. `decode_chain` is what an analyst reads to trust the result;
a decoded string with no provenance is worse than no decode at all.

### D3 — Decoded content re-enters every layer, and feeds the IOC pipeline.

Not in the briefing, and it is the single highest-value integration available.

Layers 3-6 run on the **decoded** command line when decoding fired, and on the
raw one otherwise (matching the raw form of an encoded blob finds nothing —
briefing §3 Layer 2 says as much, but never states that the decoded text should
also be mined for indicators).

The process module already set the pattern: `extract_hash_candidates()` returns
candidates, `app.py` merges them into `items`, and the normal VT/MalwareBazaar
path enriches them ([`process_analyzer.py:432`](../core/process_analyzer.py#L432),
[`app.py:1092-1094`](../app.py#L1092-L1094)). Do the same here — a decoded
download cradle nearly always carries the C2 URL or IP, so pasting one encoded
one-liner should produce a fully enriched URL row with no second analyst action.

Same constraint as the sibling module: **this module performs no network I/O.**
It returns `ioc_candidates`; `app.py` feeds them in.

One caveat, carried to §5: URL candidates recovered this way must **not** be
auto-submitted to URLScan's public queue. Submitting an attacker's URL publicly
is an outbound disclosure the analyst did not ask for.

### D4 — Layer 3 keyword table is data, not code.

`core/data/suspicious_cmdline_keywords.json`, loaded with `lru_cache`, degrading
to "no matches" on a malformed file exactly like `load_parent_child_pairs()`.
Records are `{id, patterns, match_mode, label, mitre, severity, why}` where
`match_mode` is `token` (matches a parsed flag/argument) or `substring`.

`token` mode matters: `-w hidden` as a substring false-positives on any command
containing that text in a path or a URL, while a token match against Layer 1's
parsed flag list does not. The briefing's seven-row table is the seed; expect
~40 entries at first pass.

### D5 — Sigma CommandLine extraction: Option A, with provenance.

`core/scripts/extract_sigma_cmdline_patterns.py`, a sibling of the existing
`extract_sigma_pairs.py` (same tarball fetch, same exclusion-prefix handling,
same PyYAML-is-script-only rule — it stays out of `requirements.txt`), emitting
`core/data/sigma_cmdline_patterns.json`.

Option A = keep `CommandLine` conditions, drop `Image`/`ParentImage`. Every
record carries `image_constrained` / `parentimage_constrained` /
`sigma_rule_id` / `sigma_level`, mirroring the pairs table's
`commandline_constrained` / `path_constrained`. This is the exact mirror image of
the existing extraction, which is what makes D6 work.

Keep it a **separate dataset**, as the briefing insists. Also extract from
`rules/windows/powershell/` — those rules match on `ScriptBlockText`, whose
content is command-line-shaped and directly applicable here even though the
logsource differs. Tag the record with its `logsource` so the difference stays
visible.

### D6 — Rule-ID join: Option B for the overlapping case, at no extra cost.

The two Option-A extractions are complementary halves of the same rules. A rule
requiring `ParentImage: winword.exe` **and** `CommandLine: *-enc*` produces a
pairs record (flagged `commandline_constrained: true`) *and* a cmdline record
(flagged `parentimage_constrained: true`) — both carrying the same
`sigma_rule_id`.

**Decision:** when this module and the process module both match on the same
`sigma_rule_id` in one session, the original multi-field condition has in fact
been satisfied. Mark the match `faithful_multifield: true`, treat it as the
strongest signal in the stack, and say so in the flag detail.

This is worth building deliberately: 1155 of the 1874 shipped pairs are
`commandline_constrained` — i.e. 62% of the pairs table is currently applied more
broadly than its source rule intended, and this join is what narrows them back
down whenever the analyst supplies the command line. It closes briefing §9's
deferred "full multi-field matching" for the common case without implementing a
rule engine, and it answers §10.4 for both modules at once.

### D7 — Cross-reference takes the process **result**, not the process **input**.

Briefing §2 types `linked_process` as `ProcessFilepathInput`. That cannot work:
§5.1 escalates on `MASQUERADING_*` and `SUSPICIOUS_PARENT_CHILD_PAIR`, which are
*findings*, and recovering them from the raw input means re-running the sibling
module's Layer 1 and Layer 4 here.

**Decision:** `linked_process: ProcessAnalysisResult | None`. `app.py` already
computes it immediately before this call site. The cross-reference is
**automatic** whenever both are present (§10.2) — the two fields sit in one form,
submitted by one Run, describing one event; the process module already treats its
own three fields that way, and a "link these" toggle would be asking the analyst
to confirm something the form's own structure already asserts.

The dependency is one-directional: process → cmdline. This module must produce a
complete verdict with `linked_process=None`, and D6's join degrades to a normal
Option-A match.

### D8 — Flag naming must dodge the evidence mapper's substring matching.

`flags_summary_for_evidence()` maps flag IDs to evidence keys by **substring**
([`ioc/flags/__init__.py:127-161`](../ioc/flags/__init__.py#L127-L161)). Reserved
tokens to avoid: `SIGMA`, `MALWARE`, `EXPLOIT`, `CVE`, `C2`, `RECON`, `SCANNING`,
`PERSISTENCE`, `PRIVESC`, `PROCESS_INJECTION`, `LATERAL`, `SMB`, `RDP`,
`PHISHING`, `RANSOMWARE`.

Proposed IDs, all prefixed `CMDLINE_`, none colliding:

| Flag ID | Severity | Evidence key |
|---|---|---|
| `CMDLINE_ENCODED_PAYLOAD` | MEDIUM | *(none — annotate + MITRE only)* |
| `CMDLINE_DECODED_SUSPICIOUS` | HIGH | `malware_executed` |
| `CMDLINE_SUSPICIOUS_SWITCH` | LOW–MEDIUM | *(none alone; see §5.4)* |
| `CMDLINE_FILELESS_DOWNLOAD` | HIGH | `malware_executed` |
| `CMDLINE_DETECTION_RULE_MATCH` | per `sigma_level` | `malware_executed` |
| `CMDLINE_LOLBAS_ABUSE_PATTERN` | HIGH | `malware_executed` |
| `DUAL_USE_BINARY` (reused) | INFO | *(none)* |
| `CMDLINE_HIGH_ENTROPY_TOKEN` | INFO | *(none, ever)* |

`CMDLINE_DETECTION_RULE_MATCH` deliberately omits `SIGMA` so the mapping is
explicit rather than accidental — the same call the process module made with
`SUSPICIOUS_PARENT_CHILD_PAIR`.

Note what is *not* mapped: a download cradle is **not** `c2_connection`. Seeing
`DownloadString('http://…')` in a command line proves an attempt, not a
connection. If that URL is real, D3 hands it to the providers and *they* supply
the C2 evidence on their own authority.

### D9 — LOLBAS needs a second dataset; the shipped one stays untouched.

`extract_lolbas.py` deliberately drops command strings
([`extract_lolbas.py:89-92`](../core/scripts/extract_lolbas.py#L89-L92)) —
precisely because argument-level confirmation was this module's job. Layer 4 now
needs them.

**Decision:** extend the same script with a second output file,
`core/data/lolbas_commands.json` (`binary → [{command, category, description}]`),
and add `lolbas_lookup.lookup_commands(name)`. `lolbas_binaries.json` and
`lookup()` are not modified, so the shipped process module carries zero
regression risk from this change.

Matching is the hard part and must not be naive substring: LOLBAS examples are
literal invocations full of sample paths, URLs and GUIDs. Reduce each example to
a **switch skeleton** (drop quoted literals, paths, URLs, GUIDs; keep switches
and structural keywords), then require ≥2 distinctive skeleton tokens present in
the input's parsed flags before claiming `CONFIRMED_ABUSE_PATTERN`. Below that
threshold it stays `DUAL_USE_PRESENT`, which per briefing §5.5 annotates and
never escalates. This is the least certain component in the plan — see §6.

### D10 — `Benign` is never returned. Deviation from briefing §5.7.

Briefing §5.7 routes a mundane command line to `Benign`. The sibling module never
returns `Benign` (plan §3, aggregation rule 6) and `ioc/verdict.py:169` hardcodes
`summary["benign"] = 0`. "Nothing matched our local datasets" is absence of
evidence; the project's existing stance calls that `Unknown`.

**Decision:** floor is `Unknown`. Two verdicts collapse into it — parse failure
(§5.8) and clean parse with no matches (§5.7) — so the result object carries
`parse_ok: bool` to keep them distinguishable in the UI and in the AI narrative.

---

## 2. File Layout

```
core/
  cmdline_analyzer.py                    # Layers 3, 6 + aggregation + flags + rows
  cmdline_parser.py                      # Layer 1 (D1) — tokenizer + interpreter detection
  cmdline_deobfuscator.py                # Layer 2 (D2) — pure transforms, no execution
  lolbas_lookup.py                       # extended with lookup_commands() (D9)
  data/
    cmd_internal_commands.json           # Layer 1 command table
    suspicious_cmdline_keywords.json     # Layer 3 (D4)
    sigma_cmdline_patterns.json          # Layer 5 (D5)
    lolbas_commands.json                 # Layer 4 (D9)
  scripts/
    extract_sigma_cmdline_patterns.py    # offline, sibling of extract_sigma_pairs.py
    extract_lolbas.py                    # extended to emit lolbas_commands.json
tests/
  test_cmdline_parser.py
  test_cmdline_deobfuscator.py
  test_cmdline_analyzer.py
  test_cmdline_integration.py
```

The briefing put Layers 1/3/6 in one file. Layer 1 is split out because the
tokenizer is the piece most likely to grow and the one with the densest test
suite; keeping it importable on its own also lets the UI render the structural
breakdown without pulling in the datasets.

**No new runtime dependency.** PyYAML stays script-only, as it already is.

---

## 3. Data Model

```python
@dataclass
class CommandLineInput:
    command_line: str | None = None
    context: str | None = None                      # raw_log, unparsed passthrough
    linked_process: ProcessAnalysisResult | None = None   # D7

@dataclass
class ParsedCommand:
    interpreter: str                  # "powershell" | "cmd" | "unknown"
    base_command: str
    flags: list[str]
    arguments: list[str]
    raw: str

@dataclass
class CommandLineAnalysisResult:
    parse_ok: bool                          # D10
    interpreter_detected: str
    commands: list[ParsedCommand]           # >1 when chained with ; | && &
    was_obfuscated: bool
    decoded_command: str | None
    decode_chain: list[str]
    keyword_flags: list[dict]
    lolbas_cross_check: dict | None
    rule_matches: list[dict]                # each may carry faithful_multifield (D6)
    entropy_flag: bool
    ioc_candidates: list[str]               # D3 — caller enriches, module never does
    context_passthrough: str | None
    aggregated_verdict: str
    flags: list[dict]                       # _flag()-shaped, feeds the existing system
```

`commands` is a list because `powershell -enc … ; certutil -urlcache …` is a
single pasted line containing two commands, and collapsing it to one loses the
second. The briefing's flat `structural_breakdown` dict cannot express that.

---

## 4. Verdict Aggregation

Briefing §5 order of precedence, with D10's floor:

1. Rule match at `sigma_level` high/critical → `Suspicious`; → `Malicious` with
   obfuscation (Layer 2 fired) **or** a confirmed LOLBAS abuse pattern.
2. `faithful_multifield` rule match (D6) at high/critical → `Malicious` directly.
   The full original condition was met; nothing was approximated.
3. `CONFIRMED_ABUSE_PATTERN` → `Suspicious` minimum, independent of Sigma.
4. Obfuscation **and** decoded content matches Layer 3 or 5 → `Malicious`.
   Obfuscation alone with benign decoded content → `Suspicious`.
5. Keyword matches alone → `Suspicious`. Compounding, per briefing §5.4: ≥3
   independent keyword hits on one command raise severity, they do not merely
   accumulate as list entries.
6. `DUAL_USE_PRESENT` alone → annotate, no escalation.
7. Entropy alone → `Suspicious` ceiling, manual-review framing only.
8. Nothing matched, or parse failed → `Unknown` (D10), `parse_ok` distinguishes.

**Cross-reference (§5.1):** if `linked_process` carries `MASQUERADING_*`,
`PARENT_CHAIN_CONTAMINATION` or `SUSPICIOUS_PARENT_CHILD_PAIR` and this module
found anything beyond nothing, escalate one level via the sibling module's
`_escalate()`.

⚠ **This inherits the sibling module's known over-escalation problem** (its plan
§7, first bullet). There, any masquerading parent plus any child already reaches
`Malicious` from name-only data. Adding a second automatic one-level escalation
on top compounds it. Mitigation: the cross-reference escalation is capped so it
cannot *by itself* produce `Malicious` — it may raise `Unknown → Suspicious`, but
`Suspicious → Malicious` requires this module's own findings to justify it.
That is a deliberate softening of briefing §5.1, and the rule most likely to need
retuning against real alerts.

---

## 5. Integration Points

**`app.py`** — after the existing `analyze_process_event(...)` call
([`app.py:1086`](../app.py#L1086)), so the result can be passed in:

```python
_cmd_result = analyze_command_line(CommandLineInput(
    command_line=command_line or None,
    context=raw_log or None,
    linked_process=_proc_result,
))
```

Merge `_cmd_result.ioc_candidates` into `items` the same way `hash_candidates`
already are, deduped against `_known_values`. **URL candidates must be excluded
from any automatic URLScan submission** (D3) — respect `allow_urlscan_submit`,
and default derived URLs to lookup-only.

**Rows** — reuse `run_results["process_rows"]`, identical column schema, with a
test asserting key-for-key parity, exactly as the process module does. Do not
merge into `run_results["rows"]`; three consumers assume one entry per atomic
IOC.

**AI narrative** — `flags_to_ai_context(cmdline_flags)` plus the decoded command
and `decode_chain` verbatim. The existing "Checks skipped" convention applies:
state when no command line was supplied, so the model does not imply certainty.

**UI** — the structural breakdown gets its own block above the flags (briefing
§7): interpreter, base command, flags, arguments, then decoded form with its
chain. This is the explainshell payoff and is what analysts will read first.

**Input widget** — worth revisiting: `st.text_input` is single-line, and a
base64 `-enc` blob is routinely 500+ characters, which scroll-clips badly.
`st.text_area(height=68)` reads far better for that content. Cosmetic, one line,
not done without a call from you.

---

## 6. Build Order

Three milestones, each independently mergeable and independently useful. This is
a deliberate departure from how the sibling module was built: there, all nine
steps landed before anything met a real alert, and its plan §7 now carries four
calibration unknowns discovered after the fact. Here, milestone A reaches the UI
before either dataset layer is written, so the thresholds in B and C get tuned
against observed behaviour instead of guessed up front.

### Milestone A — decode and explain (no new datasets, no extraction scripts)

| # | Step | Depends on |
|---|---|---|
| A1 | `cmd_internal_commands.json` + `cmdline_parser.py` + tests | — |
| A2 | `cmdline_deobfuscator.py` (decode chain + string folds) + tests | — |
| A3 | `suspicious_cmdline_keywords.json` + Layer 3 + Layer 6 entropy | A1 |
| A4 | Aggregation (rules 4-8 only) + flag emission + rows | A2, A3 |
| A5 | `ioc/flags/__init__.py` evidence mappings (D8) | A4 |
| A6 | `app.py` wiring, IOC candidate merge (D3), UI breakdown block, AI prompt | A4 |

This is the analyst-facing payoff: paste an encoded one-liner, get the decoded
form with its `decode_chain`, the structural breakdown, the suspicious switches,
and — via D3 — every URL/IP/hash inside the decoded payload enriched by the
existing provider pipeline. No Sigma or LOLBAS work is required to reach it.

**Status: Milestone A complete (A1-A6)** — 158 tests across
`test_cmdline_parser.py` (54), `test_cmdline_deobfuscator.py` (33),
`test_cmdline_analyzer.py` (53) and `test_cmdline_integration.py` (18). Verified
end-to-end by driving the real app under `streamlit.testing.v1.AppTest`.
Decisions taken during implementation:

- **Layer 6's premise from the briefing does not survive measurement.** Entropy
  alone inverts the answer on real command lines: an ordinary Windows path
  scores 4.27 bits/char and a long URL 4.46, while a genuine UTF-16LE `-enc`
  payload scores only **3.70** — every NUL byte encodes to a repeated `A`. A
  pure threshold flags benign paths and misses payloads. Layer 6 now gates on
  token *shape* first (no path separator, no URL scheme, restricted alphabet,
  mixed case with digits — which also excludes GUIDs and CamelCase names) and
  applies entropy only afterwards, at a threshold of 3.2.
- **`ConfidenceScore` in synthetic rows is `None`, not `""`** — in this module
  *and* in `core/process_analyzer.py`. Real IOC rows carry a number there; an
  empty string beside it produces an object column pyarrow refuses, which broke
  `st.dataframe` for the entire run. Pre-existing, but the headline case here
  (a decoded cradle yields a real URL row next to the command row) makes hitting
  it the normal outcome rather than an edge case. Regression-tested.
- **URLs recovered from a decoded payload are withheld from URLScan.**
  `allow_urlscan_submit` is one flag for the whole provider call, not per-IOC,
  so derived URLs are filtered out of that provider's payload entirely. Every
  other provider still enriches them. Submitting an attacker's URL to a public
  queue is an outbound disclosure the analyst never asked for.
- **Evidence mappings key on exact flag ids**, not substrings, unlike the
  generic rules above them in `flags_summary_for_evidence`. Defense-evasion
  switches (encoding, hidden window, skipped profile, entropy) map to **no**
  evidence key — there is no key for defense evasion and forcing one would
  overstate what a switch proves. Active tampering with host defenses (AMSI,
  ETW, Defender, event-log clearing) *is* mapped to `malware_executed`, on the
  same reasoning the process module used.
- **A download cradle is not `c2_connection`.** Seeing `DownloadString('http://…')`
  proves an attempt, not a connection. If the URL is real, D3 hands it to the
  providers and they supply that evidence on their own authority.

A1/A2 decisions:

- **Interpreter detection runs on a de-noised copy** of the line (backticks,
  quotes and carets stripped). Detection has to precede tokenizing, since the
  interpreter decides which escape character applies — so an invocation written
  as ``p`o`w`e`r`s`h`e`l`l`` would otherwise be tokenized under cmd.exe rules and
  never recognised. Cmdlet detection uses an approved-verb list rather than a
  bare hyphen, keeping filenames like `sql-backup.exe` out of the PowerShell path.
- **Backticks are folded only between two word characters.** A trailing backtick
  is PowerShell's line continuation — ordinary formatting, not evasion — and
  folding it would raise a false `was_obfuscated` on benign multi-line scripts.
- **Percent-encoding and HTML entities require ≥2 occurrences** before they are
  believed, and only *numeric* HTML entities are decoded. Otherwise
  `%SystemRoot%\notepad.exe` gets corrupted and `html.unescape` turns the
  `&copy` in `dir&copy a b` into a copyright sign.
- **Base64 detection is two-tier.** An argument to an `-enc`-family flag is a
  payload by declaration and needs only to decode to printable text; a long
  base64-looking run anywhere else must additionally look like a *command*
  (≥2 of space `.` `\` `/` `:` `(` `-`). Without the second bar, a 32-character
  MD5 in the command line decodes to convincing-looking noise.
- **The stop-parsing remainder bypasses flag classification.** A `--%` remainder
  such as `/c "a b" & whoami` opens with something switch-shaped but is one
  opaque value by definition.

**Milestone A cannot return `Malicious` by construction.** §4 rules 1-3 all
require Layer 4/5 data that does not exist yet, and rule 4's escalation needs a
Layer 5 match; keyword-only evidence tops out at `Suspicious` (rule 5). That
property is what makes A safe to ship early — the worst it can do is over-flag
toward manual review, never over-call a verdict.

### Milestone B — Sigma CommandLine matching and the rule-ID join

**Status: complete.** 1521 rules inspected → 1409 deduped patterns. 15 tests in
`test_cmdline_sigma_layer5.py`. Calibration after B: **30/30 detection, 0% FP.**

> **D5 was wrong, and the corpus proved it.** The plan assumed Option A works for
> `CommandLine` because it worked for parent/child pairs. It does not — the two
> fields are not symmetric. A pair is inherently specific (`winword.exe` →
> `cmd.exe`); a CommandLine fragment often carries *no* specificity once the
> `Image` condition beside it is removed. The shipped dataset contains rules
> whose entire surviving CommandLine condition is `.exe`, `.cmd` or `copy`.
>
> Matching those standalone flagged **32 of 32 benign samples — a 100% false
> positive rate.** Code review had not caught it; only the known-good corpus did.
>
> Two rounds of narrowing followed. Excluding `Image`-constrained records was not
> enough: even "faithful" records fired, because the extractor was splitting a
> rule's ANDed sibling blocks into separate any-of records, so a folder condition
> and an extension condition became two independent matchers. The extractor now
> computes `complete_condition` — one active detection block, one pattern group,
> no dropped values, no image constraint — and **only 153 of 1409 records (11%)
> qualify.**
>
> **A record that does not reproduce its rule's whole condition never matches on
> its own.** Those 1256 fragments are consulted solely through the D6 rule-id
> join, where the process module supplies the missing half. That turns D6 from a
> bonus into the only route by which 89% of the dataset can ever contribute —
> a stronger justification for it than the one this plan originally gave.

Measured overlap for the join: **47 distinct rules, covering 891 pair records**,
have halves in both datasets. Verified end-to-end — `apache-tomcat-9.exe →
adfind.exe` plus a command line containing `-nop` reconstructs SigmaHQ rule
`4ebc877f` exactly, and only then reaches `Malicious`. The same command line
without the process half matches nothing at all, which is the correct answer.

Other decisions taken during B:

- **Regex conditions (`|re`) are never translated.** Matching attacker-influenced
  regex at runtime risks catastrophic backtracking, and hand-translating would
  misreport what the rule said. They count as dropped values, which disqualifies
  their record from standalone matching.
- **Corroboration requires a `medium`+ rule match.** A noisy low-level rule is
  not a second source worth promoting a verdict on.
- **`MALICIOUS_REQUIRES_CORROBORATION` still stands.** Milestone B did not remove
  the ceiling, it supplied the second source that satisfies it. Keyword hits and
  obfuscation, however many, remain one source between them, and a test asserts
  every `Malicious` verdict in the corpus rests on Sigma or LOLBAS.

### Milestone B — original plan

| # | Step | Depends on |
|---|---|---|
| B1 | `extract_sigma_cmdline_patterns.py` → dataset; sanity-check the corpus | — |
| B2 | Layer 5 matching + §4 rules 1 and 4 | A4, B1 |
| B3 | D6 rule-ID join + `faithful_multifield` + §4 rule 2 | B2 |
| B4 | D7 cross-reference with `linked_process`, capped per §4 | B2 |

B3 is the reason B is worth doing and should not be deferred past B2 — without
the join, this milestone only adds a second Option-A dataset with the same
unmeasured breadth as the first. With it, 62% of the shipped pairs table gets
narrowed back to its source rules whenever a command line is present.

**Sanity-check after B1**, mirroring the sibling plan: confirm the extraction
actually pulled the high-value patterns — `-enc`/`-EncodedCommand`, `IEX` +
`DownloadString`, `certutil -urlcache`, `bitsadmin /transfer`, `rundll32` +
`javascript:`, `wmic process call create`, `vssadmin delete shadows`. A missing
category means the detection-block filter is wrong.

### Milestone C — LOLBAS argument confirmation

**Status: complete.** 105 binaries carry 165 abuse-command skeletons; 20 tests in
`test_cmdline_lolbas_layer4.py`. Calibration unchanged at 30/30, 0% FP.

**The skeleton is derived, not guessed.** This was the plan's least certain
component, and LOLBAS turned out to make it tractable: every variable part of a
documented command is already marked with an explicit placeholder —
`certutil.exe -urlcache -f {REMOTEURL:.exe} {PATH:.exe}`. Removing the
placeholders leaves exactly the tokens an operator cannot change while still
performing the abuse. The planned "≥2 distinctive tokens" heuristic was dropped
in favour of **every** skeleton token having to match, which is precise rather
than merely strict.

The same information-free-pattern rule this project reached twice in Milestone B
applies again, and cost more than half the raw data: the binary's own name,
bare numbers and job ids, two-character switches (`-f` is generic to every tool),
and punctuation fragments left by inline script payloads (`)"))`, `,entrypoint`)
are all dropped, and a command whose skeleton reduces to nothing is not shipped.
That took 272 raw skeletons down to 165. `mshta.exe` drops out entirely — its
abuse is `mshta <url>`, where the URL is the variable part, so the binary alone
is the signal and Layer 2 already reports it.

**C3 decision — promoted, but only halfway.** Measured over the corpus:

| | result |
|---|---|
| known-bad confirmed | 4 / 30 |
| known-good falsely confirmed | **0 / 32** |
| verdicts changed by promoting | none |

Perfect precision, low recall — the right shape for a confirmation layer. So
`LOLBAS_SETS_SUSPICIOUS_FLOOR = True`: a confirmed pattern can lift a verdict off
`Unknown`, which is the layer's entire purpose, since it reaches the ~105
binaries the 33-entry keyword table never names.

`LOLBAS_COUNTS_AS_CORROBORATION` stays **False**. Corroboration unlocks
`Malicious`, and 32 benign samples is a thin basis for that authority. The two
constants are separate precisely so the stronger one can be granted later on its
own evidence rather than riding along with the weaker.

### Milestone C — original plan

| # | Step | Depends on |
|---|---|---|
| C1 | `extract_lolbas.py` extension → `lolbas_commands.json` + `lookup_commands()` | — |
| C2 | Skeleton matching, **annotate-only** — no verdict effect | A1, C1 |
| C3 | Promote to `CONFIRMED_ABUSE_PATTERN` (§4 rule 3) once C2 is calibrated | C2 |

C is last because D9 is the least certain component in this plan, and C2/C3 are
split so its uncertainty never blocks a merge: the flag ships visible-but-inert,
and only earns verdict authority after §7's threshold is measured.

Everything except A5, A6 and B4 is a pure function with no Streamlit dependency.

### Calibration corpus — built; results below

**Landed** as `tests/fixtures/cmdline_corpus.json` (30 known-bad, 32 known-good),
`core/scripts/try_cmdline_analyzer.py --calibrate`, and
`tests/test_cmdline_calibration.py`, which locks the result as a regression gate.

First run: **30/30 detection, 2 false positives (6%)**. Both were real defects in
the shipped Milestone A code, and neither was visible to code review:

| Benign sample | Fired | Cause |
|---|---|---|
| `schtasks.exe /query /fo LIST /v` | `SCHTASKS_CREATE` | The pattern was the bare binary name, so a read-only query was labelled "Scheduled task created" — a plainly false statement. |
| `java.exe -Dfile.encoding=UTF-8 -jar …` | `HIGH_ENTROPY_TOKEN` | A Java system property cleared every shape test: mixed case, digits, restricted alphabet. |

Fixes: a keyword pattern may now be a **list** of substrings that must all
appear, so a technique requires its verb and not just its binary
(`["schtasks", "/create"]`); and the Layer 6 shape gate now rejects tokens that
start with `-`/`/`, contain `.`, or use `=` outside trailing padding. The same
bare-binary flaw was latent in `bitsadmin`, `net user`, `mshta`, `-computername`
and `lsass`, all corrected in the same pass.

Second run: **30/30 detection, 0 false positives.** That is the number the gate
now holds.

The known-good half is what earned this. Three of its entries are deliberately
"benign but noisy" with declared `tolerated_flags` — the SCCM
`-NoProfile -ExecutionPolicy Bypass` wrapper, an administrator's
`schtasks /create`, and an Intune detection script running hidden. Those are
reviewed exceptions rather than excuses: anything firing outside its tolerated
list fails the build.

### Corpus design notes

Every threshold in this plan and both open-item lists is currently a guess. Add
`core/scripts/try_cmdline_analyzer.py` (sibling of the existing
`try_process_analyzer.py`) plus a fixture corpus split two ways:

- **known-bad** — encoded droppers, LOLBin cradles, the §6 B1 sanity-check list;
- **known-good** — real benign automation: scheduled-task invocations, installer
  command lines, CI agents, SCCM/Intune wrappers, backup jobs.

The known-good half is the one that actually matters and the one a detection
project always forgets. Without it every threshold gets tuned for recall alone
and the false-positive rate stays invisible until analysts start ignoring the
module. This corpus is also the only way §7's LOLBAS and entropy items get
closed rather than carried forward indefinitely.

---

## 7. Open Items Carried Forward

- **LOLBAS skeleton matching (D9) is the least certain component.** The
  ≥2-token threshold is a guess. It needs measuring against real LOLBAS examples
  before `CONFIRMED_ABUSE_PATTERN` is allowed to floor a verdict at `Suspicious`;
  until then, consider shipping it annotate-only and promoting it after
  calibration.
- **Entropy (Layer 6) will fire on legitimate automation.** Long base64 in a
  scheduled-task command line is normal. Keeping it INFO-severity and
  never-escalating (D8) is the mitigation, but the threshold still needs data.
  The shape gate added in Milestone A removes the worst false positives (paths,
  URLs, GUIDs, CamelCase names); what remains unmeasured is how often a
  legitimate opaque token — a license key, a session id, a signed blob — clears
  both gates.
- **A CRITICAL keyword alone still returns `Suspicious`.** `vssadmin delete
  shadows` is about as unambiguous as a command line gets, but Milestone A holds
  it at `Suspicious` because the keyword table is a single uncalibrated source
  and the project requires two before a final verdict. Milestone B's Sigma rules
  will corroborate exactly these cases; if that proves too conservative in
  practice, the fix is a documented CRITICAL-severity exception in
  `aggregate_verdict`, not lowering the general bar.
- **Compounded cross-reference escalation** — §4's cap is a judgement call layered
  on a sibling rule already flagged as too eager. Revisit both together.
- **`--%` and variable-expansion obfuscation are unhandled** (D2's deferred row).
  `$env:ComSpec[4,15]-join''` needs a variable store, which is the first step
  toward an interpreter — deliberately not taken.
- **Sigma `ScriptBlockText` rules are logsource-mismatched.** Applying them to a
  process command line is defensible but broader than the rule intends; the
  `logsource` tag exists so this can be measured and, if noisy, filtered.
