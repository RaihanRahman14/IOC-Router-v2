# Command Line Analysis

Answers four questions about a pasted Windows command line:

1. **What does it do?** — broken into interpreter, base command, flags and arguments.
2. **Is it hiding something?** — and if so, what does it decode to?
3. **Does it match known-malicious patterns?** — Sigma rules, LOLBAS abuse patterns, a curated switch table.
4. **Does it look wrong even without matching anything?** — entropy fallback.

Implemented in [`core/cmdline_analyzer.py`](../core/cmdline_analyzer.py),
[`core/cmdline_parser.py`](../core/cmdline_parser.py) and
[`core/cmdline_deobfuscator.py`](../core/cmdline_deobfuscator.py). Surfaced in the
Result tab's **Command line breakdown** block, the Threat Indicators list, the
ticket table and the AI narrative.

**No network I/O.** Every layer is a pure function of its input plus the datasets
in [`core/data/`](../core/data). The module costs no API budget and works with
every provider key absent. Indicators it recovers are *returned* for the caller
to enrich — it never resolves them itself.

---

## Input

The **Command Line** field in the Context panel, alongside File Path, Parent
Process, Child Process and free-text Context. Every field is independent and
optional; a run can proceed on a command line alone with the IOC box empty.

```python
CommandLineInput(
    command_line = "...",   # required for this module to do anything
    context      = "...",   # free-text Context, forwarded to the AI unparsed
    linked_process = ProcessAnalysisResult | None,
)
```

`linked_process` is the [process module's](process_analyzer.md) **result**, not
its input — the cross-reference keys on *findings* (`MASQUERADING_*`,
`SUSPICIOUS_PARENT_CHILD_PAIR`), which the raw input cannot supply without
re-running that module's layers here.

---

## How It Works (Pipeline)

```
raw command line
     ↓
[Layer 2] deobfuscate         → decoded text + transform chain
     ↓                          (matching a still-encoded string finds nothing,
     ↓                           so this runs before everything else)
[Layer 1] tokenize            → interpreter, base command, flags, arguments
     ↓
[Layer 3] keyword table       ─┐
[Layer 4] LOLBAS arguments    ─┼→ flags
[Layer 5] Sigma CommandLine   ─┤
[Layer 6] entropy fallback    ─┘
     ↓
extract indicators from the decoded text → returned to app.py for enrichment
     ↓
aggregate → Malicious / Suspicious / Unknown
```

---

## Layer 1 — Structural parsing

A hand-written tokenizer covering both cmd.exe and PowerShell. It implements the
quoting rules that actually bite:

| Rule | Example |
|---|---|
| Quote grouping, quotes stripped | `copy "C:\Program Files\a.txt" b.txt` |
| Doubled quote is a literal (MSVCRT argv rule) | `echo "a""b"` → `a"b` |
| Intra-token quoting joins | `pow""ershell` → one token, `powershell` |
| cmd.exe caret escape | `ech^o te^st` → `echo test` |
| PowerShell backtick escape | `` i`e`x `` → `iex` |
| Single quotes are PowerShell-only | `echo it's fine` is three tokens in cmd |
| `--%` stop-parsing | remainder becomes one opaque argument |
| Statement separators | `;` `\|` `&&` `\|\|` for PowerShell; `&` `&&` `\|` `\|\|` for cmd |

Bare `&` is **not** a separator in PowerShell — there it is the call operator, and
splitting on it would sever the operator from what it invokes.

Interpreter detection runs on a *de-noised* copy of the line (backticks, quotes
and carets stripped), because it has to precede tokenizing — the interpreter is
what decides which escape character applies. Without that, `` p`o`w`e`r`s`h`e`l`l ``
would be tokenized under cmd.exe rules and never recognised. Cmdlet detection
uses an approved-verb list rather than a bare hyphen, so `sql-backup.exe` stays
out of the PowerShell branch.

A line that cannot be parsed returns `parse_ok = False` with whatever tokens were
recoverable. It never raises, and it never silently reports a clean result.

**Not done here:** no deobfuscation (`('c'+'a'+'l'+'c')` stays one token — Layer 2
owns that), no recursion into a `-Command` payload, and nothing is ever executed.

`cmd_internal_commands.json` lists the 45 cmd.exe builtins, which answers whether
a base command is a shell builtin or something that exists on disk — and
therefore whether a filepath or LOLBAS lookup is meaningful at all.

---

## Layer 2 — Deobfuscation

**Pure string rewriting. Nothing is ever executed** — no `eval`, no subprocess,
no interpreter. This is a deliberate constraint, not an implementation detail:
the alternative approach used by some deobfuscation tools is to *run* the sample
stage by stage, which is why those tools require an isolated VM. Doing that here
would execute attacker-supplied PowerShell on the analyst's workstation the
moment they paste into a triage form.

| Transform | Example |
|---|---|
| base64 — `-EncodedCommand` family, and long inline runs | `-enc SQBFAFgA…` |
| Quoted-string concatenation | `('c'+'a'+'l'+'c')` → `calc` |
| `[char]` codes and `[char[]](…) -join ''` | `[char]99+[char]97` → `ca` |
| Format operator | `('{1}{0}' -f 'x','ie')` → `iex` |
| Intra-word backticks | `` i`e`x `` → `iex` |
| Percent-encoding, numeric HTML entities, `\uXXXX` / `\xNN` | `%63%61%6c%63` → `calc` |

The last row lives in [`core/decode_common.py`](../core/decode_common.py), shared
with other analysis modules; everything above it is PowerShell-specific and stays
in this module.

Decoding iterates to a fixed point under hard caps (`MAX_DECODE_ROUNDS = 5`,
`MAX_DECODED_BYTES = 1_000_000`) so a layered or self-expanding payload cannot
hang a rerun. Every applied step is recorded in `decode_chain` — **a decoded
string an analyst cannot trace back to its source is worse than no decode at
all**, so the UI always shows the chain beside the result.

Details that matter in practice:

- **base64 is decoded UTF-16LE first.** PowerShell encodes `-EncodedCommand`
  payloads that way; decoding as UTF-8 yields NUL-interleaved text that then
  fails every downstream keyword and rule match.
- **Two confidence tiers.** An argument to an `-enc`-family flag is a payload by
  declaration and need only decode to printable text. A long base64-looking run
  anywhere else must additionally look like a *command* — otherwise a 32-character
  MD5 in the command line decodes to convincing-looking noise.
- **Backticks are folded only between two word characters.** A trailing backtick
  is PowerShell's line continuation — ordinary formatting, not evasion.
- **Percent-encoding and HTML entities require ≥2 occurrences**, and only numeric
  HTML entities are decoded. Otherwise `%SystemRoot%\notepad.exe` gets corrupted
  and `&copy` in `dir&copy a b` becomes a copyright sign.

**Not covered:** anything needing variable state, such as
`$env:ComSpec[4,15]-join''`. Resolving that means modelling a variable store,
which is the first step toward writing an interpreter.

### Decoded content re-enters everything

Layers 3–6 run on the **decoded** text when decoding fired. The module also
extracts URLs, IPv4 addresses and hashes from it and returns them as
`ioc_candidates`; `app.py` feeds them into the normal enrichment pipeline. Pasting
one encoded one-liner therefore produces a fully enriched URL row with no second
analyst action.

Two deliberate restrictions:

- **Bare domains are not extracted.** `Net.WebClient`, `System.IO` and
  `kernel32.dll` all satisfy a generic domain pattern — and `System.IO` even ends
  in a real TLD — so a domain sweep would push .NET type names at the providers.
- **URLs recovered this way are withheld from URLScan.** Submitting an attacker's
  URL to a public queue is an outbound disclosure the analyst did not ask for and
  cannot take back. Every other provider still enriches them.

`revealed_keywords` records which findings appeared *only after* decoding — the
evidence that the encoding was concealing something rather than merely wrapping it.

---

## Layer 3 — Suspicious switch table

`suspicious_cmdline_keywords.json` — 34 curated entries, deliberately narrower
and more direct than Sigma. Each carries an id, patterns, match mode, severity,
MITRE ids and a plain-language `why` that is shown to the analyst.

| Match mode | Meaning |
|---|---|
| `flag` | exact match against a parsed switch token |
| `flag_value` | two **adjacent** tokens, e.g. `-w hidden` |
| `token` | exact match against any parsed token |
| `substring` | appears anywhere in the command text; a pattern may be a **list**, in which case all of its parts must appear |

Adjacency and the list form both exist for the same reason: **a binary is not a
technique.** Matching `schtasks` alone labelled a read-only `schtasks /query` as
"Scheduled task created" — a plainly false statement — so the entry now requires
`["schtasks", "/create"]`. The same flaw was latent in `bitsadmin`, `net user`,
`mshta`, `-computername` and `lsass`. Similarly, matching `-w hidden` as a
substring fires on any command containing that text inside a path.

---

## Layer 4 — LOLBAS argument confirmation

Stronger than a dual-use lookup: with the arguments available, this checks
whether the *documented abuse pattern itself* is present.

`lolbas_commands.json` holds 165 abuse-command **skeletons** across 105 binaries.
The skeleton is derived, not guessed — LOLBAS marks every variable part of a
documented command with an explicit placeholder:

```
certutil.exe -urlcache -f {REMOTEURL:.exe} {PATH:.exe}   →   skeleton: ["-urlcache"]
```

Removing the placeholders leaves exactly the tokens an operator cannot change
while still performing the abuse. **Every** skeleton token must match, which is
precise rather than merely strict.

Tokens that cannot discriminate are dropped at extraction, and a command whose
skeleton reduces to nothing is not shipped at all — that took 272 raw skeletons
down to 165. Dropped: the binary's own name, bare numbers and job ids,
two-character switches (`-f` is generic to every tool), and punctuation fragments
left by inline script payloads. `mshta.exe` disappears entirely, correctly — its
abuse is `mshta <url>`, where the URL is the variable part, so the binary alone is
the signal and the dual-use lookup already reports it.

| Result | Meaning |
|---|---|
| `CONFIRMED_ABUSE_PATTERN` | arguments match a documented abuse invocation |
| `DUAL_USE_PRESENT` | binary is in LOLBAS, arguments match no abuse pattern |

`DUAL_USE_PRESENT` is INFO severity and never escalates anything. It is not an
accusation — it reports that the check ran and came back clean, which silence
would not.

---

## Layer 5 — Sigma CommandLine rules

`sigma_cmdline_patterns.json` — 1,409 patterns extracted offline from SigmaHQ's
`process_creation` and `powershell` rules. Sigma is never evaluated at runtime;
there is no rule engine, and the app only reads the generated JSON.

The extraction keeps `CommandLine` conditions and drops `Image`/`ParentImage`,
recording on every record what was dropped. That makes most records **fragments**
of their source rule, and fragments are dangerous:

> **A record that does not reproduce its rule's whole condition never matches on
> its own.** Only **153 of 1,409 records (11%)** qualify — one active detection
> block, one pattern group, no dropped values, no image constraint.

This is not caution for its own sake. When fragments were briefly allowed to match
standalone, they flagged **32 of 32 benign samples**. The dataset contains rules
whose entire surviving CommandLine condition is `.exe`, `.cmd` or `copy` —
meaningful only beside the binary or folder the rule pinned. Code review did not
catch this; the known-good corpus did.

The remaining 1,256 fragments are reachable only through the rule-ID join below.

---

## Layer 6 — Entropy fallback

The weakest signal in the stack. INFO severity, and it never escalates a verdict
on its own — long base64 in a scheduled-task command line is entirely normal.

**Entropy alone does not work here, and the measurements invert the intuition:**

| Sample | bits/char |
|---|---|
| `C:\Program Files\Common Files\vendor\setup.exe` | 4.27 |
| `http://cdn.vendor.example.com/updates/agent-x64.msi` | 4.46 |
| `SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA` (a real `-enc` payload) | **3.70** |

A UTF-16LE base64 payload is *low* entropy, because every NUL byte encodes to a
repeated `A`. Paths and URLs are high-diversity strings in their own right. A
plain threshold would flag benign paths and miss real payloads.

So **shape is the discriminator and entropy is only the second test.** A candidate
must first look like an opaque blob: at least 20 characters, no path separator, no
URL scheme, restricted alphabet, mixed case with digits, no dots, and `=` only as
trailing padding. That excludes GUIDs (single-case hex), CamelCase product names
(no digits) and Java system properties like `-Dfile.encoding=UTF-8` (leading
switch, dots). Entropy threshold is then 3.2.

Layer 2 consumes anything it can decode, so Layer 6 only ever sees encodings
nothing could decode — which is exactly what it is for.

---

## Verdict aggregation

Never returns **Benign**. Absence of evidence is `Unknown`, consistent with
`ioc/verdict.py` hardcoding the benign count to 0. `parse_ok` distinguishes a
parse failure from a clean line with no matches.

In precedence order:

| # | Condition | Verdict |
|---|---|---|
| 1 | Rule match reconstructed across both modules (see below), high/critical | **Malicious** |
| 2 | High/critical rule match **+** obfuscation or confirmed LOLBAS abuse | **Malicious** |
| 3 | High/critical rule match alone | Suspicious |
| 4 | Obfuscation whose decoded content is itself suspicious, **with** corroboration | **Malicious** |
| 5 | Obfuscation, switch matches, confirmed LOLBAS abuse, or entropy — any of them | Suspicious |
| 6 | `DUAL_USE_PRESENT` alone | annotate only |
| 7 | Nothing matched, or the line would not parse | Unknown |

### The corroboration rule

`Malicious` requires **two independent sources**, per the project's aggregation
rule. Switch matches and obfuscation count as *one source between them*, however
many fire. The second must be a Sigma rule match at `medium` or above, or a
confirmed LOLBAS abuse pattern.

LOLBAS confirmation currently sets a `Suspicious` floor but does **not** count as
corroboration — measured precision is perfect (0 false confirmations across 32
benign samples) but 32 samples is a thin basis for authority that unlocks
`Malicious`. The two powers are separate constants
(`LOLBAS_SETS_SUSPICIOUS_FLOOR`, `LOLBAS_COUNTS_AS_CORROBORATION`) precisely so
the stronger one can be granted later on its own evidence.

### Cross-reference with the process module

When the analyst also filled Parent/Child Process and that module flagged
masquerading or a suspicious pairing, this module escalates one level — but the
escalation is **capped so it can never reach `Malicious` by itself**. The process
module already reaches `Malicious` readily from name-only data, and stacking a
second automatic escalation on top would compound a known-eager rule.

---

## The rule-ID join

The two Sigma extractions are complementary halves of the same rules. A rule
requiring `ParentImage: winword.exe` **and** `CommandLine: *-enc*` produces a
record in the pairs table (flagged `commandline_constrained`) **and** one here
(flagged `parentimage_constrained`), both carrying the same `sigma_rule_id`.

When both modules match that id in one session, the rule's original condition has
in fact been satisfied — nothing is approximated. The match is marked
`faithful_multifield` and is the one path to `Malicious` that does not require
obfuscation.

This is how 89% of the CommandLine dataset contributes at all. Measured overlap:
**47 rules, covering 891 pair records**.

Worked example — two halves of SigmaHQ rule `4ebc877f`:

| Submitted | Result |
|---|---|
| Command line `powershell.exe -nop …` alone | no rule match — the fragment stays suppressed |
| Same line **+** parent `apache-tomcat-9.exe`, child `adfind.exe` | rule reconstructed exactly → **Malicious** |

---

## Output

- **Flags** — `_flag()`-shaped, ids prefixed `CMDLINE_`, feeding the existing
  100+ flag system, the Threat Analysis evidence mapper and the ticket narrative.
  Every id is checked against the substrings that mapper reserves, so each
  evidence mapping is declared explicitly rather than inherited by accident.
- **Rows** — one per parsed statement, using the identical column schema to the
  process module's rows so the renderer concatenates both without special-casing.
- **Breakdown block** — rendered between the ticket-note output and the per-IOC
  cards: submitted line, interpreter, decoded form with its chain, then base
  command / flags / arguments per statement.
- **AI prompt** — findings, the decoded command, the transform chain, and an
  explicit *"checks NOT performed"* list so the narrative never implies a check
  ran when it did not.

What deliberately maps to **no** evidence key: encoding, entropy, hidden windows,
skipped profiles and execution-policy bypasses. These are defense-evasion signals
and there is no evidence key for defense evasion; forcing one would overstate what
a switch proves. They still reach the narrative through MITRE tactics and severity
notes. Active tampering with host defenses (AMSI, ETW, Defender, event-log
clearing) *is* mapped to `malware_executed` — something ran that had a reason to
hide.

A download cradle is **not** mapped to `c2_connection`. Seeing
`DownloadString('http://…')` proves an attempt, not a connection. If the URL is
real, the providers supply that evidence on their own authority.

---

## Calibration

```bash
python core/scripts/try_cmdline_analyzer.py --calibrate
python core/scripts/try_cmdline_analyzer.py --calibrate --verbose
python core/scripts/try_cmdline_analyzer.py "powershell -nop -w hidden -enc SQBFAFgA..."
```

Corpus: [`tests/fixtures/cmdline_corpus.json`](../tests/fixtures/cmdline_corpus.json)
— 30 known-bad, 32 known-good. Gate:
[`tests/test_cmdline_calibration.py`](../tests/test_cmdline_calibration.py).

**Current: 30/30 detected, 0 unexpected flags on the known-good half.**

The known-good half is the one that matters. A detection module tuned only for
recall looks excellent right up to the point analysts start ignoring it. Two real
defects were found by it and by nothing else:

| Benign sample | Fired | Cause |
|---|---|---|
| `schtasks.exe /query /fo LIST /v` | `SCHTASKS_CREATE` | pattern was the bare binary name |
| `java.exe -Dfile.encoding=UTF-8 -jar …` | `HIGH_ENTROPY_TOKEN` | a Java system property cleared every shape test |

**Caveat:** the corpus is hand-written from ordinary Windows administration,
packaging and CI activity — not from any particular estate. Local habits differ.
The meaningful validation step is adding real command lines from your own
closed-as-false-positive alerts and re-running the gate.

Four benign samples legitimately reach `Suspicious` and are declared in the
corpus rather than suppressed: the SCCM `-NoProfile -ExecutionPolicy Bypass`
wrapper, an Intune detection script running hidden, an administrator's
`schtasks /create`, and a `Compress-Archive` backup. Note that the gate counts
*unexpected flags*, not verdict escalation — operationally these four mean
roughly 12% of benign command lines surface as `Suspicious`.

---

## Known limits

- **A CRITICAL switch alone still returns `Suspicious`.** `vssadmin delete
  shadows` is about as unambiguous as a command line gets, but the switch table is
  a single source and the project requires two.
- **Entropy's remaining false-positive rate is unmeasured.** The shape gate removes
  paths, URLs, GUIDs and CamelCase names; what is untested is how often a
  legitimate opaque token — a licence key, a session id, a signed blob — clears
  both gates.
- **`--%` and variable-expansion obfuscation are unhandled.**
- **Sigma `ScriptBlockText` rules are logsource-mismatched.** Applying them to a
  process command line is defensible but broader than intended; each record
  carries its `logsource` so this can be measured and filtered if noisy.

---

## Regenerating the datasets

Offline and committed; the app never fetches at runtime.

```bash
pip install pyyaml          # script-only — deliberately not in requirements.txt

python core/scripts/extract_sigma_cmdline_patterns.py --download
python core/scripts/extract_lolbas.py
```

Add `--dry-run` to report counts without writing. After regenerating Sigma,
confirm the high-value categories survived: `-enc`/`-EncodedCommand`, `IEX` +
`DownloadString`, `certutil -urlcache`, `bitsadmin /transfer`, `rundll32` +
`javascript:`, `wmic process call create`, `vssadmin delete shadows`. A missing
category means the detection-block filter is wrong, not that Sigma lacks the rule.

Sources: [SigmaHQ](https://github.com/SigmaHQ/sigma) (Detection Rule License 1.1) ·
[LOLBAS](https://github.com/LOLBAS-Project/LOLBAS) (CC BY 4.0).

---

## Related

- [Process & Filepath Analysis](process_analyzer.md) — the sibling module, and the
  other half of the rule-ID join.
- [Threat State, Level, and Verdict](threat_state_level_verdict.md) — what the
  emitted evidence keys drive.
