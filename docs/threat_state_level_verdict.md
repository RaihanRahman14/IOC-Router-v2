# Threat State, Level, and Verdict

IOC Router runs a **SOC L1–style triage model** on top of raw provider results. Instead of only telling you *how malicious an IOC looks*, it answers three analyst-facing questions:

1. **Threat State** - how far has the attack progressed?
2. **Threat Level** - how severe / urgent is it?
3. **Verdict** - is this a real threat the analyst should act on?

All three are computed in [`ioc/threat_analysis.py`](../ioc/threat_analysis.py) via `analyzeThreat()`, and surfaced in the AI / Threat Analysis panel ([`ui/components/ai_panel.py`](../ui/components/ai_panel.py)).

---

## How It Works (Pipeline)

Every enabled provider (VirusTotal, urlscan, AbuseIPDB, ThreatFox, MalwareBazaar, Shodan, Hybrid Analysis, MXToolbox, …) is converted into **flags**, which are mapped into an `evidence` dictionary - 11 boolean signals describing observed attacker behavior:

```
attack_prevented, scanning_or_recon, phishing_or_social_eng, exploit_attempt,
malware_executed, c2_connection, privilege_escalation, lateral_movement,
persistence_mechanism, data_exfiltration, service_disruption_or_encryption
```

This `evidence` - together with the analyst-supplied **Device Action** (what the security control did) and **Asset Criticality** (is this a critical asset?) - drives all three assessments below.

A twelfth key, `web_exploit_payload`, is set only by WAF payload findings (see [WAF Payload Analysis](waf_payload_analyzer.md) D8). It is kept apart from `exploit_attempt`, which provider reputation also sets: "this IP has attacked elsewhere" and "this payload was aimed at our application" are different claims.

---

## 1. Threat State: *how far the attack has progressed*

State names follow the phases of the **[Unified Kill Chain](https://www.unifiedkillchain.com/)** (UKC). UKC was chosen over the Lockheed Martin Cyber Kill Chain because it has phases for privilege escalation and lateral movement, which LM CKC lacks. It was chosen over MITRE ATT&CK's *Initial Access* because *Delivery* and *Exploitation* name an attempt without claiming it succeeded, which the prevention cap below depends on. UKC phases are built from ATT&CK tactics, so the `mitre_alignment` IDs stay consistent.

`determineThreatState()` maps evidence onto one stage. The two lowest rungs each hold two alternatives at the same level:

| Rung | State | Triggered by | UKC |
|---|---|---|---|
| 0 | **Exposure** | Default. Asset is merely exposed/visible; no actual attack activity. | *(outside UKC: asset posture, not adversary activity)* |
| 0 | **Reconnaissance** | `scanning_or_recon`: scanner-probed paths (`/.env`, `/wp-admin`, …) or provider reputation for scanning. Replaces Exposure. | Reconnaissance |
| 1 | **Delivery** | Phishing, provider exploit reputation, *or* a serious attack that was **prevented** by controls. | Delivery |
| 1 | **Exploitation** | `web_exploit_payload`: a WAF-flagged SQLi / XSS / RCE / LFI / RFI / SSRF / CVE payload, **blocked or not**. Replaces Delivery. | Exploitation |
| 2 | **Execution** | Foothold achieved: `malware_executed` or `c2_connection`. | Execution / Command & Control |
| 3 | **Privilege Escalation** | Attacker gained higher privileges (`privilege_escalation`). | Privilege Escalation |
| 4 | **Lateral Movement** | Attacker spreading to other systems (`lateral_movement`). | Lateral Movement |
| 5 | **Persistence** | Attacker established survival mechanism (`persistence_mechanism`). | Persistence |
| 6 | **Impact** | Real damage: `data_exfiltration` or `service_disruption_or_encryption` (e.g. ransomware). | Exfiltration / Impact |

When several signals are present the highest rung wins. A request for `/wp-login.php` carrying `' OR '1'='1` is Exploitation, not Reconnaissance.

**Deliberate deviation from UKC ordering.** UKC places Persistence in its *In* phase, before Privilege Escalation and Lateral Movement. This model keeps Persistence above them, as it was before the rename. The names follow UKC; the ladder order does not.

**Exploitation never becomes Execution on WAF evidence alone.** A payload in a WAF log proves it was sent, not that it worked; an unblocked SQLi against an application that is not vulnerable does nothing. Execution requires server-side evidence, for example the process or command-line analyzer seeing the web server spawn a shell.

**Prevention cap:** if the Device Action is a prevention (`blocked`, `isolated`, `quarantined`, `denied`, `prevented`, `terminated`, `file cleaned`), severe signals do **not** escalate the state - it is capped at **Delivery** (or **Exploitation**, when a WAF exploit payload is present). Rationale: an attack that was successfully stopped is not a compromise.

---

## 2. Threat Level: *severity / response priority*

Translates the state into a severity band (`determineThreatLevel()`):

| Level | Meaning |
|---|---|
| **Low** | Minimal risk: exposure, reconnaissance, or delivery attempts with no real progress. Routine monitoring. |
| **Medium** | Web exploit payload (Exploitation, blocked or not), or confirmed execution with limited scope. Needs investigation. |
| **High** | Serious progression (priv-esc, lateral movement, persistence) or critical-asset compromise. Prompt response. |
| **Very High** | Active impact (exfiltration/encryption) or critical assets under advanced attack. Immediate escalation. |

Base mapping: Exposure, Reconnaissance, Delivery → **Low**; Exploitation, Execution → **Medium**; Privilege Escalation, Lateral Movement, Persistence → **High**; Impact → **Very High**.

Exploitation is Medium even when the WAF blocked the request. An exploit payload aimed at the application is worth a look regardless of outcome, whereas a blocked scanner probe is not. Reconnaissance stays Low whether blocked or not.

Adjustments applied on top of the base state → level mapping:

- **Hard override**: `data_exfiltration` or `service_disruption_or_encryption` forces **Very High**.
- **Asset criticality**: when the asset is flagged **Critical**, the level is raised (e.g. Execution → High; Priv-Esc / Lateral / Persistence / Impact → Very High).
- **Floor rule**: if persistence, lateral movement, or privilege escalation is present, the level is pushed to at least **High**.

---

## 3. Verdict: *the analyst's final call on the alert*

The closing decision for the ticket (`determineVerdict()`):

| Verdict | Meaning | When |
|---|---|---|
| 🔴 **True Positive** | A genuine, meaningful threat; warrants action. | State ∈ {Execution, Priv-Esc, Lateral, Persistence, Impact} **or** Level ∈ {High, Very High}. |
| 🟠 **Benign Positive** | Real activity detected, but low-impact or not shown to have succeeded. | State ∈ {Reconnaissance, Delivery, Exploitation}, or only weak signals (recon / phishing / exploit / prevented). Exploitation lands here at Medium: the level tells the analyst to check the application's response. |
| 🟢 **False Positive** | No actual threat signal; the alert can be dismissed. | No evidence signals at all. |

`analyzeThreat()` additionally returns:

- **`reasons`**: up to 3 human-readable justifications for the assessment.
- **`mitre_alignment`**: the relevant MITRE ATT&CK tactic IDs observed across providers (e.g. `TA0011` for C2, `TA0010` for exfiltration).
- **`verdict_color`**: the color used to render the verdict badge.

---

## Not to Be Confused With: the Reputation Verdict

IOC Router has a **second, separate** "verdict" in [`ioc/verdict.py`](../ioc/verdict.py) (`summarize_results`). That one labels each IOC **Malicious / Suspicious / Unknown** with a Confidence (High / Med / Low), computed directly from raw provider counts (VT engine hits, AbuseIPDB score, urlscan / ThreatFox / MalwareBazaar hits). It fills the batch results table.

The two are complementary:

| | Reputation Verdict ([`verdict.py`](../ioc/verdict.py)) | Triage Verdict ([`threat_analysis.py`](../ioc/threat_analysis.py)) |
|---|---|---|
| **Question** | How malicious does this IOC look? | What should the analyst do about this incident? |
| **Input** | Raw provider counts/scores | `evidence` + Device Action + Asset Criticality |
| **Output** | Malicious / Suspicious / Unknown | True / Benign / False Positive (+ State + Level) |

---

**Source:** [`ioc/threat_analysis.py`](../ioc/threat_analysis.py)
