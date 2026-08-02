# Threat State, Level, and Verdict

IOC Router runs a **SOC L1–style triage model** on top of raw provider results. Instead of only telling you *how malicious an IOC looks*, it answers three analyst-facing questions:

1. **Threat State** — how far has the attack progressed?
2. **Threat Level** — how severe / urgent is it?
3. **Verdict** — is this a real threat the analyst should act on?

All three are computed in [`ioc/threat_analysis.py`](../ioc/threat_analysis.py) via `analyzeThreat()`, and surfaced in the AI / Threat Analysis panel ([`ui/components/ai_panel.py`](../ui/components/ai_panel.py)).

---

## How It Works (Pipeline)

Every enabled provider (VirusTotal, urlscan, AbuseIPDB, ThreatFox, MalwareBazaar, Shodan, Hybrid Analysis, MXToolbox, …) is converted into **flags**, which are mapped into an `evidence` dictionary — 11 boolean signals describing observed attacker behavior:

```
attack_prevented, scanning_or_recon, phishing_or_social_eng, exploit_attempt,
malware_executed, c2_connection, privilege_escalation, lateral_movement,
persistence_mechanism, data_exfiltration, service_disruption_or_encryption
```

This `evidence` — together with the analyst-supplied **Device Action** (what the security control did) and **Asset Criticality** (is this a critical asset?) — drives all three assessments below.

---

## 1. Threat State — *how far the attack has progressed*

Maps evidence onto a single kill-chain stage, from lightest to most severe (`determineThreatState()`):

| State | Triggered by |
|---|---|
| **Exposure** | Default. Asset is merely exposed/visible; no actual attack activity. |
| **Intrusion Attempt** | Recon/scanning, phishing, or exploit attempt — *or* a serious attack that was **prevented** by controls. |
| **Compromise** | Foothold achieved: `malware_executed` or `c2_connection`. |
| **Privilege Escalation** | Attacker gained higher privileges (`privilege_escalation`). |
| **Lateral Movement** | Attacker spreading to other systems (`lateral_movement`). |
| **Persistence** | Attacker established survival mechanism (`persistence_mechanism`). |
| **Impact** | Real damage: `data_exfiltration` or `service_disruption_or_encryption` (e.g. ransomware). |

**Prevention cap:** if the Device Action is a prevention (`blocked`, `isolated`, `quarantined`, `denied`, `prevented`, `terminated`, `file cleaned`), severe signals do **not** escalate the state — it is capped at **Intrusion Attempt**. Rationale: an attack that was successfully stopped is not a compromise.

---

## 2. Threat Level — *severity / response priority*

Translates the state into a severity band (`determineThreatLevel()`):

| Level | Meaning |
|---|---|
| **Low** | Minimal risk — exposure or attempts with no real progress. Routine monitoring. |
| **Medium** | Confirmed compromise, limited scope. Needs investigation. |
| **High** | Serious progression (priv-esc, lateral movement, persistence) or critical-asset compromise. Prompt response. |
| **Very High** | Active impact (exfiltration/encryption) or critical assets under advanced attack. Immediate escalation. |

Adjustments applied on top of the base state → level mapping:

- **Hard override** — `data_exfiltration` or `service_disruption_or_encryption` forces **Very High**.
- **Asset criticality** — when the asset is flagged **Critical**, the level is raised (e.g. Compromise → High; Priv-Esc / Lateral / Persistence / Impact → Very High).
- **Floor rule** — if persistence, lateral movement, or privilege escalation is present, the level is pushed to at least **High**.

---

## 3. Verdict — *the analyst's final call on the alert*

The closing decision for the ticket (`determineVerdict()`):

| Verdict | Meaning | When |
|---|---|---|
| 🔴 **True Positive** | A genuine, meaningful threat; warrants action. | State ∈ {Compromise, Priv-Esc, Lateral, Persistence, Impact} **or** Level ∈ {High, Very High}. |
| 🟠 **Benign Positive** | Real activity detected, but low-impact or already contained. | State = Intrusion Attempt, or only weak signals (recon / phishing / exploit / prevented). |
| 🟢 **False Positive** | No actual threat signal; the alert can be dismissed. | No evidence signals at all. |

`analyzeThreat()` additionally returns:

- **`reasons`** — up to 3 human-readable justifications for the assessment.
- **`mitre_alignment`** — the relevant MITRE ATT&CK tactic IDs observed across providers (e.g. `TA0011` for C2, `TA0010` for exfiltration).
- **`verdict_color`** — the color used to render the verdict badge.

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
