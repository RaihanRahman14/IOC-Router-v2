"""Tests for core.cmdline_analyzer — Layers 3 and 6, flags, verdict, rows."""
from __future__ import annotations

import unittest

from core import cmdline_analyzer as ca
from core import process_analyzer as pa
from tests.test_cmdline_deobfuscator import ENCODED_CRADLE


class TestKeywordTable(unittest.TestCase):
    def test_table_loads(self) -> None:
        table = ca.load_suspicious_keywords()
        self.assertGreaterEqual(len(table), 30)
        for record in table:
            self.assertTrue(record["id"])
            self.assertTrue(record["patterns"])
            self.assertIn(record.get("severity"), ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))

    def test_ids_avoid_reserved_evidence_substrings(self) -> None:
        # flags_summary_for_evidence maps flag ids to evidence keys by substring.
        # A keyword id containing one of these would silently inherit a mapping.
        reserved = (
            "SIGMA", "MALWARE", "EXPLOIT", "CVE", "C2", "RECON", "SCANNING",
            "PERSISTENCE", "PRIVESC", "PROCESS_INJECTION", "LATERAL", "SMB", "RDP",
            "PHISHING", "RANSOMWARE", "REGISTRY_MOD", "MUTEX", "YARA",
            "MALWARE_DOWNLOAD", "DOWNLOAD_SERVED", "CREDENTIAL_HARVEST",
        )
        for record in ca.load_suspicious_keywords():
            flag_id = f"CMDLINE_{record['id']}"
            for token in reserved:
                self.assertNotIn(token, flag_id, f"{flag_id} collides with {token}")

    def test_mitre_ids_are_well_formed(self) -> None:
        for record in ca.load_suspicious_keywords():
            for technique in record.get("mitre", []):
                self.assertRegex(technique, r"^T\d{4}(\.\d{3})?$")

    def test_missing_data_file_degrades_to_empty(self) -> None:
        ca.load_suspicious_keywords.cache_clear()
        original = ca._KEYWORDS_FILE
        try:
            ca._KEYWORDS_FILE = original.with_name("nope.json")
            self.assertEqual(ca.load_suspicious_keywords(), [])
        finally:
            ca._KEYWORDS_FILE = original
            ca.load_suspicious_keywords.cache_clear()


class TestKeywordMatching(unittest.TestCase):
    def _ids(self, line: str) -> set[str]:
        result = ca.analyze_command_line(ca.CommandLineInput(command_line=line))
        return {m["id"] for m in result.keyword_flags}

    def test_flag_mode(self) -> None:
        self.assertIn("NO_PROFILE", self._ids("powershell -nop -c whoami"))

    def test_flag_value_mode_requires_adjacency(self) -> None:
        self.assertIn("HIDDEN_WINDOW", self._ids("powershell -w hidden -c whoami"))

    def test_flag_value_mode_ignores_incidental_text(self) -> None:
        # The literal text "-w hidden" inside a path must not fire the pair rule.
        ids = self._ids(r'copy "C:\data\-w hidden\notes.txt" D:\out.txt')
        self.assertNotIn("HIDDEN_WINDOW", ids)

    def test_token_mode(self) -> None:
        self.assertIn("INVOKE_EXPRESSION", self._ids("powershell -c iex"))

    def test_substring_mode(self) -> None:
        self.assertIn("DOWNLOAD_CRADLE", self._ids("powershell -c (New-Object Net.WebClient)"))

    def test_each_keyword_reports_once(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line="powershell -nop -c iex ; powershell -nop -c iex"
        ))
        ids = [m["id"] for m in result.keyword_flags]
        self.assertEqual(len(ids), len(set(ids)))

    def test_benign_line_matches_nothing(self) -> None:
        for line in (
            r'"C:\Program Files\Vendor\agent.exe" --service --config "C:\ProgramData\a.cfg"',
            r"copy C:\a.txt C:\b.txt",
            r'msiexec /i "C:\ProgramData\vendor\agent.msi" /qn',
        ):
            with self.subTest(line=line):
                self.assertEqual(self._ids(line), set())


class TestEntropy(unittest.TestCase):
    def test_entropy_of_uniform_string_is_zero(self) -> None:
        self.assertEqual(ca.shannon_entropy("aaaaaa"), 0.0)

    def test_entropy_of_empty_string(self) -> None:
        self.assertEqual(ca.shannon_entropy(""), 0.0)

    def test_high_entropy_token_detected(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line="mytool.exe --payload Xq7Zp2Lm9Kd4Rw8Tn3Vb6Hj1Yg5Ac0Ef"
        ))
        self.assertTrue(result.entropy_flag)

    def test_ordinary_path_does_not_trip_entropy(self) -> None:
        # Measured at 4.27 bits/char — higher than a real base64 payload. Only
        # the shape gate keeps it out; a pure threshold would flag it.
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line=r'copy "C:\Program Files\Common Files\vendor\setup.exe" D:\backup'
        ))
        self.assertFalse(result.entropy_flag)

    def test_long_url_does_not_trip_entropy(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line="curl http://cdn.vendor.example.com/updates/2026/agent-setup-x64.msi"
        ))
        self.assertFalse(result.entropy_flag)

    def test_guid_does_not_trip_entropy(self) -> None:
        # Single-case hex. Common in benign msiexec lines.
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line="msiexec /x {3f2504e0-4f89-11d3-9a0c-0305e82c3301} /qn"
        ))
        self.assertFalse(result.entropy_flag)

    def test_camelcase_product_name_does_not_trip_entropy(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line="start MicrosoftEdgeUpdateSetupInstaller"
        ))
        self.assertFalse(result.entropy_flag)

    def test_undecodable_blob_trips_entropy(self) -> None:
        # Exactly what Layer 6 exists for: blob-shaped, but base64-decodes to
        # binary, so Layer 2 correctly refuses it and no other layer sees it.
        blob = "pU3KGCUwux1tEyze1iN7LtkeP3IfyxlxF0SU1kk8nVw0"
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line=f"mytool.exe --blob {blob}"
        ))
        self.assertFalse(result.was_obfuscated)
        self.assertTrue(result.entropy_flag)

    def test_decodable_blob_is_consumed_by_layer_2_not_layer_6(self) -> None:
        # A real -enc payload is replaced by its plaintext before Layer 6 runs,
        # so the fallback stays reserved for encodings nothing could decode.
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line="mytool.exe --blob SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"
        ))
        self.assertTrue(result.was_obfuscated)
        self.assertFalse(result.entropy_flag)

    def test_entropy_alone_never_reaches_malicious(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line="mytool.exe --payload Xq7Zp2Lm9Kd4Rw8Tn3Vb6Hj1Yg5Ac0Ef"
        ))
        self.assertEqual(result.aggregated_verdict, "Suspicious")
        entropy_flags = [f for f in result.flags if f["id"] == ca.CMDLINE_HIGH_ENTROPY_TOKEN]
        self.assertEqual(entropy_flags[0]["severity"], "INFO")


class TestIocCandidates(unittest.TestCase):
    def test_url_extracted_from_decoded_payload(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line=f"powershell -enc {ENCODED_CRADLE}"
        ))
        self.assertIn("http://198.51.100.7/a.ps1", result.ioc_candidates)

    def test_ipv4_extracted(self) -> None:
        self.assertIn("203.0.113.9", ca.extract_ioc_candidates("ping 203.0.113.9 -n 1"))

    def test_version_string_is_not_an_ip(self) -> None:
        self.assertEqual(ca.extract_ioc_candidates("setup.exe /version 10.0.19045.1"), [])

    def test_hash_extracted(self) -> None:
        digest = "44d88612fea8a8f36de82e1278abb02f"
        self.assertIn(digest, ca.extract_ioc_candidates(f"certutil -hashfile x {digest}"))

    def test_dotnet_type_names_are_not_extracted_as_domains(self) -> None:
        # Net.WebClient and System.IO both satisfy a generic domain pattern, and
        # System.IO even ends in a real TLD. Sending either to the providers
        # would be noise at best and an outbound disclosure at worst.
        candidates = ca.extract_ioc_candidates(
            "powershell -c (New-Object Net.WebClient); [System.IO.File]::Delete('x')"
        )
        self.assertEqual(candidates, [])

    def test_trailing_punctuation_stripped_from_url(self) -> None:
        self.assertEqual(
            ca.extract_ioc_candidates("curl http://example.com/a.exe."),
            ["http://example.com/a.exe"],
        )

    def test_candidates_are_deduplicated(self) -> None:
        text = "curl http://x.test/a & curl http://x.test/a"
        self.assertEqual(len(ca.extract_ioc_candidates(text)), 1)


class TestObfuscationDiff(unittest.TestCase):
    def test_revealed_keywords_are_those_hidden_by_encoding(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line=f"powershell -w hidden -enc {ENCODED_CRADLE}"
        ))
        self.assertTrue(result.was_obfuscated)
        self.assertIn("DOWNLOAD_CRADLE", result.revealed_keywords)
        # HIDDEN_WINDOW was visible before decoding, so it was not concealed.
        self.assertNotIn("HIDDEN_WINDOW", result.revealed_keywords)

    def test_encoding_something_mundane_reveals_nothing(self) -> None:
        import base64
        blob = base64.b64encode("whoami /all".encode("utf-16-le")).decode()
        line = f"powershell -enc {blob}"
        result = ca.analyze_command_line(ca.CommandLineInput(command_line=line))
        self.assertTrue(result.was_obfuscated)
        self.assertEqual(result.revealed_keywords, [])


class TestVerdict(unittest.TestCase):
    def _verdict(self, line: str) -> str:
        return ca.analyze_command_line(ca.CommandLineInput(command_line=line)).aggregated_verdict

    def test_empty_input_is_unknown(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(command_line=None))
        self.assertEqual(result.aggregated_verdict, "Unknown")
        self.assertFalse(result.parse_ok)
        self.assertTrue(result.checks_skipped)

    def test_clean_line_is_unknown_never_benign(self) -> None:
        self.assertEqual(self._verdict(r"copy C:\a.txt C:\b.txt"), "Unknown")
        self.assertNotIn("Benign", ca.VERDICT_LADDER)

    def test_keywords_alone_are_suspicious(self) -> None:
        self.assertEqual(self._verdict("powershell -nop -w hidden -c iex"), "Suspicious")

    def test_obfuscation_alone_is_suspicious(self) -> None:
        import base64
        blob = base64.b64encode("whoami /all".encode("utf-16-le")).decode()
        self.assertEqual(self._verdict(f"powershell -enc {blob}"), "Suspicious")

    def test_keyword_evidence_alone_still_cannot_reach_malicious(self) -> None:
        # The corroboration rule survives Milestone B: keyword hits and
        # obfuscation, with no Sigma rule agreeing, still top out at Suspicious.
        self.assertTrue(ca.MALICIOUS_REQUIRES_CORROBORATION)
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line=f"powershell -w hidden -enc {ENCODED_CRADLE}"
        ))
        result.rule_matches = []
        self.assertEqual(ca.aggregate_verdict(result), "Suspicious")

    def test_sigma_corroboration_lifts_the_ceiling(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line=f"powershell -w hidden -enc {ENCODED_CRADLE}"
        ))
        result.rule_matches = [{"sigma_rule_id": "x", "sigma_level": "high"}]
        self.assertEqual(ca.aggregate_verdict(result), "Malicious")

    def test_low_severity_rule_match_does_not_corroborate(self) -> None:
        # A noisy low-level rule is not a second source worth promoting on.
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line=f"powershell -w hidden -enc {ENCODED_CRADLE}"
        ))
        result.rule_matches = [{"sigma_rule_id": "x", "sigma_level": "low"}]
        self.assertEqual(ca.aggregate_verdict(result), "Suspicious")

    def test_unparseable_input_is_unknown(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(command_line='"'))
        self.assertEqual(result.aggregated_verdict, "Unknown")


class TestCrossReference(unittest.TestCase):
    def _linked(self, flag_id: str) -> pa.ProcessAnalysisResult:
        linked = pa.ProcessAnalysisResult()
        linked.flags = [{"id": flag_id, "severity": "HIGH", "label": "x", "mitre": []}]
        return linked

    def test_absent_linked_process_is_handled(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(command_line="powershell -nop -c iex"))
        self.assertIsNone(result.cross_reference)
        self.assertEqual(result.aggregated_verdict, "Suspicious")

    def test_masquerading_parent_raises_unknown_to_suspicious(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line="mytool.exe --payload Xq7Zp2Lm9Kd4Rw8Tn3Vb6Hj1Yg5Ac0Ef",
            linked_process=self._linked("MASQUERADING_WRONG_PATH_PARENT_PROCESS"),
        ))
        self.assertIsNotNone(result.cross_reference)
        self.assertEqual(result.aggregated_verdict, "Suspicious")

    def test_cross_reference_alone_cannot_reach_malicious(self) -> None:
        # The sibling module already reaches Malicious readily from name-only
        # data; a second automatic escalation on top must not compound it.
        # Sigma corroboration may still promote the verdict on its own merits,
        # so this asserts the cross-reference contributes no extra step.
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line="powershell -nop -c iex",
            linked_process=self._linked("SUSPICIOUS_PARENT_CHILD_PAIR"),
        ))
        self.assertEqual(result.aggregated_verdict, "Suspicious")

    def test_unrelated_process_flags_do_not_cross_reference(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line="powershell -nop -c iex",
            linked_process=self._linked("DUAL_USE_BINARY_FILE_PATH"),
        ))
        self.assertIsNone(result.cross_reference)


class TestFlags(unittest.TestCase):
    def test_flags_are_severity_sorted(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line=f"powershell -nop -noni -w hidden -enc {ENCODED_CRADLE}"
        ))
        order = [ca._SEVERITY_ORDER[f["severity"]] for f in result.flags]
        self.assertEqual(order, sorted(order, reverse=True))

    def test_flag_shape_matches_provider_flags(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(command_line="powershell -nop -c iex"))
        required = {"id", "label", "threat_type", "severity", "mitre", "detail", "source"}
        for flag in result.flags:
            # `source_url` is the optional extra the renderer turns into a
            # clickable label and badge — the same convention the process module
            # uses, and the reason ATT&CK links are no longer inlined in detail.
            self.assertLessEqual(required, set(flag))
            self.assertLessEqual(set(flag) - required, {"source_url"})
            self.assertTrue(flag["id"].startswith("CMDLINE_"))

    def test_details_do_not_inline_urls(self) -> None:
        # Raw ATT&CK URLs in the detail text pushed the readable part of the
        # finding off the card; the ids themselves are linked instead.
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line="psexec.exe \\\\WKS-042 -u admin cmd.exe /c whoami"))
        for flag in result.flags:
            self.assertNotIn("http", flag["detail"])

    def test_mitre_bearing_flags_carry_a_source_link(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line="powershell -nop -w hidden -c iex"))
        for flag in result.flags:
            if flag["mitre"]:
                self.assertTrue(flag.get("source_url", "").startswith("https://attack.mitre.org"))

    def test_compounding_flag_fires_on_three_indicators(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line="powershell -nop -noni -w hidden -ep bypass -c iex"
        ))
        ids = {f["id"] for f in result.flags}
        self.assertIn(ca.CMDLINE_SWITCH_COMBINATION, ids)

    def test_compounding_flag_absent_on_a_single_indicator(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(command_line="powershell -nop -c dir"))
        ids = {f["id"] for f in result.flags}
        self.assertNotIn(ca.CMDLINE_SWITCH_COMBINATION, ids)

    def test_obfuscation_flag_carries_the_decode_chain(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line=f"powershell -enc {ENCODED_CRADLE}"
        ))
        flag = next(f for f in result.flags if f["id"] == ca.CMDLINE_ENCODED_PAYLOAD)
        self.assertIn("base64", flag["detail"].lower())


class TestRows(unittest.TestCase):
    def test_row_schema_matches_process_rows_key_for_key(self) -> None:
        cmd_rows = ca.to_rows(ca.analyze_command_line(
            ca.CommandLineInput(command_line="powershell -nop -c iex")
        ))
        proc_rows = pa.to_rows(pa.analyze_process_event(
            pa.ProcessFilepathInput(parent_process="winword.exe", child_process="cmd.exe")
        ))
        self.assertTrue(cmd_rows and proc_rows)
        self.assertEqual(set(cmd_rows[0]), set(proc_rows[0]))

    def test_one_row_per_statement(self) -> None:
        rows = ca.to_rows(ca.analyze_command_line(
            ca.CommandLineInput(command_line="whoami & hostname & ipconfig")
        ))
        self.assertEqual(len(rows), 3)

    def test_no_rows_without_a_command_line(self) -> None:
        self.assertEqual(ca.to_rows(ca.analyze_command_line(ca.CommandLineInput())), [])

    def test_long_artifact_is_truncated(self) -> None:
        rows = ca.to_rows(ca.analyze_command_line(
            ca.CommandLineInput(command_line="mytool.exe " + "A" * 400)
        ))
        self.assertLessEqual(len(rows[0]["Artifact"]), ca._ARTIFACT_MAX_LEN)

    def test_clean_row_says_the_check_ran(self) -> None:
        rows = ca.to_rows(ca.analyze_command_line(
            ca.CommandLineInput(command_line=r"copy C:\a.txt C:\b.txt")
        ))
        self.assertIn("no known-suspicious pattern", rows[0]["Primary Evidence"].lower())


class TestChecksSkipped(unittest.TestCase):
    def test_missing_process_context_is_declared(self) -> None:
        # Every layer is built now, but without Parent/Child Process the Sigma
        # multi-field reconstruction cannot run — the narrative must say so
        # rather than imply those rules were evaluated and cleared.
        result = ca.analyze_command_line(ca.CommandLineInput(command_line="whoami"))
        joined = " ".join(result.checks_skipped).lower()
        self.assertIn("sigma", joined)
        self.assertIn("parent/child", joined)

    def test_context_passthrough_is_unmodified(self) -> None:
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line="whoami", context="  raw alert text  "
        ))
        self.assertEqual(result.context_passthrough, "  raw alert text  ")


if __name__ == "__main__":
    unittest.main()
