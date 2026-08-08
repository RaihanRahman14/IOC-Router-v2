"""Tests for core.process_analyzer — Layer 1 identity verification."""
from __future__ import annotations

import unittest

from core import process_analyzer as pa


class TestWhitelistLoading(unittest.TestCase):
    def test_table_loads_and_is_normalized(self) -> None:
        table = pa.load_known_system_processes()
        self.assertGreaterEqual(len(table), 30)
        self.assertIn("svchost.exe", table)
        # Keys lowercased, directories normalized to lowercase backslash form.
        for name, dirs in table.items():
            self.assertEqual(name, name.lower())
            for d in dirs:
                self.assertEqual(d, d.lower())
                self.assertNotIn("/", d)
                self.assertFalse(d.endswith("\\"))

    def test_expected_core_binaries_present(self) -> None:
        table = pa.load_known_system_processes()
        for name in ("lsass.exe", "csrss.exe", "explorer.exe", "cmd.exe", "powershell.exe"):
            self.assertIn(name, table)


class TestNormalizeDir(unittest.TestCase):
    def test_case_and_separator_normalization(self) -> None:
        self.assertEqual(pa._normalize_dir("C:/WINDOWS/System32/"), "c:\\windows\\system32")

    def test_systemroot_token_expansion(self) -> None:
        self.assertEqual(pa._normalize_dir("%SystemRoot%\\System32"), "c:\\windows\\system32")
        self.assertEqual(pa._normalize_dir("%windir%\\System32"), "c:\\windows\\system32")
        self.assertEqual(pa._normalize_dir("\\SystemRoot\\System32"), "c:\\windows\\system32")

    def test_native_prefix_stripped(self) -> None:
        self.assertEqual(pa._normalize_dir("\\??\\C:\\Windows\\System32"), "c:\\windows\\system32")

    def test_duplicate_separators_collapsed(self) -> None:
        self.assertEqual(pa._normalize_dir("C:\\\\Windows\\\\System32"), "c:\\windows\\system32")

    def test_quotes_stripped(self) -> None:
        self.assertEqual(pa._normalize_dir('"C:\\Windows"'), "c:\\windows")


class TestSplitProcessPath(unittest.TestCase):
    def test_full_path(self) -> None:
        name, directory = pa.split_process_path("C:\\Windows\\System32\\svchost.exe")
        self.assertEqual(name, "svchost.exe")
        self.assertEqual(directory, "c:\\windows\\system32")

    def test_bare_name_has_no_directory(self) -> None:
        name, directory = pa.split_process_path("explorer.exe")
        self.assertEqual(name, "explorer.exe")
        self.assertIsNone(directory)

    def test_forward_slashes_and_quotes(self) -> None:
        name, directory = pa.split_process_path('"C:/Windows/explorer.exe"')
        self.assertEqual(name, "explorer.exe")
        self.assertEqual(directory, "c:\\windows")

    def test_sysmon_native_prefix(self) -> None:
        name, directory = pa.split_process_path("\\??\\C:\\Windows\\System32\\cmd.exe")
        self.assertEqual(name, "cmd.exe")
        self.assertEqual(directory, "c:\\windows\\system32")

    def test_empty_input(self) -> None:
        self.assertEqual(pa.split_process_path("   "), ("", None))


class TestLevenshtein(unittest.TestCase):
    def test_identical(self) -> None:
        self.assertEqual(pa._levenshtein("svchost", "svchost"), 0)

    def test_empty_operand(self) -> None:
        self.assertEqual(pa._levenshtein("", "cmd"), 3)
        self.assertEqual(pa._levenshtein("cmd", ""), 3)

    def test_substitution_and_transposition(self) -> None:
        self.assertEqual(pa._levenshtein("svchost", "scvhost"), 2)
        self.assertEqual(pa._levenshtein("lsass", "lsasss"), 1)


class TestAnalyzeIdentityLegitimate(unittest.TestCase):
    def test_correct_path_is_legitimate(self) -> None:
        res = pa.analyze_identity("C:\\Windows\\System32\\svchost.exe")
        self.assertIsNotNone(res)
        self.assertEqual(res.identity_flag, pa.LEGITIMATE_SYSTEM_PROCESS)
        self.assertEqual(res.matched_process, "svchost.exe")

    def test_case_insensitive_path(self) -> None:
        res = pa.analyze_identity("c:\\windows\\SYSTEM32\\LSASS.EXE")
        self.assertEqual(res.identity_flag, pa.LEGITIMATE_SYSTEM_PROCESS)

    def test_syswow64_twin_accepted(self) -> None:
        res = pa.analyze_identity("C:\\Windows\\SysWOW64\\cmd.exe")
        self.assertEqual(res.identity_flag, pa.LEGITIMATE_SYSTEM_PROCESS)

    def test_nested_expected_dir(self) -> None:
        res = pa.analyze_identity("C:\\Windows\\System32\\wbem\\wmiprvse.exe")
        self.assertEqual(res.identity_flag, pa.LEGITIMATE_SYSTEM_PROCESS)

    def test_name_only_cannot_verify_path(self) -> None:
        """Parent/Child fields are name-only — path check must be skipped, not failed."""
        res = pa.analyze_identity("explorer.exe")
        self.assertEqual(res.identity_flag, pa.LEGITIMATE_SYSTEM_PROCESS)
        self.assertNotEqual(res.identity_flag, pa.MASQUERADING_WRONG_PATH)
        self.assertIn("could not be verified", res.identity_detail)


class TestAnalyzeIdentityMasquerading(unittest.TestCase):
    def test_wrong_path(self) -> None:
        res = pa.analyze_identity("C:\\Users\\user\\AppData\\Local\\Temp\\svchost.exe")
        self.assertEqual(res.identity_flag, pa.MASQUERADING_WRONG_PATH)
        self.assertIn("c:\\users\\user\\appdata\\local\\temp", res.identity_detail)

    def test_explorer_outside_windows_dir(self) -> None:
        res = pa.analyze_identity("C:\\Windows\\System32\\explorer.exe")
        self.assertEqual(res.identity_flag, pa.MASQUERADING_WRONG_PATH)

    def test_typosquat_transposition(self) -> None:
        res = pa.analyze_identity("C:\\Windows\\System32\\scvhost.exe")
        self.assertEqual(res.identity_flag, pa.MASQUERADING_TYPOSQUAT)
        self.assertEqual(res.matched_process, "svchost.exe")

    def test_typosquat_flagged_regardless_of_path(self) -> None:
        """A typosquat in a legitimate-looking directory is still a typosquat."""
        res = pa.analyze_identity("C:\\Windows\\System32\\lsasss.exe")
        self.assertEqual(res.identity_flag, pa.MASQUERADING_TYPOSQUAT)
        self.assertEqual(res.matched_process, "lsass.exe")

    def test_typosquat_name_only_field(self) -> None:
        res = pa.analyze_identity("csrsss.exe")
        self.assertEqual(res.identity_flag, pa.MASQUERADING_TYPOSQUAT)

    def test_extension_swap(self) -> None:
        res = pa.analyze_identity("C:\\Windows\\System32\\svchost.com")
        self.assertEqual(res.identity_flag, pa.MASQUERADING_TYPOSQUAT)
        self.assertEqual(res.matched_process, "svchost.exe")
        self.assertIn("different extension", res.identity_detail)


class TestAnalyzeIdentityUnresolved(unittest.TestCase):
    def test_third_party_binary(self) -> None:
        res = pa.analyze_identity("C:\\Program Files\\Contoso\\ContosoAgentService.exe")
        self.assertEqual(res.identity_flag, pa.UNRESOLVED_THIRD_PARTY)

    def test_third_party_is_not_a_red_flag(self) -> None:
        res = pa.analyze_identity("C:\\Users\\user\\Downloads\\installer.exe")
        self.assertEqual(res.identity_flag, pa.UNRESOLVED_THIRD_PARTY)
        self.assertFalse(res.identity_flag.startswith("MASQUERADING"))

    def test_empty_field_returns_none(self) -> None:
        self.assertIsNone(pa.analyze_identity(""))
        self.assertIsNone(pa.analyze_identity("   "))
        self.assertIsNone(pa.analyze_identity(None))


class TestFuzzyThreshold(unittest.TestCase):
    def test_short_stem_uses_stricter_distance(self) -> None:
        """``cmd`` is 3 chars — a 2-edit neighbour must NOT be called a typosquat."""
        self.assertEqual(pa._max_distance_for("cmd"), pa.SHORT_STEM_MAX_DISTANCE)
        res = pa.analyze_identity("abd.exe")  # distance 2 from cmd
        self.assertEqual(res.identity_flag, pa.UNRESOLVED_THIRD_PARTY)

    def test_short_stem_still_catches_one_edit(self) -> None:
        res = pa.analyze_identity("cmd1.exe")
        self.assertEqual(res.identity_flag, pa.MASQUERADING_TYPOSQUAT)

    def test_long_stem_allows_two_edits(self) -> None:
        self.assertEqual(pa._max_distance_for("svchost"), pa.LEVENSHTEIN_MAX_DISTANCE)

    def test_common_third_party_names_not_flagged(self) -> None:
        """Regression guard against the fuzzy check over-firing on real software."""
        for name in (
            "chrome.exe", "firefox.exe", "outlook.exe", "teams.exe",
            "winword.exe", "excel.exe", "python.exe", "node.exe",
            "OneDrive.exe", "SearchApp.exe",
        ):
            with self.subTest(name=name):
                res = pa.analyze_identity(name)
                self.assertEqual(
                    res.identity_flag, pa.UNRESOLVED_THIRD_PARTY,
                    f"{name} was flagged as {res.identity_flag} ({res.identity_detail})",
                )


class TestProcessFilepathInput(unittest.TestCase):
    def test_submitted_fields_tracks_only_filled(self) -> None:
        inp = pa.ProcessFilepathInput(parent_process="winword.exe", child_process="cmd.exe")
        self.assertEqual(inp.submitted_fields(), ["parent_process", "child_process"])

    def test_whitespace_only_is_not_submitted(self) -> None:
        inp = pa.ProcessFilepathInput(file_path="   ", context="paste")
        self.assertEqual(inp.submitted_fields(), ["context"])

    def test_nothing_submitted(self) -> None:
        self.assertEqual(pa.ProcessFilepathInput().submitted_fields(), [])


class TestHashExtraction(unittest.TestCase):
    """Layer 3 — opportunistic only; absence of a hash is the expected default."""

    def test_md5_sha1_sha256(self) -> None:
        for value in ("44d88612fea8a8f36de82e1278abb02f",
                      "3395856ce81f2b7382dee72602f798b642f14140",
                      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"):
            with self.subTest(value=value):
                self.assertEqual(pa.extract_hash_candidates(f"hash is {value} ok"), [value])

    def test_lowercased_and_deduplicated(self) -> None:
        upper = "44D88612FEA8A8F36DE82E1278ABB02F"
        text = f"{upper} again {upper.lower()}"
        self.assertEqual(pa.extract_hash_candidates(text), [upper.lower()])

    def test_multiple_hashes_in_order(self) -> None:
        a = "44d88612fea8a8f36de82e1278abb02f"
        b = "3395856ce81f2b7382dee72602f798b642f14140"
        self.assertEqual(pa.extract_hash_candidates(f"{a} then {b}"), [a, b])

    def test_longer_hex_run_not_split_into_shorter_hashes(self) -> None:
        """A 64-char hash must not also yield a bogus 32-char prefix."""
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        self.assertEqual(pa.extract_hash_candidates(sha256), [sha256])

    def test_arbitrary_hex_run_ignored(self) -> None:
        self.assertEqual(pa.extract_hash_candidates("deadbeef " + "a" * 31), [])

    def test_none_and_empty(self) -> None:
        self.assertEqual(pa.extract_hash_candidates(None), [])
        self.assertEqual(pa.extract_hash_candidates(""), [])
        self.assertEqual(pa.extract_hash_candidates("just prose, no hash"), [])


class TestPairingMatcher(unittest.TestCase):
    """Layer 4 — runs only when both parent and child are present."""

    def test_office_spawning_shell_matches(self) -> None:
        match = pa.match_pairing("winword.exe", "cmd.exe")
        self.assertIsNotNone(match)
        self.assertEqual(match["parent"], "winword.exe")
        self.assertEqual(match["child"], "cmd.exe")
        self.assertIn(match["sigma_level"], ("high", "critical"))

    def test_one_sided_input_skips_layer(self) -> None:
        self.assertIsNone(pa.match_pairing("winword.exe", None))
        self.assertIsNone(pa.match_pairing(None, "cmd.exe"))
        self.assertIsNone(pa.match_pairing("winword.exe", "   "))

    def test_benign_pair_does_not_match(self) -> None:
        self.assertIsNone(pa.match_pairing("services.exe", "svchost.exe"))
        self.assertIsNone(pa.match_pairing("winlogon.exe", "userinit.exe"))

    def test_full_paths_accepted(self) -> None:
        match = pa.match_pairing(
            "C:\\Program Files\\Microsoft Office\\winword.exe",
            "C:\\Windows\\System32\\cmd.exe",
        )
        self.assertIsNotNone(match)

    def test_case_insensitive(self) -> None:
        self.assertIsNotNone(pa.match_pairing("WINWORD.EXE", "CMD.EXE"))

    def test_carries_traceability_fields(self) -> None:
        match = pa.match_pairing("mshta.exe", "powershell.exe")
        self.assertTrue(match["sigma_rule_id"])
        self.assertTrue(match["title"])
        self.assertIn("approximate", match)

    def test_approximate_note_explains_dropped_conditions(self) -> None:
        """Option A drops CommandLine and directory conditions — say so explicitly."""
        record = {"sigma_level": "high", "commandline_constrained": True,
                  "path_constrained": True, "sigma_rule_id": "abc"}
        dropped = pa._dropped_conditions(record)
        self.assertEqual(len(dropped), 2)
        self.assertIsNone(pa._dropped_conditions({}) or None)

    def test_exact_match_preferred_over_approximate(self) -> None:
        """At equal severity the faithful rule must win, so notes stay truthful."""
        exact = {"sigma_level": "high", "commandline_constrained": False,
                 "path_constrained": False}
        approx = {"sigma_level": "high", "commandline_constrained": True,
                  "path_constrained": False}
        self.assertGreater(pa._pairing_sort_key(exact), pa._pairing_sort_key(approx))

    def test_severity_beats_faithfulness(self) -> None:
        critical_approx = {"sigma_level": "critical", "commandline_constrained": True}
        high_exact = {"sigma_level": "high", "commandline_constrained": False}
        self.assertGreater(
            pa._pairing_sort_key(critical_approx), pa._pairing_sort_key(high_exact)
        )


class TestChainPropagation(unittest.TestCase):
    def test_masquerading_parent_contaminates_child(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            parent_process="C:\\Users\\Public\\svchost.exe", child_process="notepad.exe",
        ))
        self.assertTrue(result.chain_contamination)
        self.assertIn(pa.PARENT_CHAIN_CONTAMINATION, [f["id"] for f in result.flags])

    def test_clean_parent_does_not_contaminate(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            parent_process="explorer.exe", child_process="notepad.exe",
        ))
        self.assertFalse(result.chain_contamination)

    def test_no_child_means_no_contamination(self) -> None:
        """Contamination propagates *to a child* — with no child there is nothing to taint."""
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            file_path="C:\\Users\\Public\\svchost.exe",
            parent_process="C:\\Users\\Public\\svchost.exe",
        ))
        self.assertFalse(result.chain_contamination)


class TestVerdictAggregation(unittest.TestCase):
    def test_nothing_submitted_is_unknown(self) -> None:
        self.assertEqual(
            pa.analyze_process_event(pa.ProcessFilepathInput()).aggregated_verdict, "Unknown"
        )

    def test_single_clean_field_is_unknown_not_benign(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            file_path="C:\\Windows\\System32\\svchost.exe"))
        self.assertEqual(result.aggregated_verdict, "Unknown")

    def test_never_returns_benign(self) -> None:
        for data in (pa.ProcessFilepathInput(file_path="C:\\Windows\\explorer.exe"),
                     pa.ProcessFilepathInput(parent_process="explorer.exe",
                                             child_process="notepad.exe")):
            self.assertNotEqual(pa.analyze_process_event(data).aggregated_verdict, "Benign")

    def test_masquerading_floors_at_suspicious(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            file_path="C:\\Temp\\scvhost.exe"))
        self.assertEqual(result.aggregated_verdict, "Suspicious")

    def test_high_pairing_is_suspicious(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            parent_process="winword.exe", child_process="cmd.exe"))
        self.assertEqual(result.aggregated_verdict, "Suspicious")

    def test_pairing_plus_masquerading_is_malicious(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            parent_process="winword.exe", child_process="C:\\Temp\\cmd.exe"))
        self.assertEqual(result.aggregated_verdict, "Malicious")

    def test_lolbas_alone_does_not_escalate(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(child_process="certutil.exe"))
        self.assertIsNotNone(result.child_process_analysis.lolbas_match)
        self.assertEqual(result.aggregated_verdict, "Unknown")

    def test_hash_verdict_dominates(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            file_path="C:\\Temp\\scvhost.exe"))
        self.assertEqual(result.aggregated_verdict, "Suspicious")
        result.hash_verdict = {"verdict": "Benign"}
        self.assertEqual(pa.aggregate_verdict(result), "Benign")

    def test_hash_verdict_ignored_when_malformed(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            file_path="C:\\Temp\\scvhost.exe"))
        result.hash_verdict = {"verdict": "banana"}
        self.assertEqual(pa.aggregate_verdict(result), "Suspicious")

    def test_chain_contamination_escalates_one_level(self) -> None:
        """Per briefing §5.5, a masquerading parent plus any child reaches Malicious."""
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            parent_process="C:\\Users\\Public\\svchost.exe", child_process="notepad.exe"))
        self.assertEqual(result.aggregated_verdict, "Malicious")


class TestFlagEmission(unittest.TestCase):
    def test_clean_input_emits_no_flags(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            file_path="C:\\Windows\\System32\\lsass.exe"))
        self.assertEqual(result.flags, [])

    def test_flags_use_shared_shape(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            parent_process="winword.exe", child_process="C:\\Temp\\cmd.exe"))
        self.assertTrue(result.flags)
        for flag in result.flags:
            for key in ("id", "label", "threat_type", "severity", "mitre", "detail", "source"):
                self.assertIn(key, flag)
            self.assertIn(flag["severity"], ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"))

    def test_flag_ids_unique_across_fields(self) -> None:
        """Two fields flagged the same way must not collide during de-duplication."""
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            file_path="C:\\Temp\\scvhost.exe", child_process="C:\\Temp\\scvhost.exe"))
        ids = [f["id"] for f in result.flags]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(len([i for i in ids if i.startswith("MASQUERADING")]), 2)

    def test_masquerading_tagged_with_t1036(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            file_path="C:\\Temp\\scvhost.exe"))
        self.assertTrue(any("T1036" in t for f in result.flags for t in f["mitre"]))

    def test_dual_use_is_informational(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(child_process="certutil.exe"))
        dual = [f for f in result.flags if f["id"].startswith(pa.DUAL_USE_BINARY)]
        self.assertEqual(len(dual), 1)
        self.assertEqual(dual[0]["severity"], "INFO")


class TestMasqueradingLolbasFraming(unittest.TestCase):
    """Briefing §3 Layer 2: LOLBAS is only meaningful on non-masquerading fields.

    Emitting DUAL_USE_BINARY beside a masquerading flag produced a direct
    contradiction — "not malicious by itself" on a binary just flagged as
    impersonating a system process — and credited the real binary's abuse
    categories to a file that is not it.
    """

    def test_masquerading_field_emits_single_flag(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            file_path="C:\\Users\\Public\\certutil.exe"))
        ids = [f["id"] for f in result.flags]
        self.assertEqual(ids, ["MASQUERADING_WRONG_PATH_FILE_PATH"])
        self.assertNotIn(pa.DUAL_USE_BINARY, " ".join(ids))

    def test_no_contradictory_wording(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            file_path="C:\\Users\\Public\\certutil.exe"))
        details = " ".join(f["detail"] for f in result.flags)
        self.assertNotIn("not malicious by itself", details)

    def test_impersonation_context_preserved_in_detail(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            file_path="C:\\Users\\Public\\certutil.exe"))
        detail = result.flags[0]["detail"]
        self.assertIn("impersonates", detail)
        self.assertIn("Certutil.exe", detail)
        self.assertIn("Download", detail)

    def test_typosquat_looks_up_the_impersonated_binary(self) -> None:
        """``regsvr33.exe`` is absent from LOLBAS; ``regsvr32.exe`` is what matters."""
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            file_path="C:\\Temp\\regsvr33.exe"))
        analysis = result.file_path_analysis
        self.assertIsNone(analysis.lolbas_match)
        self.assertIsNotNone(analysis.impersonated_lolbas)
        self.assertEqual(analysis.impersonated_lolbas["binary"].lower(), "regsvr32.exe")
        self.assertIn("AWL Bypass", result.flags[0]["detail"])

    def test_impersonated_binary_absent_from_lolbas(self) -> None:
        """svchost.exe is not a LOLBAS binary — the note is simply omitted."""
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            file_path="C:\\Temp\\scvhost.exe"))
        self.assertIsNone(result.file_path_analysis.impersonated_lolbas)
        self.assertEqual(len(result.flags), 1)
        self.assertNotIn("impersonates", result.flags[0]["detail"])

    def test_detail_reads_as_two_sentences(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            file_path="C:\\Users\\Public\\certutil.exe"))
        self.assertIn(". The binary it impersonates", result.flags[0]["detail"])

    def test_mitre_stays_masquerading_only(self) -> None:
        """The impersonated tool's techniques describe what it *can* do, not what happened."""
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            file_path="C:\\Users\\Public\\certutil.exe"))
        self.assertEqual(result.flags[0]["mitre"], ["T1036.005"])

    def test_legitimate_field_still_gets_dual_use_flag(self) -> None:
        """The fix must not suppress LOLBAS on the normal path."""
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            file_path="C:\\Windows\\System32\\certutil.exe"))
        ids = [f["id"] for f in result.flags]
        self.assertEqual(ids, ["DUAL_USE_BINARY_FILE_PATH"])

    def test_unresolved_third_party_still_checked_against_lolbas(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(child_process="msbuild.exe"))
        self.assertTrue(
            any(f["id"].startswith(pa.DUAL_USE_BINARY) for f in result.flags)
        )

    def test_mixed_fields_behave_independently(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            file_path="C:\\Users\\Public\\certutil.exe", child_process="mshta.exe"))
        ids = sorted(f["id"] for f in result.flags)
        self.assertEqual(
            ids, ["DUAL_USE_BINARY_CHILD_PROCESS", "MASQUERADING_WRONG_PATH_FILE_PATH"]
        )

    def test_flags_sorted_by_severity(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            parent_process="C:\\Users\\Public\\svchost.exe", child_process="certutil.exe"))
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        ranks = [order[f["severity"]] for f in result.flags]
        self.assertEqual(ranks, sorted(ranks))

    def test_flag_ids_avoid_reserved_evidence_tokens(self) -> None:
        """flags_summary_for_evidence maps ids by SUBSTRING — collisions misclassify.

        ``SIGMA`` would route the pairing flag to malware_executed and
        ``PROCESS_INJECTION`` to privilege_escalation, both unintended.
        """
        reserved = ("SIGMA", "PROCESS_INJECTION", "YARA", "SANDBOX_PROCESS",
                    "RANSOMWARE", "PHISHING", "PORTSCAN")
        emitted = (pa.SUSPICIOUS_PARENT_CHILD_PAIR, pa.PARENT_CHAIN_CONTAMINATION,
                   pa.DUAL_USE_BINARY, pa.MASQUERADING_TYPOSQUAT, pa.MASQUERADING_WRONG_PATH)
        for flag_id in emitted:
            for token in reserved:
                self.assertNotIn(token, flag_id, f"{flag_id} collides with {token}")


class TestAnalyzeProcessEvent(unittest.TestCase):
    def test_reports_which_fields_were_submitted(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            parent_process="winword.exe", child_process="cmd.exe"))
        self.assertEqual(result.fields_submitted, ["parent_process", "child_process"])

    def test_reports_skipped_checks(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(file_path="a.exe"))
        skipped = " | ".join(result.checks_skipped)
        self.assertIn("Parent Process", skipped)
        self.assertIn("Child Process", skipped)
        self.assertIn("Parent-child pairing", skipped)
        self.assertIn("Hash lookup", skipped)

    def test_pairing_absent_when_one_side_missing(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(parent_process="winword.exe"))
        self.assertIsNone(result.pairing_flag)

    def test_context_forwarded_unmodified(self) -> None:
        raw = "  Raw log line with WEIRD spacing\nand a newline  "
        result = pa.analyze_process_event(pa.ProcessFilepathInput(context=raw))
        self.assertEqual(result.context_passthrough, raw)

    def test_context_only_submission_runs_no_process_layers(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(context="some prose"))
        self.assertEqual(result.field_analyses(), [])
        self.assertEqual(result.aggregated_verdict, "Unknown")

    def test_result_is_serializable(self) -> None:
        import dataclasses
        import json as _json
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            parent_process="winword.exe", child_process="cmd.exe", context="ctx"))
        _json.dumps(dataclasses.asdict(result))

    def test_lolbas_populated_per_field(self) -> None:
        result = pa.analyze_process_event(pa.ProcessFilepathInput(
            parent_process="certutil.exe", child_process="ContosoAgent.exe"))
        self.assertIsNotNone(result.parent_process_analysis.lolbas_match)
        self.assertIsNone(result.child_process_analysis.lolbas_match)


if __name__ == "__main__":
    unittest.main()
