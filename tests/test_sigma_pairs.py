"""Tests for the Sigma parent-child pairing blocklist (Layer 4 data).

Two groups:

* **Data integrity** — validates the shipped ``sigma_parent_child_pairs.json``.
  These run everywhere and guard against a bad regeneration being committed.
* **Extraction logic** — unit-tests ``core/scripts/extract_sigma_pairs.py``.
  That script needs PyYAML, a script-only dependency, so these skip when it is
  not installed rather than failing the suite.
"""
from __future__ import annotations

import fnmatch
import json
import unittest
from pathlib import Path

DATA_FILE = Path(__file__).resolve().parents[1] / "core" / "data" / "sigma_parent_child_pairs.json"

try:
    import yaml  # noqa: F401
    from core.scripts import extract_sigma_pairs as ex
    _HAS_YAML = True
except (ImportError, SystemExit):  # pragma: no cover — depends on environment
    _HAS_YAML = False


def _load() -> dict:
    return json.loads(DATA_FILE.read_text(encoding="utf-8"))


def _matches(pairs: list[dict], parent: str, child: str) -> list[dict]:
    """Return blocklist entries matching a bare parent/child name pair."""
    return [
        p for p in pairs
        if fnmatch.fnmatch("\\" + parent.lower(), p["parent_pattern"])
        and fnmatch.fnmatch("\\" + child.lower(), p["child_pattern"])
    ]


class TestDataIntegrity(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.doc = _load()
        cls.pairs = cls.doc["pairs"]

    def test_meta_declares_option_a(self) -> None:
        self.assertIn("Option A", self.doc["_meta"]["extraction_mode"])

    def test_meta_counts_match_payload(self) -> None:
        self.assertEqual(self.doc["_meta"]["pair_count"], len(self.pairs))

    def test_reasonable_size(self) -> None:
        self.assertGreater(len(self.pairs), 500)

    def test_required_fields_present(self) -> None:
        required = ("parent_pattern", "child_pattern", "sigma_rule_id", "sigma_level",
                    "title", "commandline_constrained", "path_constrained")
        for entry in self.pairs:
            for key in required:
                self.assertIn(key, entry)

    def test_faithfulness_is_tracked_and_honest(self) -> None:
        """Dropping CommandLine *and* directory conditions must both be recorded.

        A pair whose source rule pinned a directory is not a faithful
        reproduction, and labelling it as one overstates the finding.
        """
        meta = self.doc["_meta"]
        exact = sum(1 for p in self.pairs
                    if not p["commandline_constrained"] and not p["path_constrained"])
        self.assertEqual(meta["fully_faithful_count"], exact)
        self.assertLess(exact, len(self.pairs), "no approximation recorded — suspicious")
        self.assertGreater(meta["path_constrained_count"], 0)

    def test_levels_are_known_sigma_severities(self) -> None:
        allowed = {"informational", "low", "medium", "high", "critical"}
        for entry in self.pairs:
            self.assertIn(entry["sigma_level"], allowed)

    def test_globs_are_lowercase(self) -> None:
        """Layer 4 matches lowercased names; a stray uppercase glob would go dead."""
        for entry in self.pairs:
            for glob in (entry["parent_pattern"], entry["child_pattern"]):
                self.assertEqual(glob, glob.lower())

    def test_no_path_shaped_globs(self) -> None:
        """Directory constraints cannot match a name-only field — they must be dropped."""
        for entry in self.pairs:
            for glob in (entry["parent_pattern"], entry["child_pattern"]):
                self.assertNotIn(":", glob, f"drive-qualified glob: {glob}")
                self.assertFalse(glob.rstrip("*").endswith("\\"), f"directory glob: {glob}")

    def test_no_duplicate_pairings(self) -> None:
        keys = [(e["parent_pattern"], e["child_pattern"]) for e in self.pairs]
        self.assertEqual(len(keys), len(set(keys)))

    def test_mitre_techniques_well_formed(self) -> None:
        for entry in self.pairs:
            technique = entry.get("mitre_technique")
            if technique is not None:
                self.assertRegex(technique, r"^T\d{4}(\.\d{3})?$")


class TestBriefingHighValueCoverage(unittest.TestCase):
    """Section 3 Layer 4 of the briefing lists patterns the extraction must find.

    A miss here means the extraction filter regressed, not that Sigma changed.
    """

    @classmethod
    def setUpClass(cls) -> None:
        cls.pairs = _load()["pairs"]

    def test_office_apps_spawning_shells(self) -> None:
        for parent in ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"):
            for child in ("cmd.exe", "powershell.exe"):
                with self.subTest(parent=parent, child=child):
                    self.assertTrue(_matches(self.pairs, parent, child))

    def test_browsers_spawning_shells(self) -> None:
        for parent in ("chrome.exe", "msedge.exe", "iexplore.exe"):
            with self.subTest(parent=parent):
                self.assertTrue(_matches(self.pairs, parent, "powershell.exe"))

    def test_script_engines_spawning_shells(self) -> None:
        self.assertTrue(_matches(self.pairs, "wscript.exe", "powershell.exe"))
        self.assertTrue(_matches(self.pairs, "cscript.exe", "cmd.exe"))

    def test_mshta_spawning_shells(self) -> None:
        self.assertTrue(_matches(self.pairs, "mshta.exe", "cmd.exe"))
        self.assertTrue(_matches(self.pairs, "mshta.exe", "powershell.exe"))

    def test_wmiprvse_and_java_spawning_shells(self) -> None:
        """wmiprvse arrives via ``ParentImage|endswith: \\wbem\\WmiPrvSE.exe``.

        Regression guard: a name-shape filter that rejects multi-segment values
        silently drops this entire rule.
        """
        self.assertTrue(_matches(self.pairs, "wmiprvse.exe", "cmd.exe"))
        self.assertTrue(_matches(self.pairs, "java.exe", "cmd.exe"))

    def test_nested_powershell(self) -> None:
        self.assertTrue(_matches(self.pairs, "powershell.exe", "powershell.exe"))

    def test_benign_pairings_absent(self) -> None:
        """Exclusion blocks must not leak known-good pairings into the blocklist."""
        for parent, child in (("explorer.exe", "chrome.exe"),
                              ("services.exe", "svchost.exe"),
                              ("svchost.exe", "taskhostw.exe"),
                              ("winlogon.exe", "userinit.exe")):
            with self.subTest(parent=parent, child=child):
                self.assertEqual(_matches(self.pairs, parent, child), [])


@unittest.skipUnless(_HAS_YAML, "PyYAML not installed — extraction script tests skipped")
class TestNameGlobConversion(unittest.TestCase):
    def test_endswith_simple_name(self) -> None:
        self.assertEqual(ex._to_name_glob("\\winword.exe", "endswith"), "*\\winword.exe")

    def test_endswith_multi_segment_reduces_to_basename(self) -> None:
        self.assertEqual(ex._to_name_glob("\\wbem\\WmiPrvSE.exe", "endswith"), "*\\wmiprvse.exe")

    def test_contains_bare_token(self) -> None:
        self.assertEqual(ex._to_name_glob("tomcat", "contains"), "*tomcat*")

    def test_exact_full_path_reduces_to_basename(self) -> None:
        self.assertEqual(
            ex._to_name_glob("C:\\Windows\\System32\\cmd.exe", ""), "*\\cmd.exe"
        )

    def test_directory_values_rejected(self) -> None:
        self.assertIsNone(ex._to_name_glob(":\\PerfLogs\\", "contains"))
        self.assertIsNone(ex._to_name_glob("\\AppData\\Local\\Temp\\", "contains"))
        self.assertIsNone(ex._to_name_glob("C:\\Users\\Public\\", "contains"))

    def test_unevaluable_modifiers_rejected(self) -> None:
        for modifier in ("startswith", "re", "all"):
            self.assertIsNone(ex._to_name_glob("\\cmd.exe", modifier))

    def test_empty_value(self) -> None:
        self.assertIsNone(ex._to_name_glob("", "endswith"))
        self.assertIsNone(ex._to_name_glob(None, "endswith"))


@unittest.skipUnless(_HAS_YAML, "PyYAML not installed — extraction script tests skipped")
class TestExclusionHandling(unittest.TestCase):
    def test_filter_blocks_recognised(self) -> None:
        for name in ("filter_main_fp", "filter", "known_good", "reduction_x"):
            self.assertTrue(ex._is_exclusion_block(name), name)

    def test_selection_blocks_not_excluded(self) -> None:
        for name in ("selection", "selection_parent", "suspicious_children"):
            self.assertFalse(ex._is_exclusion_block(name), name)

    def test_condition_negation_detected(self) -> None:
        blocks = ["selection", "susp_parent", "legit_parent"]
        self.assertEqual(
            ex._negated_blocks("selection and not legit_parent", blocks), {"legit_parent"}
        )

    def test_wildcard_negation_detected(self) -> None:
        blocks = ["selection", "legit_a", "legit_b"]
        self.assertEqual(
            ex._negated_blocks("selection and not 1 of legit_*", blocks),
            {"legit_a", "legit_b"},
        )

    def test_negation_does_not_over_capture(self) -> None:
        """``not filter_a and selection_b`` must not mark selection_b as negated."""
        blocks = ["selection_b", "filter_a"]
        self.assertEqual(
            ex._negated_blocks("not filter_a and selection_b", blocks), {"filter_a"}
        )


@unittest.skipUnless(_HAS_YAML, "PyYAML not installed — extraction script tests skipped")
class TestExtractFromRule(unittest.TestCase):
    RULE = r"""
title: Office Application Spawning Shell
id: 11111111-2222-3333-4444-555555555555
status: test
level: high
tags:
  - attack.execution
  - attack.t1566.001
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith:
      - '\WINWORD.EXE'
      - '\EXCEL.EXE'
  selection_child:
    Image|endswith: '\cmd.exe'
  filter_known_good:
    Image|endswith: '\splwow64.exe'
  condition: all of selection_* and not filter_known_good
"""

    def test_cross_product_of_parents_and_children(self) -> None:
        records = ex.extract_pairs_from_rule("sample.yml", self.RULE)
        pairs = {(r["parent_pattern"], r["child_pattern"]) for r in records}
        self.assertEqual(pairs, {("*\\winword.exe", "*\\cmd.exe"),
                                 ("*\\excel.exe", "*\\cmd.exe")})

    def test_filter_block_value_excluded(self) -> None:
        records = ex.extract_pairs_from_rule("sample.yml", self.RULE)
        self.assertNotIn("*\\splwow64.exe", {r["child_pattern"] for r in records})

    def test_metadata_preserved(self) -> None:
        record = ex.extract_pairs_from_rule("sample.yml", self.RULE)[0]
        self.assertEqual(record["sigma_rule_id"], "11111111-2222-3333-4444-555555555555")
        self.assertEqual(record["sigma_level"], "high")
        self.assertEqual(record["mitre_technique"], "T1566.001")
        self.assertFalse(record["commandline_constrained"])
        self.assertFalse(record["path_constrained"])

    def test_dropped_directory_constraint_recorded(self) -> None:
        rule = self.RULE.replace(
            r"    Image|endswith: '\cmd.exe'",
            "    Image|endswith: '\\cmd.exe'\n    Image|contains: '\\Users\\Public\\'",
        )
        record = ex.extract_pairs_from_rule("sample.yml", rule)[0]
        self.assertTrue(record["path_constrained"])

    def test_commandline_condition_flagged(self) -> None:
        rule = self.RULE.replace(
            r"    Image|endswith: '\cmd.exe'",
            "    Image|endswith: '\\cmd.exe'\n    CommandLine|contains: '-enc'",
        )
        record = ex.extract_pairs_from_rule("sample.yml", rule)[0]
        self.assertTrue(record["commandline_constrained"])

    def test_deprecated_rule_skipped(self) -> None:
        rule = self.RULE.replace("status: test", "status: deprecated")
        self.assertEqual(ex.extract_pairs_from_rule("sample.yml", rule), [])

    def test_non_process_creation_skipped(self) -> None:
        rule = self.RULE.replace("category: process_creation", "category: image_load")
        self.assertEqual(ex.extract_pairs_from_rule("sample.yml", rule), [])

    def test_rule_without_parent_skipped(self) -> None:
        rule = self.RULE.replace("ParentImage|endswith", "SomeOtherField|endswith")
        self.assertEqual(ex.extract_pairs_from_rule("sample.yml", rule), [])

    def test_malformed_yaml_returns_empty(self) -> None:
        """A broken rule is logged and skipped, never fatal to the extraction run."""
        with self.assertLogs(ex.logger, level="WARNING") as captured:
            self.assertEqual(ex.extract_pairs_from_rule("bad.yml", "title: [unclosed"), [])
        self.assertIn("bad.yml", captured.output[0])


@unittest.skipUnless(_HAS_YAML, "PyYAML not installed — extraction script tests skipped")
class TestDedupe(unittest.TestCase):
    @staticmethod
    def _record(level: str, rule_id: str, cmdline: bool = False, path: bool = False) -> dict:
        return {
            "parent_pattern": "*\\winword.exe", "child_pattern": "*\\cmd.exe",
            "mitre_technique": "T1566.001", "mitre_techniques": ["T1566.001"],
            "sigma_rule_id": rule_id, "sigma_level": level, "sigma_status": "test",
            "sigma_file": "x.yml", "title": "t", "commandline_constrained": cmdline,
            "path_constrained": path,
        }

    def test_prefers_faithful_rule_at_equal_severity(self) -> None:
        out = ex.dedupe([self._record("high", "constrained", cmdline=True),
                         self._record("high", "exact")])
        self.assertEqual(out[0]["sigma_rule_id"], "exact")

    def test_path_constraint_also_counts_as_unfaithful(self) -> None:
        out = ex.dedupe([self._record("high", "path_bound", path=True),
                         self._record("high", "exact")])
        self.assertEqual(out[0]["sigma_rule_id"], "exact")

    def test_keeps_most_severe_rule(self) -> None:
        out = ex.dedupe([self._record("medium", "a"), self._record("critical", "b"),
                         self._record("low", "c")])
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["sigma_level"], "critical")
        self.assertEqual(out[0]["sigma_rule_id"], "b")

    def test_counts_duplicates(self) -> None:
        out = ex.dedupe([self._record("high", "a"), self._record("high", "b")])
        self.assertEqual(out[0]["duplicate_rule_count"], 2)

    def test_distinct_pairs_kept(self) -> None:
        other = {**self._record("high", "b"), "child_pattern": "*\\powershell.exe"}
        self.assertEqual(len(ex.dedupe([self._record("high", "a"), other])), 2)


if __name__ == "__main__":
    unittest.main()
