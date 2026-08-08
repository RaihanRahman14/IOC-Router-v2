"""Tests for core.lolbas_lookup — Layer 2 dual-use binary lookup."""
from __future__ import annotations

import unittest

from core import lolbas_lookup as ll


class TestDatasetLoading(unittest.TestCase):
    def test_table_loads(self) -> None:
        table = ll.load_lolbas_table()
        self.assertGreaterEqual(len(table), 150)

    def test_keys_are_lowercased_filenames(self) -> None:
        for name in ll.load_lolbas_table():
            self.assertEqual(name, name.lower())
            self.assertNotIn("\\", name)

    def test_records_have_required_shape(self) -> None:
        for name, record in ll.load_lolbas_table().items():
            with self.subTest(name=name):
                self.assertIn("binary", record)
                self.assertIsInstance(record.get("categories"), list)
                self.assertIsInstance(record.get("mitre"), list)
                self.assertTrue(record["categories"], f"{name} has no categories")

    def test_well_known_binaries_present(self) -> None:
        table = ll.load_lolbas_table()
        for name in ("certutil.exe", "mshta.exe", "rundll32.exe", "regsvr32.exe",
                     "bitsadmin.exe", "wmic.exe", "msbuild.exe"):
            self.assertIn(name, table)


class TestLookup(unittest.TestCase):
    def test_bare_name(self) -> None:
        record = ll.lookup("certutil.exe")
        self.assertIsNotNone(record)
        self.assertIn("Download", record["categories"])

    def test_case_insensitive(self) -> None:
        self.assertIsNotNone(ll.lookup("CertUtil.EXE"))

    def test_full_path_uses_filename_only(self) -> None:
        record = ll.lookup("C:\\Windows\\System32\\mshta.exe")
        self.assertIsNotNone(record)
        self.assertEqual(record["binary"].lower(), "mshta.exe")

    def test_forward_slashes_and_quotes(self) -> None:
        self.assertIsNotNone(ll.lookup('"C:/Windows/System32/regsvr32.exe"'))

    def test_non_lolbas_binary(self) -> None:
        self.assertIsNone(ll.lookup("ContosoAgentService.exe"))

    def test_empty_and_none(self) -> None:
        self.assertIsNone(ll.lookup(""))
        self.assertIsNone(ll.lookup("   "))
        self.assertIsNone(ll.lookup(None))

    def test_directory_only_input(self) -> None:
        self.assertIsNone(ll.lookup("C:\\Windows\\System32\\"))


class TestAbuseSummary(unittest.TestCase):
    def test_summary_names_binary_and_categories(self) -> None:
        text = ll.abuse_summary(ll.lookup("certutil.exe"))
        self.assertIn("Certutil.exe", text)
        self.assertIn("LOLBAS categories", text)
        self.assertIn("Download", text)

    def test_summary_includes_techniques(self) -> None:
        self.assertIn("T1105", ll.abuse_summary(ll.lookup("certutil.exe")))

    def test_summary_of_none_is_empty(self) -> None:
        self.assertEqual(ll.abuse_summary(None), "")

    def test_summary_tolerates_partial_record(self) -> None:
        self.assertIn("uncategorized", ll.abuse_summary({"binary": "x.exe"}))


class TestMitreTechniques(unittest.TestCase):
    def test_returns_technique_ids(self) -> None:
        techniques = ll.mitre_techniques(ll.lookup("regsvr32.exe"))
        self.assertIn("T1218.010", techniques)

    def test_none_yields_empty_list(self) -> None:
        self.assertEqual(ll.mitre_techniques(None), [])
        self.assertEqual(ll.mitre_techniques({}), [])


class TestNoImportCycle(unittest.TestCase):
    def test_lolbas_lookup_does_not_import_process_analyzer(self) -> None:
        """Aggregation imports Layer 2, so Layer 2 must never import back."""
        import ast
        import inspect

        imported: set[str] = set()
        for node in ast.walk(ast.parse(inspect.getsource(ll))):
            if isinstance(node, ast.Import):
                imported.update(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.add(node.module)
                imported.update(f"{node.module}.{alias.name}" for alias in node.names)

        offenders = {name for name in imported if "process_analyzer" in name}
        self.assertEqual(offenders, set(), f"import cycle risk: {offenders}")


if __name__ == "__main__":
    unittest.main()
