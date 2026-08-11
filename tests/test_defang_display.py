"""Tests for the Threat Indicators badge defanging.

Two defects fixed at once, which is why this is asserted rather than eyeballed:
a live link to attacker infrastructure in a triage UI, and a rendering bug where
Streamlit's markdown linkifier nested an anchor inside the badge's own anchor,
emptying the coloured box and spilling the URL outside it.
"""
from __future__ import annotations

import unittest

from ui.components.ai_panel import defang_for_display


class TestDefang(unittest.TestCase):
    def test_url_scheme_and_host_are_neutralised(self) -> None:
        self.assertEqual(
            defang_for_display("http://198.51.100.7/a.ps1"),
            "hxxp://198[.]51[.]100[.]7/a.ps1",
        )

    def test_https_keeps_its_s(self) -> None:
        self.assertEqual(
            defang_for_display("https://evil.example.com/x?a=1"),
            "hxxps://evil[.]example[.]com/x?a=1",
        )

    def test_path_stays_readable(self) -> None:
        # Only the host is altered — an analyst still needs to read the path.
        self.assertIn("/downloads/stage2.ps1", defang_for_display(
            "http://evil.example.com/downloads/stage2.ps1"))

    def test_bare_ip(self) -> None:
        self.assertEqual(defang_for_display("198.51.100.7"), "198[.]51[.]100[.]7")

    def test_bare_domain(self) -> None:
        self.assertEqual(defang_for_display("evil.example.com"), "evil[.]example[.]com")

    def test_hash_is_untouched(self) -> None:
        digest = "44d88612fea8a8f36de82e1278abb02f"
        self.assertEqual(defang_for_display(digest), digest)

    def test_empty_and_none(self) -> None:
        self.assertEqual(defang_for_display(""), "")
        self.assertEqual(defang_for_display(None), "")

    def test_result_contains_no_linkifiable_url(self) -> None:
        # The actual fix for the empty-badge bug: nothing the markdown
        # linkifier will turn into an <a>, so the badge's own anchor stays valid.
        import re
        for value in (
            "http://198.51.100.7/a.ps1",
            "https://evil.example.com/x",
            "evil.example.com",
        ):
            with self.subTest(value=value):
                out = defang_for_display(value)
                self.assertIsNone(re.search(r"https?://", out))
                self.assertNotIn("</a>", out)

    def test_idempotent_enough_to_re_render(self) -> None:
        # Streamlit re-renders on every interaction; defanging an already
        # defanged value must not corrupt it further.
        once = defang_for_display("http://198.51.100.7/a.ps1")
        self.assertEqual(defang_for_display(once), once)


if __name__ == "__main__":
    unittest.main()
