"""Tests for core.decode_common — the shared decode primitives.

Per ``docs/waf_payload_analyzer.md`` D2, this module exists so that two
consumers with *different calibrations* can share one implementation. The
existing command-line suite already proves the extraction preserved that
module's behaviour; what these tests prove is the other half — that a profile
actually changes what gets decoded, so the WAF module will not silently inherit
command-line assumptions that would blind it.

Every profile below is built inline. No named web profile is exported yet: its
values are a calibration question (plan §6, Milestone C), and a constant
invented here would be a guess with a name.
"""
from __future__ import annotations

import base64
import unittest

from core import decode_common as dc

# Command-line calibration, mirroring core.cmdline_deobfuscator._PROFILE.
STRICT = dc.DecodeProfile(
    min_encoding_hits=2,
    min_b64_inline=24,
    b64_require_command_shape=True,
    b64_utf16_first=True,
)

# The looser end of the range a web payload will need. Not a proposed WAF
# profile — a second point on the axis, enough to show the axis is real.
LOOSE = dc.DecodeProfile(
    min_encoding_hits=1,
    min_b64_inline=16,
    b64_require_command_shape=False,
    b64_utf16_first=False,
)


class TestEncodingThreshold(unittest.TestCase):
    """min_encoding_hits is the field the WAF module most needs to lower."""

    def test_single_percent_sequence_needs_the_loose_profile(self) -> None:
        # A SQLi payload carrying exactly one encoded quote. The strict profile
        # must ignore it (that is what keeps %SystemRoot% intact for the command
        # line); the loose profile must decode it, or the whole payload class is
        # invisible to lexical matching.
        payload = "id=1%27 OR 1=1"

        strict_text, strict_changed = dc.decode_percent(payload, STRICT)
        self.assertFalse(strict_changed)
        self.assertEqual(strict_text, payload)

        loose_text, loose_changed = dc.decode_percent(payload, LOOSE)
        self.assertTrue(loose_changed)
        self.assertIn("1' OR 1=1", loose_text)

    def test_two_sequences_decode_under_both_profiles(self) -> None:
        for profile in (STRICT, LOOSE):
            with self.subTest(min_hits=profile.min_encoding_hits):
                text, changed = dc.decode_percent("%63%61lc", profile)
                self.assertTrue(changed)
                self.assertEqual(text, "calc")

    def test_environment_variable_is_never_percent_decoded(self) -> None:
        # %SystemRoot% has no valid two-hex-digit sequence at all, so it is safe
        # under *both* profiles. Worth pinning: the loose profile is the one that
        # would corrupt it if the guard were only the hit count.
        for profile in (STRICT, LOOSE):
            with self.subTest(min_hits=profile.min_encoding_hits):
                text, changed = dc.decode_percent(r"copy %SystemRoot%\np.exe", profile)
                self.assertFalse(changed)
                self.assertEqual(text, r"copy %SystemRoot%\np.exe")

    def test_single_html_entity_needs_the_loose_profile(self) -> None:
        payload = "<img src=x onerror=alert&#40;1)>"
        self.assertFalse(dc.decode_html_entities(payload, STRICT)[1])
        self.assertEqual(
            dc.decode_html_entities(payload, LOOSE)[0],
            "<img src=x onerror=alert(1)>",
        )

    def test_named_entities_are_never_decoded(self) -> None:
        # html.unescape would turn "&copy" into a copyright sign, corrupting
        # "dir&copy a b". Numeric entities only, under every profile.
        for profile in (STRICT, LOOSE):
            with self.subTest(min_hits=profile.min_encoding_hits):
                text, changed = dc.decode_html_entities("dir&copy a &amp b", profile)
                self.assertFalse(changed)
                self.assertIn("&copy", text)

    def test_single_unicode_escape_needs_the_loose_profile(self) -> None:
        self.assertFalse(dc.decode_escapes(r"abc", STRICT)[1])
        self.assertEqual(dc.decode_escapes(r"abc", LOOSE)[0], "abc")

    def test_hex_escapes_decode_independently_of_unicode_escapes(self) -> None:
        text, changed = dc.decode_escapes(r"\x63\x61\x6c\x63", STRICT)
        self.assertTrue(changed)
        self.assertEqual(text, "calc")


class TestBase64Decoding(unittest.TestCase):
    # 24 letters, no command markers at all — the shape gate's target case.
    OPAQUE_WORD = "abcdefghijklmnopqrstuvwx"
    OPAQUE_B64 = base64.b64encode(OPAQUE_WORD.encode()).decode()

    def test_command_shape_gate_rejects_a_markerless_decode(self) -> None:
        # The strict profile refuses this because a decoded blob with no spaces,
        # dots or slashes is more likely a lucky base64-shaped word than a
        # recovered command.
        self.assertIsNone(dc.b64_decode_text(
            self.OPAQUE_B64, require_command_shape=True, utf16_first=True,
        ))

    def test_command_shape_gate_disabled_accepts_it(self) -> None:
        # A web payload has no command shape to find, so the gate must be
        # switchable or base64-in-a-query-parameter never decodes.
        self.assertEqual(
            dc.b64_decode_text(
                self.OPAQUE_B64, require_command_shape=False, utf16_first=False,
            ),
            self.OPAQUE_WORD,
        )

    def test_utf16_first_is_a_preference_not_a_capability(self) -> None:
        # A UTF-16LE blob decoded as UTF-8 yields NUL-interleaved text, which
        # fails the printable-ratio check and falls through to UTF-16LE. So
        # b64_utf16_first changes which encoding is *tried* first, not which
        # payloads can be recovered. Pinning this stops a future reader from
        # assuming the WAF module cannot read a UTF-16LE blob.
        blob = base64.b64encode("whoami /all".encode("utf-16-le")).decode()
        for utf16_first in (True, False):
            with self.subTest(utf16_first=utf16_first):
                decoded = dc.b64_decode_text(
                    blob, require_command_shape=False, utf16_first=utf16_first,
                )
                self.assertEqual(decoded, "whoami /all")

    def test_binary_payload_is_rejected_as_not_text(self) -> None:
        # Invalid UTF-8, and an odd byte count so the UTF-16LE fallback cannot
        # decode it either.
        blob = base64.b64encode(bytes([0xFF, 0xFE, 0x80, 0x81, 0x00])).decode()
        self.assertIsNone(dc.b64_decode_text(
            blob, require_command_shape=False, utf16_first=False,
        ))

    def test_known_gap_utf16_fallback_rescues_low_byte_binary(self) -> None:
        # Documented, not endorsed. Low-byte binary is invalid as text under
        # UTF-8 (control characters fail the printable ratio), but an even-length
        # run reinterpreted as UTF-16LE yields exotic-but-printable code points
        # that pass. With require_command_shape=True the command-line module is
        # protected downstream; a WAF payload, which cannot use that gate, is
        # not. This is pre-existing shipped behaviour, left unchanged here so the
        # command-line module keeps its calibration, and carried into the plan's
        # open items for the Milestone B threshold work.
        blob = base64.b64encode(bytes(range(0, 40))).decode()

        self.assertIsNone(dc.b64_decode_text(
            blob, require_command_shape=True, utf16_first=False,
        ))
        self.assertIsNotNone(dc.b64_decode_text(
            blob, require_command_shape=False, utf16_first=False,
        ))

    def test_invalid_and_empty_input_return_none(self) -> None:
        for candidate in ("not base64!", "", "   ", "===="):
            with self.subTest(candidate=candidate):
                self.assertIsNone(dc.b64_decode_text(
                    candidate, require_command_shape=False, utf16_first=False,
                ))

    def test_inline_length_floor_is_profile_controlled(self) -> None:
        # 18 chars of base64 — above LOOSE's floor of 16, below STRICT's 24.
        word = "cat /etc/passwd"
        blob = base64.b64encode(word.encode()).decode()
        self.assertGreaterEqual(len(blob), LOOSE.min_b64_inline)
        self.assertLess(len(blob), STRICT.min_b64_inline)

        self.assertFalse(dc.decode_base64_inline(blob, STRICT)[1])
        text, changed = dc.decode_base64_inline(blob, LOOSE)
        self.assertTrue(changed)
        self.assertEqual(text, word)

    def test_surrounding_text_survives_an_inline_decode(self) -> None:
        blob = base64.b64encode("cat /etc/passwd".encode()).decode()
        text, changed = dc.decode_base64_inline(f"cmd={blob}&x=1", LOOSE)
        self.assertTrue(changed)
        self.assertEqual(text, "cmd=cat /etc/passwd&x=1")


class TestLooksLikeText(unittest.TestCase):
    def test_empty_is_not_text(self) -> None:
        self.assertFalse(dc.looks_like_text(""))

    def test_tabs_and_newlines_count_as_printable(self) -> None:
        self.assertTrue(dc.looks_like_text("line one\r\n\tline two"))

    def test_mostly_control_characters_is_not_text(self) -> None:
        self.assertFalse(dc.looks_like_text("ok\x00\x01\x02\x03\x04\x05\x06\x07"))


class TestRunPipeline(unittest.TestCase):
    @staticmethod
    def _upper_once(text: str) -> tuple[str, bool]:
        """Idempotent transform: fires on the first round only."""
        return text.upper(), text != text.upper()

    def test_chain_is_empty_when_nothing_fires(self) -> None:
        run = dc.run_pipeline("ABC", (("upper", self._upper_once),), STRICT)
        self.assertEqual(run.chain, [])
        self.assertEqual(run.rounds, 0)
        self.assertEqual(run.text, "ABC")
        self.assertFalse(run.truncated)

    def test_chain_records_labels_in_application_order(self) -> None:
        payload = "%3cscript%3e&#40;&#41;"
        run = dc.run_pipeline(
            payload,
            (
                (dc.LABEL_PERCENT, lambda t: dc.decode_percent(t, LOOSE)),
                (dc.LABEL_HTML_ENTITIES, lambda t: dc.decode_html_entities(t, LOOSE)),
            ),
            LOOSE,
        )
        self.assertEqual(run.chain[:2], [dc.LABEL_PERCENT, dc.LABEL_HTML_ENTITIES])
        self.assertEqual(run.text, "<script>()")

    def test_transforms_compose_within_a_single_round(self) -> None:
        # Percent wrapping entities resolves in one pass, because percent runs
        # ahead of entities in the transform order.
        run = dc.run_pipeline(
            "%26%2340%3B",
            (
                (dc.LABEL_PERCENT, lambda t: dc.decode_percent(t, LOOSE)),
                (dc.LABEL_HTML_ENTITIES, lambda t: dc.decode_html_entities(t, LOOSE)),
            ),
            LOOSE,
        )
        self.assertEqual(run.text, "(")
        self.assertEqual(run.rounds, 1)

    def test_layered_encoding_reaches_a_fixed_point(self) -> None:
        # The nesting the transform order does *not* anticipate: entities
        # wrapping percent-encoding, so entities must decode before percent can
        # see anything. Only the driver's iteration resolves this, which is the
        # whole reason it loops rather than making one pass.
        payload = "&#37;28&#37;29"
        run = dc.run_pipeline(
            payload,
            (
                (dc.LABEL_PERCENT, lambda t: dc.decode_percent(t, LOOSE)),
                (dc.LABEL_HTML_ENTITIES, lambda t: dc.decode_html_entities(t, LOOSE)),
            ),
            LOOSE,
        )
        self.assertEqual(run.text, "()")
        self.assertGreaterEqual(run.rounds, 2)

    def test_round_cap_is_enforced(self) -> None:
        capped = dc.DecodeProfile(max_rounds=3)
        run = dc.run_pipeline("x", (("grow", lambda t: (t + "x", True)),), capped)
        self.assertEqual(run.rounds, 3)
        self.assertEqual(run.text, "xxxx")

    def test_output_size_cap_truncates_and_stops(self) -> None:
        capped = dc.DecodeProfile(max_rounds=10, max_bytes=50)
        run = dc.run_pipeline("x", (("double", lambda t: (t * 4, True)),), capped)
        self.assertTrue(run.truncated)
        self.assertEqual(len(run.text), 50)

    def test_a_raising_transform_is_skipped_not_fatal(self) -> None:
        def _boom(_text: str) -> tuple[str, bool]:
            raise ValueError("malformed construct")

        run = dc.run_pipeline(
            "abc",
            (("boom", _boom), ("upper", self._upper_once)),
            STRICT,
        )
        # The surviving transform still applied, and the failed one contributed
        # nothing to the chain — a decode chain must not claim a step that threw.
        self.assertEqual(run.text, "ABC")
        self.assertEqual(run.chain, ["upper"])

    def test_input_string_is_never_mutated(self) -> None:
        payload = "%63%61lc"
        run = dc.run_pipeline(
            payload,
            ((dc.LABEL_PERCENT, lambda t: dc.decode_percent(t, STRICT)),),
            STRICT,
        )
        self.assertEqual(payload, "%63%61lc")
        self.assertEqual(run.text, "calc")


class TestProfileDefaults(unittest.TestCase):
    def test_defaults_match_the_command_line_calibration(self) -> None:
        # The defaults are the strict, command-line values on purpose: a caller
        # that forgets to pass a profile gets the conservative behaviour, not the
        # permissive one.
        from core import cmdline_deobfuscator as dob

        default = dc.DecodeProfile()
        self.assertEqual(default.min_encoding_hits, dob._PROFILE.min_encoding_hits)
        self.assertEqual(default.min_b64_inline, dob._PROFILE.min_b64_inline)
        self.assertTrue(default.b64_require_command_shape)
        self.assertTrue(default.b64_utf16_first)

    def test_profile_is_immutable(self) -> None:
        # Shared across two modules and cached by lru_cache on min_b64_inline —
        # a mutable profile would let one consumer retune the other's decoder.
        with self.assertRaises(Exception):
            STRICT.min_encoding_hits = 1  # type: ignore[misc]


if __name__ == "__main__":
    unittest.main()
