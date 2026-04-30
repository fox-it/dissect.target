from __future__ import annotations

import sys
from io import BytesIO
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest

pytest.importorskip("prompt_toolkit")

from prompt_toolkit.completion import CompleteEvent
from prompt_toolkit.document import Document

from dissect.target.helpers.completer import (
    QuotedPathCompleter,
    detect_path_input_style,
    get_current_word,
    unescape_path_input,
)
from dissect.target.target import Target
from dissect.target.tools.shell import TargetCli, TargetCmdCompleter
from tests._utils import absolute_path

if TYPE_CHECKING:
    from pathlib import Path

    from prompt_toolkit.completion import Completer


def _make_document(line: str) -> Document:
    """Helper function to create a Document with the cursor position indicated by a <TAB> marker in the input line."""
    cursor_marker = "<TAB>"
    cursor_position = line.find(cursor_marker)
    if cursor_position == -1:
        return Document(text=line, cursor_position=len(line))

    if line.count(cursor_marker) != 1:
        raise ValueError("line must contain at most one <TAB> marker")

    text = line.replace(cursor_marker, "", 1)
    return Document(text=text, cursor_position=cursor_position)


def _get_completion_texts(completer: Completer, line: str) -> list[str]:
    """Helper function to get list of completion texts from a Completer for a given input line with a <TAB> marker."""
    document = _make_document(line)
    complete_event = CompleteEvent(completion_requested=True)
    return [c.text for c in completer.get_completions(document, complete_event)]


def test_local_path_completion_with_unclosed_double_quote(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that local path completion works correctly when the user has typed an unclosed double quote."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "my file.txt").write_text("x")
    (tmp_path / "my folder").mkdir()

    completer = QuotedPathCompleter()
    completions = sorted(_get_completion_texts(completer, 'cat "my<TAB>'))

    assert completions == ['"my file.txt"', '"my folder/"']


@pytest.mark.skipif(
    sys.platform.startswith("win"),
    reason="Windows filesystems do not allow double quotes in local filenames",
)
def test_local_path_completion_escapes_quote_char(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that a quote character in a filename is properly escaped in the completion suggestions."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / 'a"b.txt').write_text("x")

    completer = QuotedPathCompleter()
    completions = _get_completion_texts(completer, 'cat "a<TAB>')

    assert '"a\\"b.txt"' in completions


def test_local_path_completion_handles_escaped_spaces(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that quoted local path completion accepts backslash-escaped spaces in the typed input."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "System Volume Information").mkdir()

    completer = QuotedPathCompleter()
    completions = _get_completion_texts(completer, 'cat "System\\ Volume Information<TAB>')

    assert '"System Volume Information/"' in completions


def test_local_path_completion_handles_generic_escaped_characters(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test that quoted local path completion accepts arbitrary backslash-escaped characters in the typed input."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "files").mkdir()

    completer = QuotedPathCompleter()
    completions = _get_completion_texts(completer, 'save -o "fi\\l<TAB>')

    assert '"files/"' in completions


def test_local_path_completion_handles_trailing_backslash_escape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test that an unfinished escape at the cursor still matches the intended path prefix."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "files").mkdir()

    completer = QuotedPathCompleter()
    completions = _get_completion_texts(completer, "stat file\\<TAB>")

    assert "files/" in completions


def test_get_current_word_keeps_trailing_escaped_space_in_quotes() -> None:
    """Test that a trailing space inside an open quoted token is still part of the current word."""
    assert get_current_word('save -o "/tmp/System\\ ') == '"/tmp/System\\ '


def test_detect_path_input_style_uses_input_shape_for_windows_paths() -> None:
    """Test that Windows-like local paths are detected from the typed token itself."""
    assert detect_path_input_style(r"C:\\Temp\\fi", target=False) == "windows"
    assert detect_path_input_style(r"\\\\server\\share\\fi", target=False) == "windows"


def test_detect_path_input_style_defaults_to_posix_without_os_checks() -> None:
    """Test that ambiguous local input defaults to POSIX semantics and target paths stay POSIX-like."""
    assert detect_path_input_style("./files", target=False) == "posix"
    assert detect_path_input_style(r"C:\\Temp\\fi", target=True) == "posix"


def test_unescape_path_input_keeps_backslashes_for_windows_like_input() -> None:
    """Test that Windows-like local path input does not treat backslashes as generic escapes."""
    assert unescape_path_input(r"C:\\Temp\\fi", "windows") == r"C:\\Temp\\fi"
    assert unescape_path_input(r"\\\\server\\share\\fi", "windows") == r"\\\\server\\share\\fi"


def test_unescape_path_input_still_unescapes_posix_shell_input() -> None:
    """Test that POSIX-like input still interprets backslashes as shell escapes for matching."""
    assert unescape_path_input(r"System\ Volume", "posix") == "System Volume"
    assert unescape_path_input("file\\", "posix") == "file"
    assert unescape_path_input("file\\s", "posix") == "files"


def test_target_path_completion_with_unclosed_double_quote(target_bare: Target) -> None:
    """Test that target path completion works correctly when the user has typed an unclosed double quote."""
    target_bare.fs.root.makedirs("/evidence dir")
    target_bare.fs.root.map_file_fh("/evidence dir/file one.txt", BytesIO(b"x"))

    cli = SimpleNamespace(cwd=target_bare.fs.path("/"))
    completer = QuotedPathCompleter(cli=cli, target=target_bare)
    completions = _get_completion_texts(completer, 'ls "/evi<TAB>')

    assert completions == ['"/evidence dir/"']


def test_target_path_completion_respects_target_cwd(target_bare: Target) -> None:
    """Test that target path completion respects the target's current working directory."""
    target_bare.fs.root.makedirs("/cases")
    target_bare.fs.root.map_file_fh("/cases/report one.txt", BytesIO(b"x"))

    cli = SimpleNamespace(cwd=target_bare.fs.path("/cases"))
    completer = QuotedPathCompleter(cli=cli, target=target_bare)
    completions = _get_completion_texts(completer, 'cat "rep<TAB>')

    assert completions == ['"report one.txt"']


def test_target_path_completion_handles_escaped_spaces(target_bare: Target) -> None:
    """Test that quoted target path completion accepts backslash-escaped spaces in the typed input."""
    target_bare.fs.root.makedirs("/tmp/System Volume Information")

    cli = SimpleNamespace(cwd=target_bare.fs.path("/"))
    completer = QuotedPathCompleter(cli=cli, target=target_bare)
    completions = _get_completion_texts(completer, 'ls "/tmp/System\\ Volume Information<TAB>')

    assert completions == ['"/tmp/System Volume Information/"']


@pytest.mark.parametrize(
    ("quote", "filename", "prefix", "expected_completion"),
    [
        ("'", "apostrophe's note.txt", "apostrophe", "'apostrophe\\'s note.txt'"),
        pytest.param(
            '"',
            'doubleq"note.txt',
            "doubleq",
            '"doubleq\\"note.txt"',
            marks=pytest.mark.skipif(
                sys.platform.startswith("win"),
                reason="Windows filesystems do not allow double quotes in local filenames",
            ),
        ),
    ],
)
def test_local_path_completion_quote_matrix(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    quote: str,
    filename: str,
    prefix: str,
    expected_completion: str,
) -> None:
    """Test that local path completion correctly handles filenames with quotes, for both single and double quotes."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / filename).write_text("x")

    completer = QuotedPathCompleter()
    completions = _get_completion_texts(completer, f"cat {quote}{prefix}<TAB>")

    assert expected_completion in completions


@pytest.mark.parametrize(
    ("quote", "filename", "prefix", "expected_completion"),
    [
        ("'", "apostrophe's note.txt", "apostrophe", "'/vault/apostrophe\\'s note.txt'"),
        ('"', 'doubleq"note.txt', "doubleq", '"/vault/doubleq\\"note.txt"'),
    ],
)
def test_target_path_completion_quote_matrix(
    target_bare: Target,
    quote: str,
    filename: str,
    prefix: str,
    expected_completion: str,
) -> None:
    """Test that target path completion correctly handles filenames with quotes, for both single and double quotes."""
    target_bare.fs.root.makedirs("/vault")
    target_bare.fs.root.map_file_fh(f"/vault/{filename}", BytesIO(b"x"))

    cli = SimpleNamespace(cwd=target_bare.fs.path("/"))
    completer = QuotedPathCompleter(cli=cli, target=target_bare)
    completions = _get_completion_texts(completer, f"ls {quote}/vault/{prefix}<TAB>")

    assert expected_completion in completions


@pytest.mark.parametrize(
    ("quote", "line", "expected_completion"),
    [
        ('"', 'cat "case<TAB>', '"case notes/"'),
        ("'", "cat 'case<TAB>", "'case notes/'"),
    ],
)
def test_local_path_completion_unclosed_quote_directory_trailing_slash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    quote: str,
    line: str,
    expected_completion: str,
) -> None:
    """Test that local path completion correctly completes a directory name with a /, even with unclosed quote."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "case notes").mkdir()

    completer = QuotedPathCompleter()
    completions = _get_completion_texts(completer, line)

    assert expected_completion in completions


@pytest.mark.parametrize(
    ("quote", "line", "expected_completion"),
    [
        ('"', 'ls "/cases/for<TAB>', '"/cases/for review/"'),
        ("'", "ls '/cases/for<TAB>", "'/cases/for review/'"),
    ],
)
def test_target_path_completion_unclosed_quote_directory_trailing_slash(
    target_bare: Target,
    quote: str,
    line: str,
    expected_completion: str,
) -> None:
    """Test that target path completion correctly completes a directory name with a /, even with unclosed quote."""
    target_bare.fs.root.makedirs("/cases/for review")

    cli = SimpleNamespace(cwd=target_bare.fs.path("/"))
    completer = QuotedPathCompleter(cli=cli, target=target_bare)
    completions = _get_completion_texts(completer, line)

    assert expected_completion in completions


def test_completion_helper_accepts_cursor_marker_mid_line(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that the completion helper correctly handles a cursor marker in the middle of a line."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "cases").mkdir()
    (tmp_path / "cases" / "for review").mkdir()

    completer = QuotedPathCompleter()
    completions = _get_completion_texts(completer, 'ls "cases/<TAB>" ../files/README.txt')

    assert '"cases/for review/"' in completions


def test_completion_argparser_integration(target_bare: Target, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test ArgumentParser completer integration with different edge cases around quoting and cursor position."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "my folder").mkdir()
    (tmp_path / "my folder/cat pictures").mkdir()
    (tmp_path / "my folder/downloads").mkdir()
    (tmp_path / "System Volume Information").mkdir(parents=True)
    (tmp_path / "mynotes.txt").touch()

    target_cli = TargetCli(target_bare)
    completer = TargetCmdCompleter(target_cli)

    target_bare.fs.root.makedirs("/System Volume 1")
    target_bare.fs.root.makedirs("/System32")
    target_bare.fs.root.map_file_fh("/System Volume 1/file one.txt", BytesIO(b"1"))
    target_bare.fs.root.map_file_fh("/System Volume 1/file two.txt", BytesIO(b"2"))
    target_bare.fs.root.map_file_fh("/System Volume 1/README.txt", BytesIO(b"readme"))
    target_bare.fs.root.map_file_fh("/System32/kernel32.dll", BytesIO(b"kernel"))

    # quoted path completion (mid quote)
    completions = set(_get_completion_texts(completer, 'tar -cf "my<TAB>"'))
    assert completions == {'"my folder/"', '"mynotes.txt"'}

    # unquoted path completion, but with the cursor in the middle of the argument
    completions = set(_get_completion_texts(completer, "tar -cf my<TAB>"))
    assert completions == {'"my folder/"', "mynotes.txt"}

    # unquoted path completion, with the cursor in the middle of the argument and a suffix after the cursor
    completions = set(_get_completion_texts(completer, "tar -cf my<TAB>t"))
    assert completions == {'"my folder/"', "mynotes.txt"}

    # quoted path completion, with the cursor after the quoted completion directory
    completions = set(_get_completion_texts(completer, 'tar -cf "my folder/"<TAB>'))
    assert completions == {'"my folder/cat pictures/"', '"my folder/downloads/"'}

    # quoted relative path completion, with the cursor after the quoted completion directory
    completions = set(_get_completion_texts(completer, 'tar -cf "./my folder/"<TAB>'))
    assert completions == {
        '"./my folder/cat pictures/"',
        '"./my folder/downloads/"',
    }

    # tab completion for the target path items
    completions = set(_get_completion_texts(completer, 'tar -cf "my folder/" <TAB>'))
    assert completions == {'"System Volume 1/"', "System32/"}

    # tab completion for the target path (mid quote)
    completions = set(_get_completion_texts(completer, 'tar -cf "my folder/" "System<TAB>'))
    assert completions == {'"System Volume 1/"', '"System32/"'}

    # tab completion for the target path (mid quote, with space)
    completions = set(_get_completion_texts(completer, 'tar -cf "my folder/" "System V<TAB>'))
    assert completions == {'"System Volume 1/"'}

    # tab completion for the target path (mid quote, with space)
    completions = set(_get_completion_texts(completer, 'tar -cf "my folder/<TAB>" "System32"'))
    assert completions == {'"my folder/cat pictures/"', '"my folder/downloads/"'}

    # tab completion for relative local path
    monkeypatch.chdir(tmp_path / "my folder")
    completions = set(_get_completion_texts(completer, 'tar -cf "../my folder/<TAB>"'))
    assert completions == {
        '"../my folder/cat pictures/"',
        '"../my folder/downloads/"',
    }

    # quoted local path completion with escaped trailing space should keep completing -o
    monkeypatch.chdir(tmp_path)
    completions = set(_get_completion_texts(completer, 'tar -cf "./System\\ <TAB>'))
    assert completions == {'"./System Volume Information/"'}

    # target absolute path completion
    completions = set(_get_completion_texts(completer, "tar /System3<TAB>"))
    assert completions == {"/System32/"}

    # target absolute path completion with quote
    completions = set(_get_completion_texts(completer, 'tar "/System3<TAB>'))
    assert completions == {'"/System32/"'}

    # local path completion positional args
    monkeypatch.chdir(tmp_path / "my folder")
    completions = set(_get_completion_texts(completer, "tar /System32 mynotes.txt -cf <TAB>"))
    assert completions == {'"cat pictures/"', "downloads/"}

    # target path completion positional args (second path as argument)
    completions = set(
        _get_completion_texts(completer, 'tar /System32 "/System Volume 1/<TAB> -cf downloads/export.tar')
    )
    assert completions == {
        '"/System Volume 1/README.txt"',
        '"/System Volume 1/file one.txt"',
        '"/System Volume 1/file two.txt"',
    }


def test_completion_target_relative() -> None:
    """Test relative path completion for a target using ``cd`` command."""
    target = Target.open(absolute_path("_data/tools/shell/unicode.tar"), apply=True)
    target_cli = TargetCli(target)
    completer = TargetCmdCompleter(target_cli)

    completions = set(_get_completion_texts(completer, "cd ./<TAB>"))
    assert completions == {
        "./unicode/",
    }

    target_cli.onecmd("cd /unicode/charsets")
    assert str(target_cli.cwd) == "/unicode/charsets"

    completions = set(_get_completion_texts(completer, "cd <TAB>"))
    assert completions == {"ħēļľŏ/", "привет/", "🕵🕵🕵/", "你好/", "مرحبًا/", "hello/"}

    completions = set(_get_completion_texts(completer, "cd ../<TAB>"))
    assert completions == {
        "../charsets/",
    }


def test_completion_local_relative(target_bare: Target, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test relative path completion for a local path using ``lcd`` command."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "one/two/three/four").mkdir(parents=True)
    (tmp_path / "one/2").touch()
    (tmp_path / "one/two/3").touch()
    (tmp_path / "one/two/three/4").touch()

    target_cli = TargetCli(target_bare)
    completer = TargetCmdCompleter(target_cli)

    completions = set(_get_completion_texts(completer, "lcd <TAB>"))
    assert "one/" in completions

    completions = set(_get_completion_texts(completer, "lcd one/<TAB>"))
    assert completions == {
        "one/2",
        "one/two/",
    }

    target_cli.onecmd("lcd one/two")
    completions = set(_get_completion_texts(completer, "lcd ../<TAB>"))
    assert completions == {
        "../2",
        "../two/",
    }
    completions = set(_get_completion_texts(completer, "lcd ./<TAB>"))
    assert completions == {
        "./3",
        "./three/",
    }

    target_cli.onecmd("lcd three/four")
    completions = set(_get_completion_texts(completer, "lcd ../../../<TAB>"))
    assert completions == {
        "../../../two/",
        "../../../2",
    }
    completions = set(_get_completion_texts(completer, "lcd ../../<TAB>"))
    assert completions == {
        "../../three/",
        "../../3",
    }
