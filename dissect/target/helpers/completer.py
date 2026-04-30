from __future__ import annotations

import argparse
import copy
import os
import re
import shlex
from pathlib import Path
from typing import TYPE_CHECKING

from prompt_toolkit.completion import Completer, Completion

if TYPE_CHECKING:
    import cmd
    from collections.abc import Callable, Iterable
    from typing import Literal

    from prompt_toolkit.completion import CompleteEvent
    from prompt_toolkit.document import Document

    from dissect.target import Target


def split_words(text: str) -> list[str]:
    """Split the text into words, but handle unclosed quotes gracefully."""
    try:
        return shlex.split(text)
    except ValueError:
        # only fix if there's actually an unclosed quote
        last_open = max(text.rfind('"'), text.rfind("'"))
        if last_open != -1:
            quote_char = text[last_open]
            # check if it's actually unclosed (odd number of that quote after last_open)
            after = text[last_open + 1 :]
            if after.count(quote_char) % 2 == 0:  # even means unclosed
                try:
                    return shlex.split(text + quote_char)
                except ValueError:
                    pass
        return text.split()


def quote_path_for_completion(path: str, preferred_quote: str = "") -> str:
    """Quote and escape a completion path when needed."""
    if not preferred_quote and " " not in path:
        return path

    q = preferred_quote or '"'
    escaped = path.replace(q, f"\\{q}")
    return f"{q}{escaped}{q}"


def get_quoted_word_context(text_before: str) -> tuple[str, str, str]:
    """Extract quote info and text from the text before cursor.

    Parses quoted and unquoted words, handling both single and double quotes.
    Supports escaped quotes within the quoted string.

    Returns:
        (quote, word, text) where:
        - quote: the quote character ('"' or "'"), or empty string if not quoted
        - word: the raw word including quotes (used for calculating start_position)
        - text: the raw inner content before path-style-specific unescaping
    """
    quote = ""
    word = ""
    text = ""

    for q in ('"', "'"):
        idx = text_before.rfind(q)
        if idx == -1:
            continue

        # Find the matching opening quote
        open_idx = text_before.rfind(q, 0, idx)
        if open_idx == -1:
            # Only one quote found — it's an opening quote
            quote = q
            word = text_before[idx:]
            inner = word[1:]
            text = inner
            break
        # Two quotes found — check if cursor is inside or just after them
        quote = q
        word = text_before[open_idx:]
        inner = word[1 : word.rfind(q)]
        text = inner
        break

    return quote, word, text


def detect_path_input_style(text: str, *, target: bool) -> Literal["windows", "posix"]:
    """Infer path syntax from the typed token itself.

    Target paths are always treated as POSIX-like. Local paths that look like
    drive-letter or UNC paths are treated as Windows-like.
    """
    # If we have a target, we assume POSIX-style paths, since that's what TargetPath uses.
    if target:
        return "posix"

    # Drive-letter paths start with a letter followed by a colon and a slash or backslash, e.g. C:\ or D:/
    if re.match(r"^[A-Za-z]:[\\/]", text):
        return "windows"

    # UNC paths start with double backslashes
    if text.startswith("\\\\"):
        return "windows"

    return "posix"


def unescape_path_input(text: str, style: Literal["windows", "posix"], quote: str = "") -> str:
    """Normalize typed path text for completion matching."""
    if style == "windows":
        if quote:
            return text.replace(f"\\{quote}", quote)
        return text

    text = re.sub(r"\\(.)", r"\1", text)

    # If the cursor is right after a backslash, treat it as an incomplete escape.
    return text.removesuffix("\\")


def get_current_word(text: str) -> str:
    """Extract the current (last) word from text, preserving quotes."""
    if not text:
        return ""

    # Track token boundaries while respecting quotes and escaped quote characters.
    token_start = 0
    in_quote = ""
    escaped = False

    for i, ch in enumerate(text):
        if escaped:
            escaped = False
            continue

        if ch == "\\":
            escaped = True
            continue

        if ch in ('"', "'"):
            if in_quote == ch:
                in_quote = ""
            elif not in_quote:
                in_quote = ch
            continue

        if not in_quote and ch in (" ", "="):
            token_start = i + 1

    return text[token_start:]


class SilentArgumentParser(argparse.ArgumentParser):
    """ArgumentParser that doesn't print anything on error or exit, so we can use it for autocompletion."""

    def error(self, message: str) -> None:
        raise argparse.ArgumentError(None, message)

    def exit(self, status: int = 0, message: str | None = None) -> None:
        pass

    def get_completing_action(self, args: argparse.Namespace, sentinel: str) -> argparse.Action | None:
        """Find the action whose dest contains the sentinel value."""
        return next(
            (
                action
                for action in self._actions
                if (val := getattr(args, action.dest, None)) == sentinel or (isinstance(val, list) and sentinel in val)
            ),
            None,
        )


def make_completion_parser(parser: argparse.ArgumentParser) -> SilentArgumentParser:
    """Make a copy of the given ArgumentParser, but relax it so that it can be used for autocompletion.

    - Make all arguments optional (required=False)
    - Relax nargs='+' to nargs='*'
    - Remove all types (type=None) so that we can do custom type handling in the completer.
    - Store the original types in a separate dict (dest_types) so that we can access them in the completer.
    """
    new_parser = SilentArgumentParser(add_help=False)
    new_parser.dest_types = {}  # store types here
    for action in parser._actions:
        if isinstance(action, argparse._HelpAction):
            continue
        new_parser.dest_types[action.dest] = action.type  # save type
        action_copy = copy.copy(action)
        action_copy.type = None
        action_copy.required = False
        if action.nargs == "+":
            action_copy.nargs = "*"  # relax nargs=+ to nargs=*
        new_parser._actions.append(action_copy)
        if action.option_strings:
            new_parser._option_string_actions.update(dict.fromkeys(action.option_strings, action_copy))
        else:
            # register positional properly
            new_parser._positionals._group_actions.append(action_copy)
    return new_parser


class QuotedPathCompleter(Completer):
    """Complete for Path or TargetPath variables.

    This class is modeled after the PathCompleter from prompt_toolkit, but adapted to work with the
    pathlib Path paths, which makes it work for both local and TargetPath paths.

    It also adds support for quoting paths with spaces.
    """

    def __init__(
        self,
        cli: cmd.Cmd | None = None,
        target: Target | None = None,
        only_directories: bool = False,
        file_filter: Callable[[str], bool] | None = None,
        expanduser: bool = True,
    ) -> None:
        self.cli = cli
        self.target = target
        self.only_directories = only_directories
        self.file_filter = file_filter or (lambda _: True)
        self.expanduser = expanduser

    def _make_path(self, path: str) -> Path:
        """Create a Path object from the given path string, using the target's path function if available."""
        if self.target:
            return self.target.fs.path(path)
        return Path(path)

    def _resolve_path(self, path: str) -> Path:
        """Resolve the given path to an absolute Path object, using the target's path function if available."""
        p = self._make_path(path)
        if not p.is_absolute():
            cwd = self.cli.cwd if self.target else Path.cwd()
            p = cwd / p
        return p

    def get_completions(self, document: Document, complete_event: CompleteEvent) -> Iterable[Completion]:
        text_before = document.text_before_cursor

        quote, word, text = get_quoted_word_context(text_before)

        if not quote:
            word = document.get_word_before_cursor(WORD=True)

        style = detect_path_input_style(text or word, target=bool(self.target))
        text = unescape_path_input(text or word, style, quote)

        text = os.path.expanduser(text) if self.expanduser and not self.target else text  # noqa: PTH111

        # The directory we are trying to list
        directory, prefix = os.path.split(text)

        # Do tilde expansion, only works on local file system
        if self.expanduser and not self.target:
            directory = os.path.expanduser(directory)  # noqa: PTH111

        # Determine the absolute path of the directory we are trying to list.
        # If it's not absolute, we need to make it absolute based on the current working directory.
        abs_path = self._resolve_path(directory)

        filenames: list[tuple[str, str]] = []

        if abs_path.is_dir():
            try:
                for fpath in abs_path.iterdir():
                    filename = str(fpath.name)
                    if filename.startswith(prefix):
                        filenames.append((directory, filename))
            except OSError:
                pass

        # Sort
        filenames = sorted(filenames, key=lambda k: k[1])

        # Yield them.
        for directory, filename in filenames:
            completion = filename[len(prefix) :]
            full_name = "/".join([directory.rstrip("/"), filename]) if directory else filename
            full_path = self._resolve_path(full_name)

            if full_path.is_dir():
                full_name += "/"
                filename += "/"
            elif self.only_directories:
                continue

            if not self.file_filter(full_name):
                continue

            completion = quote_path_for_completion(full_name, quote)

            yield Completion(
                text=completion,
                start_position=-len(word),
                display=filename,
            )
