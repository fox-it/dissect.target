from __future__ import annotations

import argparse
import cmd
import contextlib
import fnmatch
import io
import itertools
import logging
import os
import pathlib
import platform
import pydoc
import random
import re
import shlex
import shutil
import subprocess
import sys
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, BinaryIO, Callable, ClassVar, TextIO

from dissect.cstruct import hexdump
from flow.record import RecordOutput

from dissect.target.exceptions import (
    PluginError,
    RegistryError,
    RegistryKeyNotFoundError,
    RegistryValueNotFoundError,
    TargetError,
)
from dissect.target.helpers import cyber, fsutil, regutil
from dissect.target.helpers.utils import StrEnum
from dissect.target.plugin import FunctionDescriptor, alias, arg, clone_alias
from dissect.target.target import Target
from dissect.target.tools.fsutils import (
    fmt_ls_colors,
    ls_scandir,
    print_ls,
    print_stat,
    print_xattr,
)
from dissect.target.tools.info import print_target_info
from dissect.target.tools.utils import (
    catch_sigpipe,
    configure_generic_arguments,
    escape_str,
    execute_function_on_target,
    find_and_filter_plugins,
    generate_argparse_for_bound_method,
    process_generic_arguments,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.filesystem import FilesystemEntry

log = logging.getLogger(__name__)
logging.lastResort = None
logging.raiseExceptions = False

try:
    import readline

    # remove `-`, `$` and `{` as an autocomplete delimeter on Linux
    # https://stackoverflow.com/questions/27288340/python-cmd-on-linux-does-not-autocomplete-special-characters-or-symbols
    readline.set_completer_delims(readline.get_completer_delims().replace("-", "").replace("$", "").replace("{", ""))

    # Fix autocomplete on macOS
    # https://stackoverflow.com/a/7116997
    if "libedit" in readline.__doc__:
        readline.parse_and_bind("bind ^I rl_complete")
    else:
        readline.parse_and_bind("tab: complete")
except ImportError:
    # Readline is not available on Windows
    log.warning("Readline module is not available")
    readline = None


def readline_escape(s: str | dict[str, str]) -> str | dict[str, str]:
    """Escape a string or values in dictionary for readline prompt.

    Used to embed terminal-specific escape sequences in prompts.

    References:
        - https://wiki.hackzine.org/development/misc/readline-color-prompt.html
        - http://stackoverflow.com/a/9468954/148845
        - RL_PROMPT_START_IGNORE = "\001"
        - RL_PROMPT_END_IGNORE = "\002"
    """
    if isinstance(s, dict):
        return {k: f"\001{v}\002" for k, v in s.items()}
    return f"\001{s}\002"


class AnsiColors(StrEnum):
    """ANSI color escape sequences."""

    # Base formatting
    RESET = "\033[0m"

    # Basic colors
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"

    # Bold colors
    BOLD_RED = "\033[1;31m"
    BOLD_GREEN = "\033[1;32m"
    BOLD_YELLOW = "\033[1;33m"
    BOLD_BLUE = "\033[1;34m"
    BOLD_MAGENTA = "\033[1;35m"
    BOLD_CYAN = "\033[1;36m"
    BOLD_WHITE = "\033[1;37m"

    @classmethod
    def as_dict(cls) -> dict[str, str]:
        """Return ANSI color escape sequences as a dictionary."""
        return {item.name: item.value for item in cls}


# ANSI color escape sequences for readline prompt
ANSI_COLORS = readline_escape(AnsiColors.as_dict())


class ExtendedCmd(cmd.Cmd):
    """Subclassed cmd.Cmd to provide some additional features.

    Add new simple commands by implementing:
        do_<cmd>(self, line)

    Add new complex commands by implementing:
        cmd_<cmd>(self, args, stdout)

    Simple commands are plain cmd.Cmd commands. Output is generally
    presented using print().

    Complex command allow @arg decorators for argparse argument parsing.
    Additionally, complex commands allow their output to be piped to
    external commands. Complex commands should therefor always write to
    the stdout handle that is passed as argument.
    """

    CMD_PREFIX = "cmd_"
    DEFAULT_RUNCOMMANDS_FILE = None

    _runtime_aliases: ClassVar[dict[str, str]] = {}

    def __init__(self, cyber: bool = False):
        cmd.Cmd.__init__(self)
        self.debug = False
        self.cyber = cyber
        self.identchars += "."

        self.register_aliases()

    def __getattr__(self, attr: str) -> Any:
        if attr.startswith("help_"):
            _, _, command = attr.partition("_")

            def print_help(command: str, func: Callable) -> None:
                parser = generate_argparse_for_bound_method(func, usage_tmpl=f"{command} {{usage}}")
                parser.print_help()

            try:
                func = getattr(self, self.CMD_PREFIX + command)
                return lambda: print_help(command, func)
            except AttributeError:
                pass

        return object.__getattribute__(self, attr)

    def _load_targetrc(self, path: pathlib.Path) -> None:
        """Load and execute commands from the run commands file."""
        try:
            with path.open() as fh:
                for line in fh:
                    if (line := line.strip()) and not line.startswith("#"):  # Ignore empty lines and comments
                        self.onecmd(line)
        except FileNotFoundError:
            # The .targetrc file is optional
            pass
        except Exception as e:
            log.debug("Error processing .targetrc file: %s", e)

    def _get_targetrc_path(self) -> pathlib.Path | None:
        """Get the path to the run commands file. Can return ``None`` if ``DEFAULT_RUNCOMMANDS_FILE`` is not set."""
        return pathlib.Path(self.DEFAULT_RUNCOMMANDS_FILE).expanduser() if self.DEFAULT_RUNCOMMANDS_FILE else None

    def preloop(self) -> None:
        super().preloop()
        if targetrc_path := self._get_targetrc_path():
            self._load_targetrc(targetrc_path)

    @staticmethod
    def check_compatible(target: Target) -> bool:
        return True

    def register_aliases(self) -> None:
        for name in self.get_names():
            if name.startswith(self.CMD_PREFIX):
                func = getattr(self.__class__, name)
                for alias_name in getattr(func, "__aliases__", []):
                    if not alias_name.startswith(self.CMD_PREFIX):
                        alias_name = self.CMD_PREFIX + alias_name

                    clone_alias(self.__class__, func, alias_name)

    def get_names(self) -> list[str]:
        names = cmd.Cmd.get_names(self)

        # Add fake do_ and help_ entries to get_names return value
        # This is for help output and completion
        for c in [c.partition("_")[2] for c in names if c.startswith(self.CMD_PREFIX)]:
            names.append("do_" + c)
            names.append("help_" + c)

        return names

    def _handle_command(self, line: str) -> bool | None:
        """Check whether custom handling of the cmd can be performed and if so, do it.

        If a custom handling of the cmd was performed, return the result (a boolean indicating whether the shell should
        exit). If not, return None. Can be overridden by subclasses to perform further / other 'custom command' checks.
        """
        if line == "EOF":
            return True

        # Override default command execution to first attempt complex command execution
        command, command_args_str, line = self.parseline(line)

        if hasattr(self, self.CMD_PREFIX + command):
            return self._exec_command(command, command_args_str)

        # Return None if no custom command was found to be run
        return None

    def default(self, line: str) -> bool:
        com, arg, _ = self.parseline(line)
        if com in self._runtime_aliases:
            expanded = " ".join([self._runtime_aliases[com], arg])
            return self.onecmd(expanded)

        if (should_exit := self._handle_command(line)) is not None:
            return should_exit

        # Fallback to default
        cmd.Cmd.default(self, line)
        return False

    def emptyline(self) -> None:
        """This function forces Python's cmd.Cmd module to behave like a regular shell.

        When entering an empty command, the cmd module will by default repeat the previous command.
        By defining an empty ``emptyline`` function we make sure no command is executed instead.

        References:
            - https://stackoverflow.com/a/16479030
            - https://github.com/python/cpython/blob/3.12/Lib/cmd.py#L10
        """

    def _exec(self, func: Callable[[list[str], TextIO], bool], command_args_str: str, no_cyber: bool = False) -> bool:
        """Command execution helper that chains initial command and piped subprocesses (if any) together."""

        argparts = []
        if command_args_str is not None:
            argparts = arg_str_to_arg_list(command_args_str)

        if "|" in argparts:
            pipeidx = argparts.index("|")
            argparts, pipeparts = argparts[:pipeidx], argparts[pipeidx + 1 :]
            try:
                with build_pipe_stdout(pipeparts) as pipe_stdin:
                    return func(argparts, pipe_stdin)
            except OSError as e:
                # in case of a failure in a subprocess
                print(e)
                return False
        else:
            ctx = contextlib.nullcontext()
            if self.cyber and not no_cyber:
                ctx = cyber.cyber(color=None, run_at_end=True)

            with ctx:
                return func(argparts, sys.stdout)

    def _exec_command(self, command: str, command_args_str: str) -> bool:
        """Command execution helper for ``cmd_`` commands."""
        cmdfunc = getattr(self, self.CMD_PREFIX + command)
        argparser = generate_argparse_for_bound_method(cmdfunc, usage_tmpl=f"{command} {{usage}}")

        def _exec_(argparts: list[str], stdout: TextIO) -> bool:
            try:
                args = argparser.parse_args(argparts)
            except SystemExit:
                return False
            return cmdfunc(args, stdout)

        # These commands enter a subshell, which doesn't work well with cyber
        no_cyber = cmdfunc.__func__ in (TargetCli.cmd_registry, TargetCli.cmd_enter)
        return self._exec(_exec_, command_args_str, no_cyber)

    def do_man(self, line: str) -> bool:
        """alias for help"""
        self.do_help(line)
        return False

    def complete_man(self, *args: list[str]) -> list[str]:
        return cmd.Cmd.complete_help(self, *args)

    def do_unalias(self, line: str) -> bool:
        """delete runtime alias"""
        aliases = list(shlex.shlex(line, posix=True))
        for aliased in aliases:
            if aliased in self._runtime_aliases:
                del self._runtime_aliases[aliased]
            else:
                print(f"alias {aliased} not found")
        return False

    def do_alias(self, line: str) -> bool:
        """create a runtime alias"""
        args = list(shlex.shlex(line, posix=True))

        if not args:
            for aliased, command in self._runtime_aliases.items():
                print(f"alias {aliased}={command}")
            return False

        while args:
            alias_name = args.pop(0)
            try:
                equals = args.pop(0)
                # our parser works different, so we have to stop this
                if equals != "=":
                    raise RuntimeError("Token not allowed")
                expanded = args.pop(0) if args else ""  # this is how it works in bash
                self._runtime_aliases[alias_name] = expanded
            except IndexError:
                if alias_name in self._runtime_aliases:
                    print(f"alias {alias_name}={self._runtime_aliases[alias_name]}")
                else:
                    print(f"alias {alias_name} not found")

        return False

    def do_clear(self, line: str) -> bool:
        """clear the terminal screen"""
        os.system("cls||clear")
        return False

    def do_cls(self, line: str) -> bool:
        """alias for clear"""
        return self.do_clear(line)

    def do_exit(self, line: str) -> bool:
        """exit shell"""
        return True

    def do_cyber(self, line: str) -> bool:
        """cyber"""
        self.cyber = not self.cyber
        word, color = {False: ("D I S E N", cyber.Color.RED), True: ("E N", cyber.Color.YELLOW)}[self.cyber]
        with cyber.cyber(color=color):
            print(f"C Y B E R - M O D E - {word} G A G E D")
        return False

    def do_debug(self, line: str) -> bool:
        """toggle debug mode"""
        self.debug = not self.debug
        if self.debug:
            print("Debug mode on")
        else:
            print("Debug mode off")
        return False


class TargetCmd(ExtendedCmd):
    DEFAULT_HISTFILE = "~/.dissect_history"
    DEFAULT_HISTFILESIZE = 10_000
    DEFAULT_HISTDIR = None
    DEFAULT_HISTDIRFMT = ".dissect_history_{uid}_{target}"
    DEFAULT_RUNCOMMANDS_FILE = "~/.targetrc"
    CONFIG_KEY_RUNCOMMANDS_FILE = "TARGETRCFILE"

    def __init__(self, target: Target):
        self.target = target

        # history file
        self.histfilesize = getattr(target._config, "HISTFILESIZE", self.DEFAULT_HISTFILESIZE)
        self.histdir = getattr(target._config, "HISTDIR", self.DEFAULT_HISTDIR)

        if self.histdir:
            self.histdirfmt = getattr(target._config, "HISTDIRFMT", self.DEFAULT_HISTDIRFMT)
            self.histfile = pathlib.Path(self.histdir).resolve() / pathlib.Path(
                self.histdirfmt.format(uid=os.getuid(), target=target.name)
            )
        else:
            self.histfile = pathlib.Path(getattr(target._config, "HISTFILE", self.DEFAULT_HISTFILE)).expanduser()

        # prompt format
        self.prompt_ps1 = "{BOLD_GREEN}{base}{RESET}:{BOLD_BLUE}{cwd}{RESET}$ "
        if ps1 := getattr(target._config, "PS1", None):
            if "{cwd}" in ps1 and "{base}" in ps1:
                self.prompt_ps1 = ps1
            else:
                self.target.log.warning("{cwd} and {base} were not set inside PS1, using the default prompt")

        elif getattr(target._config, "NO_COLOR", None) or os.getenv("NO_COLOR"):
            self.prompt_ps1 = "{base}:{cwd}$ "

        super().__init__(self.target.props.get("cyber"))

    def _get_targetrc_path(self) -> pathlib.Path:
        """Get the path to the run commands file."""

        return pathlib.Path(
            getattr(self.target._config, self.CONFIG_KEY_RUNCOMMANDS_FILE, self.DEFAULT_RUNCOMMANDS_FILE)
        ).expanduser()

    def preloop(self) -> None:
        super().preloop()
        if readline and self.histfile.exists():
            try:
                readline.read_history_file(self.histfile)
            except Exception as e:
                log.debug("Error reading history file: %s", e)

    def postloop(self) -> None:
        if readline:
            readline.set_history_length(self.histfilesize)
            try:
                readline.write_history_file(self.histfile)
            except Exception as e:
                log.debug("Error writing history file: %s", e)

    def _handle_command(self, line: str) -> bool | None:
        if (should_exit := super()._handle_command(line)) is not None:
            return should_exit

        # The parent class has already attempted complex command execution, we now attempt target plugin command
        # execution
        command, command_args_str, line = self.parseline(line)

        if functions := list(find_and_filter_plugins(command, self.target)):
            return self._exec_target(functions, command_args_str)

        # We didn't execute a function on the target
        return None

    def _exec_target(self, funcs: list[FunctionDescriptor], command_args_str: str) -> bool:
        """Command exection helper for target plugins."""

        def _exec_(argparts: list[str], stdout: TextIO) -> None:
            try:
                output, value, _ = execute_function_on_target(self.target, func, argparts)
            except SystemExit:
                return

            if output == "record":
                # if the command results are piped to another process,
                # the process will receive Record objects
                if stdout is sys.stdout:
                    for entry in value:
                        print(entry, file=stdout)
                else:
                    stdout = stdout.buffer

                    rs = RecordOutput(stdout)
                    for entry in value:
                        rs.write(entry)
            elif output == "yield":
                for entry in value:
                    print(entry, file=stdout)
            elif output == "none":
                return
            else:
                print(value, file=stdout)

        # What in the variable hoisting is this
        for func in funcs:  # noqa: B007
            try:
                self._exec(_exec_, command_args_str)
            except PluginError:  # noqa: PERF203
                if self.debug:
                    raise
                self.target.log.exception("Plugin error")

        # Keep the shell open
        return False

    def do_python(self, line: str) -> bool:
        """drop into a Python shell"""
        python_shell([self.target])
        return False


class TargetHubCli(cmd.Cmd):
    """Hub Cli for interacting with multiple targets."""

    prompt = "dissect> "
    doc_header = (
        "Target Hub\n"
        "==========\n"
        "List and enter targets by using 'list' and 'enter'.\n\n"
        "Documented commands (type help <topic>):"
    )

    def __init__(self, targets: list[Target], cli: TargetCmd):
        cmd.Cmd.__init__(self)
        self.targets = targets
        self._targetcli = cli
        self._names = [t.name for t in targets]
        self._names_lower = [h.lower() for h in self._names]

        self._clicache = {}

    def default(self, line: str) -> bool:
        if line == "EOF":
            return True

        cmd.Cmd.default(self, line)
        return False

    def emptyline(self) -> None:
        pass

    def do_exit(self, line: str) -> bool:
        """exit shell"""
        return True

    def do_list(self, line: str) -> bool:
        """list the loaded targets"""
        print("\n".join([f"{i:2d}: {e}" for i, e in enumerate(self._names)]))
        return False

    def do_enter(self, line: str) -> bool:
        """enter a target by number or name"""

        if line.isdigit():
            idx = int(line)
        else:
            try:
                idx = self._names_lower.index(line.lower())
            except ValueError:
                print("Unknown name")
                return False

        if idx >= len(self.targets):
            print("Unknown target")
            return False

        try:
            cli = self._clicache[idx]
        except KeyError:
            target = self.targets[idx]
            if not self._targetcli.check_compatible(target):
                return False

            cli = self._targetcli(self.targets[idx])
            self._clicache[idx] = cli

        print(f"Entering {idx}: {self._names[idx]}")
        run_cli(cli)
        return False

    def complete_enter(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        if not text:
            return self._names[:]

        compl = [h for h in self._names if h.lower().startswith(text.lower())]

        # Also provide completion for multidigit numbers
        if text.isdigit():
            compl.extend([str(i) for i in range(len(self.targets)) if str(i).startswith(text)])

        return compl

    def do_python(self, line: str) -> bool:
        """drop into a Python shell"""
        python_shell(self.targets)
        return False


class TargetCli(TargetCmd):
    """CLI for interacting with a target and browsing the filesystem."""

    def __init__(self, target: Target):
        self.prompt_base = _target_name(target)

        TargetCmd.__init__(self, target)
        self._clicache = {}
        # Force to root, using `chdir` causes `None` to propagate throughout the class methods.
        self.cwd = self.target.fs.path("/")

    @property
    def prompt(self) -> str:
        return self.prompt_ps1.format(base=self.prompt_base, cwd=self.cwd, **ANSI_COLORS)

    def completedefault(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        path = self.resolve_path(line[:begidx].rsplit(" ")[-1])
        textlower = text.lower()

        suggestions = []
        for fpath, fname in ls_scandir(path):
            if not fname.lower().startswith(textlower):
                continue

            # Add a trailing slash to directories, to allow for easier traversal of the filesystem
            suggestion = f"{fname}/" if fpath.is_dir() else fname
            suggestions.append(suggestion)
        return suggestions

    def resolve_path(self, path: str) -> fsutil.TargetPath:
        if not path:
            return self.cwd

        if isinstance(path, fsutil.TargetPath):
            return path

        path = fsutil.abspath(path, cwd=str(self.cwd), alt_separator=self.target.fs.alt_separator)
        return self.target.fs.path(path)

    def resolve_glob_path(self, path: str) -> Iterator[fsutil.TargetPath]:
        path = self.resolve_path(path)
        if path.exists():
            yield path
        else:
            # Strip the leading '/' as non-relative patterns are unsupported as glob patterns.
            glob_path = str(path).lstrip("/")
            try:
                for path in self.target.fs.path("/").glob(glob_path):
                    yield path
            except ValueError as e:
                # The generator returned by glob() will raise a
                # ValueError if the '**' glob is not used as an entire path
                # component
                print(e)

    def check_file(self, path: str) -> fsutil.TargetPath | None:
        path = self.resolve_path(path)
        if not path.exists():
            print(f"{path}: No such file")
            return None

        if path.is_dir():
            print(f"{path}: Is a directory")
            return None

        if not path.is_file():
            print(f"{path}: Not a file")
            return None

        return path

    def check_dir(self, path: str) -> fsutil.TargetPath | None:
        path = self.resolve_path(path)
        if not path.exists():
            print(f"{path}: No such directory")
            return None

        if path.is_file():
            print(f"{path}: Is a file")
            return None

        if not path.is_dir():
            print(f"{path}: Not a directory")
            return None

        return path

    def check_path(self, path: str) -> fsutil.TargetPath | None:
        path = self.resolve_path(path)
        if not path.exists():
            print(f"{path}: No such file or directory")
            return None

        return path

    def chdir(self, path: str) -> None:
        """Change directory to the given path."""
        if dir := self.check_dir(path):
            self.cwd = dir

    def do_cd(self, line: str) -> bool:
        """change directory"""
        self.chdir(line)
        return False

    def do_pwd(self, line: str) -> bool:
        """print current directory"""
        print(self.cwd)
        return False

    def do_disks(self, line: str) -> bool:
        """print target disks"""
        for d in self.target.disks:
            print(str(d))
        return False

    def do_volumes(self, line: str) -> bool:
        """print target volumes"""
        for v in self.target.volumes:
            print(str(v))
        return False

    def do_filesystems(self, line: str) -> bool:
        """print target filesystems"""
        for fs in self.target.filesystems:
            print(str(fs))
        return False

    def do_info(self, line: str) -> bool:
        """print target information"""
        print_target_info(self.target)
        return False

    def do_reload(self, line: str) -> bool:
        """reload the target"""
        self.target = self.target.reload()
        if self.cwd:
            self.chdir(str(self.cwd))  # self.cwd has reference into the old target :/
        return False

    @arg("path", nargs="?")
    @arg("-l", action="store_true")
    @arg("-a", "--all", action="store_true")  # ignored but included for proper argument parsing
    @arg("-h", "--human-readable", action="store_true")
    @arg("-R", "--recursive", action="store_true", help="recursively list subdirectories encountered")
    @arg("-c", action="store_true", dest="use_ctime", help="show time when file status was last changed")
    @arg("-u", action="store_true", dest="use_atime", help="show time of last access")
    @alias("l")
    @alias("dir")
    def cmd_ls(self, args: argparse.Namespace, stdout: TextIO) -> bool:
        """list directory contents"""

        path = self.resolve_path(args.path)

        if args.use_ctime and args.use_atime:
            print("can't specify -c and -u at the same time")
            return False

        if not path or not self.check_dir(path):
            return False

        if path.is_file():
            print(args.path)  # mimic ls behaviour
            return False

        print_ls(path, 0, stdout, args.l, args.human_readable, args.recursive, args.use_ctime, args.use_atime)
        return False

    @arg("path", nargs="?")
    def cmd_ll(self, args: argparse.Namespace, stdout: TextIO) -> bool:
        """alias for ls -la"""
        args = extend_args(args, self.cmd_ls)
        args.l = True
        args.a = True
        return self.cmd_ls(args, stdout)

    @arg("path", nargs="?")
    def cmd_tree(self, args: argparse.Namespace, stdout: TextIO) -> bool:
        """alias for ls -R"""
        args = extend_args(args, self.cmd_ls)
        args.recursive = True
        return self.cmd_ls(args, stdout)

    @arg("path", nargs="?")
    @arg("-name", default="*", help="path to match with")
    @arg("-iname", help="like -name, but the match is case insensitive")
    @arg("-atime", type=int, help="file was last accessed n*24 hours ago")
    @arg("-mtime", type=int, help="file was last modified n*24 hours ago")
    @arg("-ctime", type=int, help="file (windows) or metadata (unix) was last changed n*24 hours ago")
    @arg("-btime", type=int, help="file was born n*24 hours ago (ext4)")
    def cmd_find(self, args: argparse.Namespace, stdout: TextIO) -> bool:
        """search for files in a directory hierarchy"""
        path = self.resolve_path(args.path)
        if not path or not self.check_dir(path):
            return False

        matches = []
        now = datetime.now(tz=timezone.utc)
        do_time_compare = any([args.mtime, args.atime])

        if args.iname:
            pattern = re.compile(fnmatch.translate(args.iname), re.IGNORECASE)
            for f in path.rglob("*"):
                if pattern.match(f.name):
                    matches.append(f) if do_time_compare else print(f, file=stdout)
        else:
            for f in path.rglob(args.name):
                matches.append(f) if do_time_compare else print(f, file=stdout)

        def compare(now: datetime, then_ts: float, offset: int) -> bool:
            then = datetime.fromtimestamp(then_ts, tz=timezone.utc)
            return now - timedelta(hours=offset * 24) > then

        if do_time_compare:
            for f in matches:
                s = f.lstat()

                if args.mtime and compare(now, s.st_mtime, offset=args.mtime):
                    continue

                if args.atime and compare(now, s.st_atime, offset=args.atime):
                    continue

                if args.ctime and compare(now, s.st_ctime, offset=args.ctime):
                    continue

                if args.btime and compare(now, s.st_birthtime, offset=args.btime):
                    continue

                print(f, file=stdout)

        return False

    @arg("path")
    @arg("-L", "--dereference", action="store_true")
    def cmd_stat(self, args: argparse.Namespace, stdout: TextIO) -> bool:
        """display file status"""
        path = self.resolve_path(args.path)
        if not path or not self.check_path(path):
            return False

        print_stat(path, stdout, args.dereference)
        return False

    @arg("path")
    @arg("-d", "--dump", action="store_true")
    @arg("-R", "--recursive", action="store_true")
    @alias("getfattr")
    def cmd_attr(self, args: argparse.Namespace, stdout: TextIO) -> bool:
        """display file attributes"""
        path = self.resolve_path(args.path)
        if not path or not self.check_path(path):
            return False

        try:
            if attr := path.get().attr():
                print_xattr(path.name, attr, stdout)
        except Exception:
            pass

        if args.recursive:
            for child in path.rglob("*"):
                try:
                    if child_attr := child.get().attr():
                        print_xattr(child, child_attr, stdout)
                        print()
                except Exception:  # noqa: PERF203
                    pass

        return False

    @arg("path")
    def cmd_file(self, args: argparse.Namespace, stdout: TextIO) -> bool:
        """determine file type"""

        path = self.check_file(args.path)
        if not path:
            return False

        fh = path.open()

        # We could just alias this to cat <path> | file -, but this is slow for large files
        # This way we can explicitly limit to just 512 bytes
        p = subprocess.Popen(["file", "-"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        p.stdin.write(fh.read(512))
        p.stdin.close()
        p.wait()
        filetype = p.stdout.read().decode().split(":", 1)[1].strip()
        print(f"{path}: {filetype}", file=stdout)
        return False

    @arg("path", nargs="+")
    @arg("-o", "--out", default=".")
    @arg("-v", "--verbose", action="store_true")
    def cmd_save(self, args: argparse.Namespace, stdout: TextIO) -> bool:
        """save a common file or directory to the host filesystem"""
        dst_path = pathlib.Path(args.out).resolve()

        if len(args.path) > 1 and not dst_path.is_dir():
            # Saving multiple items to a non-directory is generally not very
            # useful. This also prevents multiple error messages if some of the
            # items are directories.
            print(f"{dst_path}: cannot save multiple files, destination is not a directory")

        def log_saved_path(src_path: pathlib.Path, dst_path: pathlib.Path) -> None:
            if args.verbose:
                print(f"{src_path} -> {dst_path}")

        def get_diverging_path(path: pathlib.Path, reference_path: pathlib.Path) -> pathlib.Path:
            """Get the part of path where it diverges from reference_path."""
            diverging_path = pathlib.Path()

            for diff_idx, path_part in enumerate(reference_path.parts):
                if path_part != path.parts[diff_idx]:
                    diverging_parts = path.parts[diff_idx:]
                    if diverging_parts:
                        for part in diverging_parts:
                            diverging_path = diverging_path.joinpath(pathlib.Path(part))
                    break

            return diverging_path

        def save_path(
            src_path: pathlib.Path, dst_path: pathlib.Path, create_dst_subdir: pathlib.Path | None = None
        ) -> None:
            """Save a common file or directory in src_path to dst_path.

            If src_path is a file, dst_path can be either a directory or a file
            (the latter case will rename the source file).

            If src_path is a directory, dst_path is only allowed to be a
            directory.

            Symlinks in src_path are not explicitly resolved, if they point to
            a file or directory they will be saved under the symlinked name.

            If create_dst_subdir is specified, this sub directory is first
            created below dst_path (if dst_path is a directory) after which the
            src_path is saved there. This can be useful to recreate a part of
            the directory hierarchy in src_path.
            """

            src_name = src_path.name
            src_path = src_path.resolve()
            if src_path.is_dir():
                # Directories can only be copied if the destination is a
                # directory.
                if not dst_path.exists():
                    print(f"{dst_path}: destination directory does not exist")
                    return
                if not dst_path.is_dir():
                    print(f"{src_path}: cannot save directory into non-directory {dst_path}")
                    return
                if create_dst_subdir:
                    dst_path = dst_path.joinpath(create_dst_subdir)
                dst_path = dst_path.joinpath(src_name)
                dst_path.mkdir(parents=True, exist_ok=True)
                log_saved_path(src_path, dst_path)
                for path in src_path.glob("*"):
                    save_path(path, dst_path)

            elif src_path.is_file():
                # Files will overwrite existing destination files, if they
                # exist, or be created if they don't.
                if not dst_path.exists() and not dst_path.parent.is_dir():
                    print(f"{dst_path.parent}: destination directory does not exist")
                    return
                if dst_path.exists():
                    if dst_path.is_dir():
                        if create_dst_subdir:
                            dst_path = dst_path.joinpath(create_dst_subdir)
                            dst_path.mkdir(parents=True, exist_ok=True)
                        dst_path = dst_path.joinpath(src_name)
                    elif not dst_path.is_file():
                        # Saving over special files like device or pipe files
                        # won't work (and is not useful).
                        print(f"{src_path}: cannot save file as non-file {dst_path}")
                        return

                with dst_path.open(mode="wb") as dst_fh:
                    shutil.copyfileobj(src_path.open(), dst_fh)
                log_saved_path(src_path, dst_path)

            else:
                if src_path.exists():
                    print(f"{src_path}: not a file or directory")
                else:
                    print(f"{src_path}: no such file or directory")

        for path in args.path:
            # This normalizes /'s and \'s, resolves . and ..  and makes the
            # path absolute, but does not resolve symlinks like pathlib's
            # Path.resolve(). This is needed as we need the original filename
            # for saving.
            src_paths = self.resolve_glob_path(path)
            reference_path = self.resolve_path(path)
            # See if the path has globs in it which resolve to multiple files.
            # If so the dst_path needs to be a directory to properly save all
            # the files resulting from globbing.
            try:
                first_src_path = next(src_paths)
            except StopIteration:
                print(f"{path}: No such file or directory")
                return False

            try:
                second_src_path = next(src_paths)
            except StopIteration:
                # We use the parent of the diverging path as the final part
                # (if there is any) is the file or directory we want to
                # save.
                extra_dir = get_diverging_path(first_src_path, reference_path).parent
                save_path(first_src_path, dst_path, create_dst_subdir=extra_dir)
            else:
                if not dst_path.is_dir():
                    # Saving multiple items to a non-directory is generally not very
                    # useful. This also prevents multiple error messages if some of the
                    # items are directories.
                    print(f"{dst_path}: cannot save multiple files, destination is not a directory")
                else:
                    for src_path in itertools.chain([first_src_path, second_src_path], src_paths):
                        extra_dir = get_diverging_path(src_path, reference_path).parent
                        save_path(src_path, dst_path, create_dst_subdir=extra_dir)

        return False

    @arg("path")
    @alias("type")
    def cmd_cat(self, args: argparse.Namespace, stdout: TextIO) -> bool:
        """print file content"""
        paths = list(self.resolve_glob_path(args.path))

        if not paths:
            print(f"{args.path}: No such file or directory")
            return False

        stdout = stdout.buffer
        for path in paths:
            path = self.check_file(path)
            if not path:
                continue

            fh = path.open()
            shutil.copyfileobj(fh, stdout)
            stdout.flush()
        print()
        return False

    @arg("path")
    def cmd_zcat(self, args: argparse.Namespace, stdout: TextIO) -> bool:
        """print file content from compressed files"""
        paths = list(self.resolve_glob_path(args.path))

        if not paths:
            print(f"{args.path}: No such file or directory")
            return False

        stdout = stdout.buffer
        for path in paths:
            path = self.check_file(path)
            if not path:
                continue

            fh = fsutil.open_decompress(path)
            shutil.copyfileobj(fh, stdout)
            stdout.flush()

        return False

    @arg("path")
    @arg("-n", "--length", type=int, default=16 * 20, help="amount of bytes to read")
    @arg("-s", "--skip", type=int, default=0, help="skip offset bytes from the beginning")
    @arg("-p", "--hex", action="store_true", help="output in plain hexdump style")
    @arg("-C", "--canonical", action="store_true")
    @alias("xxd")
    def cmd_hexdump(self, args: argparse.Namespace, stdout: TextIO) -> bool:
        """print a hexdump of a file"""
        path = self.check_file(args.path)
        if not path:
            return False

        fh = path.open("rb")
        if args.skip > 0:
            fh.seek(args.skip + 1)

        if args.hex:
            print(fh.read(args.length).hex(), file=stdout)
        else:
            print(hexdump(fh.read(args.length), output="string"), file=stdout)

        return False

    @arg("path")
    @alias("digest")
    @alias("shasum")
    def cmd_hash(self, args: argparse.Namespace, stdout: TextIO) -> bool:
        """print the MD5, SHA1 and SHA256 hashes of a file"""
        path = self.check_file(args.path)
        if not path:
            return False

        md5, sha1, sha256 = path.get().hash()
        print(f"MD5:\t{md5}\nSHA1:\t{sha1}\nSHA256:\t{sha256}", file=stdout)
        return False

    @arg("path")
    @alias("head")
    @alias("more")
    def cmd_less(self, args: argparse.Namespace, stdout: TextIO) -> bool:
        """open the first 10 MB of a file with less"""
        path = self.check_file(args.path)
        if not path:
            return False

        pydoc.pager(path.open("rt", errors="ignore").read(10 * 1024 * 1024))
        return False

    @arg("path")
    @alias("zhead")
    @alias("zmore")
    def cmd_zless(self, args: argparse.Namespace, stdout: TextIO) -> bool:
        """open the first 10 MB of a compressed file with zless"""
        path = self.check_file(args.path)
        if not path:
            return False

        pydoc.pager(fsutil.open_decompress(path, "rt").read(10 * 1024 * 1024))
        return False

    @arg("path", nargs="+")
    def cmd_readlink(self, args: argparse.Namespace, stdout: TextIO) -> bool:
        """print resolved symbolic links or canonical file names"""
        for path in args.path:
            path = self.resolve_path(path)
            if not path.is_symlink():
                continue

            print(path.get().readlink(), file=stdout)

        return False

    @arg("path", nargs="?", help="load a hive from the given path")
    def cmd_registry(self, args: argparse.Namespace, stdout: TextIO) -> bool:
        """drop into a registry shell"""
        if self.target.os == "linux":
            run_cli(UnixConfigTreeCli(self.target))
            return False

        hive = None

        clikey = "registry"
        if args.path:
            path = self.check_file(args.path)
            if not path:
                return False

            hive = regutil.RegfHive(path)
            clikey = f"registry_{path}"

        try:
            cli = self._clicache[clikey]
        except KeyError:
            if not hive and not RegistryCli.check_compatible(self.target):
                return False

            cli = RegistryCli(self.target, hive)
            self._clicache[clikey] = cli

        run_cli(cli)
        print()
        return False

    @arg("targets", metavar="TARGETS", nargs="*", help="targets to load")
    @arg("-p", "--python", action="store_true", help="(I)Python shell")
    @arg("-r", "--registry", action="store_true", help="registry shell")
    def cmd_enter(self, args: argparse.Namespace, stdout: TextIO) -> bool:
        """load one or more files as sub-targets and drop into a sub-shell"""
        paths = [self.resolve_path(path) for path in args.targets]

        if args.python:
            # Quick path that doesn't require CLI caching
            open_shell(paths, args.python, args.registry)
            return False

        clikey = tuple(str(path) for path in paths)
        try:
            cli = self._clicache[clikey]
        except KeyError:
            targets = list(Target.open_all(paths))
            cli = create_cli(targets, RegistryCli if args.registry else TargetCli)
            if not cli:
                return False

            self._clicache[clikey] = cli

        run_cli(cli)
        print()
        return False


class UnixConfigTreeCli(TargetCli):
    def __init__(self, target: Target):
        TargetCmd.__init__(self, target)
        self.config_tree = target.etc()
        self.prompt_base = _target_name(target)

        self.cwd = None
        self.chdir("/")

    @property
    def prompt(self) -> str:
        return f"(config tree) {self.prompt_base}:{self.cwd}$ "

    def check_compatible(target: Target) -> bool:
        return target.has_function("etc")

    def resolve_path(self, path: str | fsutil.TargetPath | None) -> fsutil.TargetPath:
        if not path:
            return self.cwd

        if isinstance(path, fsutil.TargetPath):
            return path

        # It uses the alt separator of the underlying fs
        path = fsutil.abspath(path, cwd=str(self.cwd), alt_separator=self.target.fs.alt_separator)
        return self.config_tree.path(path)

    def resolve_key(self, path: str) -> FilesystemEntry:
        return self.config_tree.path(path).get()

    def resolve_glob_path(self, path: fsutil.TargetPath) -> Iterator[fsutil.TargetPath]:
        path = self.resolve_path(path)
        if path.exists():
            yield path
        else:
            # Strip the leading '/' as non-relative patterns are unsupported as glob patterns.
            glob_path = str(path).lstrip("/")
            try:
                for path in self.config_tree.path("/").glob(glob_path):
                    yield path
            except ValueError as e:
                # The generator returned by glob() will raise a
                # ValueError if the '**' glob is not used as an entire path
                # component
                print(e)


class RegistryCli(TargetCmd):
    """CLI for browsing the registry."""

    # Registry shell is incompatible with default shell, so override the default rc file and config key
    DEFAULT_RUNCOMMANDS_FILE = "~/.targetrc.registry"
    CONFIG_KEY_RUNCOMMANDS_FILE = "TARGETRCFILE_REGISTRY"

    def __init__(self, target: Target, registry: regutil.RegfHive | None = None):
        self.prompt_base = _target_name(target)

        TargetCmd.__init__(self, target)

        self.registry = registry or target.registry
        self.cwd = None
        self.chdir("\\")

    @staticmethod
    def check_compatible(target: Target) -> bool:
        if not target.has_function("registry"):
            print("ERROR: Target doesn't have a registry")
            return False
        return True

    @property
    def prompt(self) -> str:
        return "(registry) " + self.prompt_ps1.format(base=self.prompt_base, cwd=self.cwd, **ANSI_COLORS)

    def completedefault(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        path = line[:begidx].rsplit(" ")[-1]
        return [fname for _, fname in self.scandir(path) if fname.lower().startswith(text.lower())]

    def resolve_key(self, path: str) -> regutil.RegistryKey:
        if isinstance(path, regutil.RegistryKey):
            return path

        path = f"{self.cwd}\\{path}" if path and not path.startswith("\\") else path or self.cwd
        path = path.replace("\\\\", "\\")
        return self.registry.key(path.strip("\\"))

    def check_key(self, path: str) -> regutil.RegistryKey:
        try:
            return self.resolve_key(path)
        except RegistryError:
            print(f"{path}: No such subkey")

    def check_value(self, path: str) -> regutil.RegistryValue:
        path, _, value = path.rpartition("\\")
        try:
            key = self.resolve_key(path)
            return key.value(value)
        except RegistryKeyNotFoundError:
            print(f"{path}: No such subkey")
        except RegistryValueNotFoundError:
            print(f"{path}\\{value}: No such value")

    def chdir(self, path: str) -> None:
        if not path.startswith("\\"):
            path = f"{self.cwd}\\{path}"

        if self.check_key(path):
            self.cwd = "\\" + path.strip("\\")

    def scandir(self, path: str, color: bool = False) -> list[tuple[regutil.RegistryKey | regutil.RegistryValue, str]]:
        try:
            key = self.resolve_key(path)
        except RegistryError:
            return []

        r = [
            *((s, fmt_ls_colors("di", s.name) if color else s.name) for s in key.subkeys()),
            *((v, fmt_ls_colors("fi", v.name) if color else v.name) for v in key.values()),
        ]

        r.sort(key=lambda e: e[0].name)
        return r

    def do_cd(self, line: str) -> bool:
        """change subkey"""
        if line == "..":
            try:
                self.resolve_key(self.cwd + "\\..")
            except RegistryError:
                self.do_up(line)
                return False

        self.chdir(line)
        return False

    def do_up(self, line: str) -> bool:
        """go up a subkey"""
        parent = self.cwd.rpartition("\\")[0]
        if not parent:
            parent = "\\"
        self.chdir(parent)
        return False

    def do_pwd(self, line: str) -> bool:
        """print current path"""
        print(self.cwd.lstrip("\\"))
        return False

    def do_recommend(self, line: str) -> bool:
        """recommend a key"""
        print(random.choice([name for _, name in self.scandir(None)]))
        return False

    @arg("path", nargs="?")
    def cmd_ls(self, args: argparse.Namespace, stdout: TextIO) -> bool:
        key = self.check_key(args.path)
        if not key:
            return False

        r = self.scandir(key, color=True)
        print("\n".join([name for _, name in r]), file=stdout)
        return False

    @arg("value")
    def cmd_cat(self, args: argparse.Namespace, stdout: TextIO) -> bool:
        value = self.check_value(args.value)
        if not value:
            return False

        print(repr(value.value), file=stdout)
        return False

    @arg("value")
    @arg("-p", "--hex", action="store_true")
    @alias("xxd")
    def cmd_hexdump(self, args: argparse.Namespace, stdout: TextIO) -> bool:
        value = self.check_value(args.value)
        if not value:
            return False

        if args.hex:
            print(value.value.hex(), file=stdout)
        else:
            print(hexdump(value.value, output="string"), file=stdout)

        return False


def arg_str_to_arg_list(args: str) -> list[str]:
    """Convert a commandline string to a list of command line arguments."""
    lexer = shlex.shlex(args, posix=True, punctuation_chars=True)
    lexer.wordchars += "$"
    lexer.whitespace_split = True
    return list(lexer)


def extend_args(args: argparse.Namespace, func: Callable) -> argparse.Namespace:
    """Extend the arguments of the given ``func`` with the provided ``argparse.Namespace``."""
    for short, kwargs in func.__args__:
        name = kwargs.get("dest", short[-1]).lstrip("-").replace("-", "_")
        if not hasattr(args, name):
            setattr(args, name, None)
    return args


def _target_name(target: Target) -> str:
    """Return a printable FQDN target name for cmd.Cmd base prompts."""

    if target.has_function("domain") and target.domain:
        return escape_str(f"{target.name}.{target.domain}")

    return escape_str(target.name)


@contextmanager
def build_pipe(pipe_parts: list[str], pipe_stdout: int = subprocess.PIPE) -> Iterator[tuple[TextIO, BinaryIO]]:
    """Generator context manager that chains piped subprocessess and
    returns a tuple (chain input stream, chain output stream).

    On context exit the generator will close the input stream and wait for
    the subprocessess to finish.
    """

    if not pipe_parts:
        raise ValueError("No pipe components provided")

    proc_args = []
    current_stdin = subprocess.PIPE
    pipe_stdin = None

    for part in pipe_parts:
        if part == "|":
            proc = subprocess.Popen(proc_args, stdin=current_stdin, stdout=subprocess.PIPE)
            if not pipe_stdin:
                pipe_stdin = proc.stdin

            proc_args = []
            current_stdin = proc.stdout
        else:
            proc_args.append(part)

    if not proc_args:
        # fail gracefully by piping stdin into stdout if command ends
        # with hanging `|`
        proc_args = ["cat"]

    # last process in a pipe
    proc = subprocess.Popen(proc_args, stdin=current_stdin, stdout=pipe_stdout)
    if not pipe_stdin:
        pipe_stdin = proc.stdin

    pipe_stdout = proc.stdout

    # turn a byte stream into a text stream
    pipe_txt_stdin = io.TextIOWrapper(pipe_stdin)
    try:
        yield pipe_txt_stdin, pipe_stdout
    finally:
        try:
            pipe_txt_stdin.close()
        except IOError:
            # Ignore errors if pipe closes prematurely
            pass
    proc.wait()


@contextmanager
def build_pipe_stdout(pipe_parts: list[str]) -> Iterator[TextIO]:
    """Generator context manager that chains piped subprocessess, with a chain's
    outgoing stream configured to be parent's stdout.

    Generator returns a chain's input stream from `build_pipe` generator.
    """
    with build_pipe(pipe_parts, pipe_stdout=None) as (pipe_stdin, _):
        yield pipe_stdin


def open_shell(targets: list[str | pathlib.Path], python: bool, registry: bool, commands: list[str] | None) -> None:
    """Helper method for starting a regular, Python or registry shell for one or multiple targets."""
    targets = list(Target.open_all(targets))

    if python:
        python_shell(targets, commands=commands)
    else:
        cli_cls = RegistryCli if registry else TargetCli
        target_shell(targets, cli_cls=cli_cls, commands=commands)


def target_shell(targets: list[Target], cli_cls: type[TargetCmd], commands: list[str] | None) -> None:
    """Helper method for starting a :class:`TargetCli` or :class:`TargetHubCli` for one or multiple targets."""
    if cli := create_cli(targets, cli_cls):
        if commands is not None:
            for command in commands:
                cli.onecmd(command)
            return
        run_cli(cli)


def python_shell(targets: list[Target], commands: list[str] | None = None) -> None:
    """Helper method for starting a (I)Python shell with multiple targets."""
    banner = "Loaded targets in 'targets' variable. First target is in 't'."
    ns = {"targets": targets, "t": targets[0]}

    try:
        if commands is not None:
            for command in commands:
                eval(command, ns)
            return

        import IPython

        IPython.embed(header=banner, user_ns=ns, colors="linux")

        # IPython already prints an empty newline
    except ImportError:
        import code

        shell = code.InteractiveConsole(ns)
        shell.interact(banner)

        # Print an empty newline on exit
        print()


def create_cli(targets: list[Target], cli_cls: type[TargetCmd]) -> cmd.Cmd | None:
    """Helper method for instatiating the appropriate CLI."""
    if len(targets) == 1:
        target = targets[0]
        if not cli_cls.check_compatible(target):
            return None

        cli = cli_cls(target)
    else:
        cli = TargetHubCli(targets, cli_cls)

    return cli


def run_cli(cli: cmd.Cmd) -> None:
    """Helper method for running a cmd.Cmd cli.

    Loops cli.cmdloop(), skipping KeyboardInterrupts. This is done so
    that ctrl+c doesn't exit the shell but only resets the current line.
    """
    while True:
        try:
            cli.cmdloop()
        except KeyboardInterrupt:  # noqa: PERF203
            # Run postloop so the interrupted command is added to the history file
            cli.postloop()

            # Add a line when pressing ctrl+c, so the next one starts at a new line
            print()

        except Exception as e:
            if cli.debug:
                log.exception("Unhandled error")
            else:
                log.info(e)
                print(f"*** Unhandled error: {e}")
                print("If you wish to see the full debug trace, enable debug mode.")

            cli.postloop()
        else:
            # Print an empty newline on exit
            print()
            return


@catch_sigpipe
def main() -> int:
    help_formatter = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(
        description="dissect.target",
        fromfile_prefix_chars="@",
        formatter_class=help_formatter,
    )
    parser.add_argument("targets", metavar="TARGETS", nargs="*", help="targets to load")
    parser.add_argument("-p", "--python", action="store_true", help="(I)Python shell")
    parser.add_argument("-r", "--registry", action="store_true", help="registry shell")
    parser.add_argument("-c", "--commands", action="store", nargs="*", help="commands to execute")
    configure_generic_arguments(parser)

    args, rest = parser.parse_known_args()
    process_generic_arguments(args, rest)

    # For the shell tool we want -q to log slightly more then just CRITICAL messages.
    if args.quiet:
        logging.getLogger("dissect").setLevel(level=logging.ERROR)

    # PyPy < 3.10.14 readline is stuck in Python 2.7
    if platform.python_implementation() == "PyPy":
        major, minor, patch = tuple(map(int, platform.python_version_tuple()))
        if major < 3 or (major == 3 and (minor < 10 or (minor == 10 and patch < 14))):
            print(
                "Note for users of PyPy < 3.10.14:\n"
                "Autocomplete might not work due to an outdated version of pyrepl/readline.py\n"
                "To fix this, please update your version of PyPy.",
                file=sys.stderr,
            )

    try:
        open_shell(args.targets, args.python, args.registry, args.commands)
    except TargetError as e:
        log.exception("Error opening shell")
        log.debug("", exc_info=e)

    return 0


if __name__ == "__main__":
    main()
