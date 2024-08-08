import argparse
import cmd
import contextlib
import fnmatch
import io
import itertools
import logging
import os
import pathlib
import pydoc
import random
import re
import shlex
import shutil
import subprocess
import sys
from contextlib import contextmanager
from typing import Any, BinaryIO, Callable, Iterator, Optional, TextIO, Union

from dissect.cstruct import hexdump
from flow.record import RecordOutput

from dissect.target.exceptions import (
    PluginError,
    RegistryError,
    RegistryKeyNotFoundError,
    RegistryValueNotFoundError,
    TargetError,
)
from dissect.target.filesystem import FilesystemEntry
from dissect.target.helpers import cyber, fsutil, regutil
from dissect.target.plugin import PluginFunction, arg
from dissect.target.target import Target
from dissect.target.tools.fsutils import fmt_ls_colors, ls_scandir, print_ls, print_stat
from dissect.target.tools.info import print_target_info
from dissect.target.tools.utils import (
    args_to_uri,
    catch_sigpipe,
    configure_generic_arguments,
    execute_function_on_target,
    find_and_filter_plugins,
    generate_argparse_for_bound_method,
    process_generic_arguments,
)

log = logging.getLogger(__name__)
logging.lastResort = None
logging.raiseExceptions = False

try:
    import readline

    # remove `-` as an autocomplete delimeter on Linux
    # https://stackoverflow.com/questions/27288340/python-cmd-on-linux-does-not-autocomplete-special-characters-or-symbols
    readline.set_completer_delims(readline.get_completer_delims().replace("-", "").replace("$", ""))
except ImportError:
    # Readline is not available on Windows
    log.warning("Readline module is not available")
    readline = None


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

    def __init__(self, start_in_cyber: bool = False):
        cmd.Cmd.__init__(self)
        self.debug = False
        self.cyber = start_in_cyber
        self.identchars += "."

    def __getattr__(self, attr: str) -> Any:
        if attr.startswith("help_"):
            _, _, command = attr.partition("_")
            try:
                func = getattr(self, self.CMD_PREFIX + command)
                return lambda: print(func.__doc__)
            except AttributeError:
                pass

        return object.__getattribute__(self, attr)

    @staticmethod
    def check_compatible(target: Target) -> bool:
        return True

    def get_names(self) -> list[str]:
        names = cmd.Cmd.get_names(self)

        # Add fake do_ and help_ entries to get_names return value
        # This is for help output and completion
        for c in [c.partition("_")[2] for c in names if c.startswith(self.CMD_PREFIX)]:
            names.append("do_" + c)
            names.append("help_" + c)

        return names

    def check_custom_command_execution(self, line: str) -> tuple[bool, Any]:
        """Check whether custom handling of the cmd can be performed and if so, do it. Returns a tuple containing a
        boolean whether or not a custom command execution was performed, and the result of said execution."""
        if line == "EOF":
            return True, True

        # Override default command execution to first attempt complex command execution
        command, command_args_str, line = self.parseline(line)

        if hasattr(self, self.CMD_PREFIX + command):
            return True, self._exec_command(command, command_args_str)

        return False, None

    def default(self, line: str):
        handled, response = self.check_custom_command_execution(line)
        if handled:
            return response
        return cmd.Cmd.default(self, line)

    def emptyline(self) -> None:
        """This function forces Python's cmd.Cmd module to behave like a regular shell.

        When entering an empty command, the cmd module will by default repeat the previous command.
        By defining an empty ``emptyline`` function we make sure no command is executed instead.
        See https://stackoverflow.com/a/16479030
        """
        pass

    def _exec(
        self, func: Callable[[list[str], TextIO], bool], command_args_str: str, no_cyber: bool = False
    ) -> Optional[bool]:
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
        else:
            ctx = contextlib.nullcontext()
            if self.cyber and not no_cyber:
                ctx = cyber.cyber(color=None, run_at_end=True)

            with ctx:
                return func(argparts, sys.stdout)

    def _exec_command(self, command: str, command_args_str: str) -> Optional[bool]:
        """Command execution helper for ``cmd_`` commands."""
        cmdfunc = getattr(self, self.CMD_PREFIX + command)
        argparser = generate_argparse_for_bound_method(cmdfunc, usage_tmpl=f"{command} {{usage}}")

        def _exec_(argparts: list[str], stdout: TextIO) -> bool:
            try:
                args = argparser.parse_args(argparts)
            except SystemExit:
                return
            return cmdfunc(args, stdout)

        # These commands enter a subshell, which doesn't work well with cyber
        no_cyber = cmdfunc.__func__ in (TargetCli.cmd_registry, TargetCli.cmd_enter)
        return self._exec(_exec_, command_args_str, no_cyber)

    def do_clear(self, line: str) -> Optional[bool]:
        """clear the terminal screen"""
        os.system("cls||clear")

    def do_exit(self, line: str) -> Optional[bool]:
        """exit shell"""
        return True

    def do_cyber(self, line: str):
        """cyber"""
        self.cyber = not self.cyber
        word, color = {False: ("D I S E N", cyber.Color.RED), True: ("E N", cyber.Color.YELLOW)}[self.cyber]
        with cyber.cyber(color=color):
            print(f"C Y B E R - M O D E - {word} G A G E D")

    def do_debug(self, line: str) -> Optional[bool]:
        """toggle debug mode"""
        self.debug = not self.debug
        if self.debug:
            print("Debug mode on")
        else:
            print("Debug mode off")


class TargetCmd(ExtendedCmd):
    DEFAULT_HISTFILE = "~/.dissect_history"
    DEFAULT_HISTFILESIZE = 10_000
    DEFAULT_HISTDIR = None
    DEFAULT_HISTDIRFMT = ".dissect_history_{uid}_{target}"

    def __init__(self, target: Target):
        self.target = target
        start_in_cyber = self.target.props.get("cyber")

        self.histfilesize = getattr(target._config, "HISTFILESIZE", self.DEFAULT_HISTFILESIZE)
        self.histdir = getattr(target._config, "HISTDIR", self.DEFAULT_HISTDIR)

        if self.histdir:
            self.histdirfmt = getattr(target._config, "HISTDIRFMT", self.DEFAULT_HISTDIRFMT)
            self.histfile = pathlib.Path(self.histdir).resolve() / pathlib.Path(
                self.histdirfmt.format(uid=os.getuid(), target=target.name)
            )
        else:
            self.histfile = pathlib.Path(getattr(target._config, "HISTFILE", self.DEFAULT_HISTFILE)).expanduser()

        super().__init__(start_in_cyber)

    def preloop(self) -> None:
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

    def check_custom_command_execution(self, line: str) -> tuple[bool, Any]:
        handled, response = super().check_custom_command_execution(line)
        if handled:
            return handled, response

        # The parent class has already attempted complex command execution, we now attempt target plugin command
        # execution
        command, command_args_str, line = self.parseline(line)

        if plugins := list(find_and_filter_plugins(self.target, command, [])):
            return True, self._exec_target(plugins, command_args_str)
        return False, None

    def _exec_target(self, funcs: list[PluginFunction], command_args_str: str) -> Optional[bool]:
        """Command exection helper for target plugins."""

        def _exec_(argparts: list[str], stdout: TextIO) -> Optional[bool]:
            try:
                output, value, _ = execute_function_on_target(self.target, func, argparts)
            except SystemExit:
                return False

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

        result = None
        for func in funcs:
            try:
                result = self._exec(_exec_, command_args_str)
            except PluginError as err:
                if self.debug:
                    raise err
                self.target.log.error(err)

        return result

    def do_python(self, line: str) -> Optional[bool]:
        """drop into a Python shell"""
        python_shell([self.target])


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

    def default(self, line: str) -> Optional[bool]:
        if line == "EOF":
            return True

        return cmd.Cmd.default(self, line)

    def emptyline(self) -> None:
        pass

    def do_exit(self, line: str) -> Optional[bool]:
        """exit shell"""
        return True

    def do_list(self, line: str) -> Optional[bool]:
        """list the loaded targets"""
        print("\n".join([f"{i:2d}: {e}" for i, e in enumerate(self._names)]))

    def do_enter(self, line: str) -> Optional[bool]:
        """enter a target by number or name"""

        if line.isdigit():
            idx = int(line)
        else:
            try:
                idx = self._names_lower.index(line.lower())
            except ValueError:
                print("Unknown name")
                return

        if idx >= len(self.targets):
            print("Unknown target")
            return

        try:
            cli = self._clicache[idx]
        except KeyError:
            target = self.targets[idx]
            if not self._targetcli.check_compatible(target):
                return

            cli = self._targetcli(self.targets[idx])
            self._clicache[idx] = cli

        print(f"Entering {idx}: {self._names[idx]}")
        run_cli(cli)

    def complete_enter(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        if not text:
            return self._names[:]

        compl = [h for h in self._names if h.lower().startswith(text.lower())]

        # Also provide completion for multidigit numbers
        if text.isdigit():
            compl.extend([str(i) for i in range(len(self.targets)) if str(i).startswith(text)])

        return compl

    def do_python(self, line: str) -> Optional[bool]:
        """drop into a Python shell"""
        python_shell(self.targets)


class TargetCli(TargetCmd):
    """CLI for interacting with a target and browsing the filesystem."""

    def __init__(self, target: Target):
        TargetCmd.__init__(self, target)
        self.prompt_base = target.name
        self._clicache = {}

        self.cwd = None
        self.chdir("/")

    @property
    def prompt(self) -> str:
        return f"{self.prompt_base} {self.cwd}> "

    def completedefault(self, text: str, line: str, begidx: int, endidx: int):
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
            except ValueError as err:
                # The generator returned by glob() will raise a
                # ValueError if the '**' glob is not used as an entire path
                # component
                print(err)

    def check_file(self, path: str) -> Optional[fsutil.TargetPath]:
        path = self.resolve_path(path)
        if not path.exists():
            print(f"{path}: No such file")
            return

        if path.is_dir():
            print(f"{path}: Is a directory")
            return

        if not path.is_file():
            print(f"{path}: Not a file")
            return

        return path

    def check_dir(self, path: str) -> Optional[fsutil.TargetPath]:
        path = self.resolve_path(path)
        if not path.exists():
            print(f"{path}: No such directory")
            return

        if path.is_file():
            print(f"{path}: Is a file")
            return

        if not path.is_dir():
            print(f"{path}: Not a directory")
            return

        return path

    def chdir(self, path: str) -> None:
        """Change directory to the given path."""
        if path := self.check_dir(path):
            self.cwd = path

    def do_cd(self, line: str) -> Optional[bool]:
        """change directory"""
        self.chdir(line)

    def do_pwd(self, line: str) -> Optional[bool]:
        """print current directory"""
        print(self.cwd)

    def do_disks(self, line: str) -> Optional[bool]:
        """print target disks"""
        for d in self.target.disks:
            print(str(d))

    def do_volumes(self, line: str) -> Optional[bool]:
        """print target volumes"""
        for v in self.target.volumes:
            print(str(v))

    def do_filesystems(self, line: str) -> Optional[bool]:
        """print target filesystems"""
        for fs in self.target.filesystems:
            print(str(fs))

    def do_info(self, line: str) -> Optional[bool]:
        """print target information"""
        return print_target_info(self.target)

    @arg("path", nargs="?")
    @arg("-l", action="store_true")
    @arg("-a", "--all", action="store_true")  # ignored but included for proper argument parsing
    @arg("-h", "--human-readable", action="store_true")
    @arg("-R", "--recursive", action="store_true", help="recursively list subdirectories encountered")
    @arg("-c", action="store_true", dest="use_ctime", help="show time when file status was last changed")
    @arg("-u", action="store_true", dest="use_atime", help="show time of last access")
    def cmd_ls(self, args: argparse.Namespace, stdout: TextIO) -> Optional[bool]:
        """list directory contents"""

        path = self.resolve_path(args.path)

        if args.use_ctime and args.use_atime:
            print("can't specify -c and -u at the same time")
            return

        if not path or not path.exists():
            return

        print_ls(path, 0, stdout, args.l, args.human_readable, args.recursive, args.use_ctime, args.use_atime)

    @arg("path", nargs="?")
    @arg("-name", default="*")
    @arg("-iname")
    def cmd_find(self, args: argparse.Namespace, stdout: TextIO) -> Optional[bool]:
        """search for files in a directory hierarchy"""
        path = self.resolve_path(args.path)
        if not path:
            return

        if args.iname:
            pattern = re.compile(fnmatch.translate(args.iname), re.IGNORECASE)
            for f in path.rglob("*"):
                if pattern.match(f.name):
                    print(f, file=stdout)

        elif args.name:
            for f in path.rglob(args.name):
                print(f, file=stdout)

    @arg("path")
    @arg("-L", "--dereference", action="store_true")
    def cmd_stat(self, args: argparse.Namespace, stdout: TextIO) -> Optional[bool]:
        """display file status"""
        path = self.resolve_path(args.path)
        if not path:
            return

        print_stat(path, stdout, args.dereference)

    @arg("path")
    def cmd_file(self, args: argparse.Namespace, stdout: TextIO) -> Optional[bool]:
        """determine file type"""
        path = self.check_file(args.path)
        if not path:
            return

        fh = path.open()

        # We could just alias this to cat <path> | file -, but this is slow for large files
        # This way we can explicitly limit to just 512 bytes
        p = subprocess.Popen(["file", "-"], stdin=subprocess.PIPE, stdout=subprocess.PIPE)
        p.stdin.write(fh.read(512))
        p.stdin.close()
        p.wait()
        filetype = p.stdout.read().decode().split(":", 1)[1].strip()
        print(f"{path}: {filetype}", file=stdout)

    @arg("path", nargs="+")
    @arg("-o", "--out", default=".")
    @arg("-v", "--verbose", action="store_true")
    def cmd_save(self, args: argparse.Namespace, stdout: TextIO) -> Optional[bool]:
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
            diverging_path = pathlib.Path("")

            for diff_idx, path_part in enumerate(reference_path.parts):
                if path_part != path.parts[diff_idx]:
                    diverging_parts = path.parts[diff_idx:]
                    if diverging_parts:
                        for part in diverging_parts:
                            diverging_path = diverging_path.joinpath(pathlib.Path(part))
                    break

            return diverging_path

        def save_path(
            src_path: pathlib.Path, dst_path: pathlib.Path, create_dst_subdir: Optional[pathlib.Path] = None
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
                elif dst_path.exists():
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
                print(f"{path}: no such file or directory")
                return

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

    @arg("path")
    def cmd_cat(self, args: argparse.Namespace, stdout: TextIO) -> Optional[bool]:
        """print file content"""
        paths = self.resolve_glob_path(args.path)
        stdout = stdout.buffer
        for path in paths:
            path = self.check_file(path)
            if not path:
                continue

            fh = path.open()
            shutil.copyfileobj(fh, stdout)
            stdout.flush()
        print("")

    @arg("path")
    def cmd_zcat(self, args: argparse.Namespace, stdout: TextIO) -> Optional[bool]:
        """print file content from compressed files"""
        paths = self.resolve_glob_path(args.path)
        stdout = stdout.buffer
        for path in paths:
            path = self.check_file(path)
            if not path:
                continue

            fh = fsutil.open_decompress(path)
            shutil.copyfileobj(fh, stdout)
            stdout.flush()

    @arg("path")
    def cmd_hexdump(self, args: argparse.Namespace, stdout: TextIO) -> Optional[bool]:
        """print a hexdump of the first X bytes"""
        path = self.check_file(args.path)
        if not path:
            return

        print(hexdump(path.open().read(16 * 20), output="string"), file=stdout)

    @arg("path")
    def cmd_hash(self, args: argparse.Namespace, stdout: TextIO) -> Optional[bool]:
        """print the MD5, SHA1 and SHA256 hashes of a file"""
        path = self.check_file(args.path)
        if not path:
            return

        md5, sha1, sha256 = path.get().hash()
        print(f"MD5:\t{md5}\nSHA1:\t{sha1}\nSHA256:\t{sha256}", file=stdout)

    @arg("path")
    def cmd_less(self, args: argparse.Namespace, stdout: TextIO) -> Optional[bool]:
        """open the first 10 MB of a file with less"""
        path = self.check_file(args.path)
        if not path:
            return

        pydoc.pager(path.open("rt", errors="ignore").read(10 * 1024 * 1024))

    @arg("path")
    def cmd_zless(self, args: argparse.Namespace, stdout: TextIO) -> Optional[bool]:
        """open the first 10 MB of a compressed file with zless"""
        path = self.check_file(args.path)
        if not path:
            return

        pydoc.pager(fsutil.open_decompress(path, "rt").read(10 * 1024 * 1024))

    @arg("path", nargs="+")
    def cmd_readlink(self, args: argparse.Namespace, stdout: TextIO) -> Optional[bool]:
        """print resolved symbolic links or canonical file names"""
        for path in args.path:
            path = self.resolve_path(path)
            if not path.is_symlink():
                continue

            print(path.get().readlink(), file=stdout)

    @arg("path", nargs="?", help="load a hive from the given path")
    def cmd_registry(self, args: argparse.Namespace, stdout: TextIO) -> Optional[bool]:
        """drop into a registry shell"""
        if self.target.os == "linux":
            run_cli(UnixConfigTreeCli(self.target))
            return

        hive = None

        clikey = "registry"
        if args.path:
            path = self.check_file(args.path)
            if not path:
                return

            hive = regutil.RegfHive(path)
            clikey = f"registry_{path}"

        try:
            cli = self._clicache[clikey]
        except KeyError:
            if not hive and not RegistryCli.check_compatible(self.target):
                return

            cli = RegistryCli(self.target, hive)
            self._clicache[clikey] = cli

        run_cli(cli)

        # Print an additional empty newline after exit
        print()

    @arg("targets", metavar="TARGETS", nargs="*", help="targets to load")
    @arg("-p", "--python", action="store_true", help="(I)Python shell")
    @arg("-r", "--registry", action="store_true", help="registry shell")
    def cmd_enter(self, args: argparse.Namespace, stdout: TextIO) -> None:
        """load one or more files as sub-targets and drop into a sub-shell"""
        paths = [self.resolve_path(path) for path in args.targets]

        if args.python:
            # Quick path that doesn't require CLI caching
            return open_shell(paths, args.python, args.registry)

        clikey = tuple(str(path) for path in paths)
        try:
            cli = self._clicache[clikey]
        except KeyError:
            targets = list(Target.open_all(paths))
            cli = create_cli(targets, RegistryCli if args.registry else TargetCli)
            if not cli:
                return

            self._clicache[clikey] = cli

        run_cli(cli)

        # Print an additional empty newline after exit
        print()


class UnixConfigTreeCli(TargetCli):
    def __init__(self, target: Target):
        TargetCmd.__init__(self, target)
        self.config_tree = target.etc()
        self.prompt_base = target.name

        self.cwd = None
        self.chdir("/")

    @property
    def prompt(self) -> str:
        return f"{self.prompt_base}/config_tree {self.cwd}> "

    def check_compatible(target: Target) -> bool:
        return target.has_function("etc")

    def resolve_path(self, path: Optional[Union[str, fsutil.TargetPath]]) -> fsutil.TargetPath:
        if not path:
            return self.cwd

        if isinstance(path, fsutil.TargetPath):
            return path

        # It uses the alt separator of the underlying fs
        path = fsutil.abspath(path, cwd=str(self.cwd), alt_separator=self.target.fs.alt_separator)
        return self.config_tree.path(path)

    def resolve_key(self, path) -> FilesystemEntry:
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
            except ValueError as err:
                # The generator returned by glob() will raise a
                # ValueError if the '**' glob is not used as an entire path
                # component
                print(err)


class RegistryCli(TargetCmd):
    """CLI for browsing the registry."""

    def __init__(self, target: Target, registry: Optional[regutil.RegfHive] = None):
        TargetCmd.__init__(self, target)
        self.registry = registry or target.registry

        self.prompt_base = target.name

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
        prompt_end = self.cwd.strip("\\")
        return f"{self.prompt_base}/registry {prompt_end}> "

    def completedefault(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        path = line[:begidx].rsplit(" ")[-1]
        return [fname for _, fname in self.scandir(path) if fname.lower().startswith(text.lower())]

    def resolve_key(self, path: str) -> regutil.RegistryKey:
        if isinstance(path, regutil.RegistryKey):
            return path

        if path and not path.startswith("\\"):
            path = "\\".join([self.cwd, path])
        else:
            path = path or self.cwd
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
            path = "\\".join([self.cwd, path])

        if self.check_key(path):
            self.cwd = "\\" + path.strip("\\")

    def scandir(
        self, path: str, color: bool = False
    ) -> list[tuple[Union[regutil.RegistryKey, regutil.RegistryValue], str]]:
        try:
            key = self.resolve_key(path)
        except RegistryError:
            return []

        r = []
        for s in key.subkeys():
            r.append((s, fmt_ls_colors("di", s.name) if color else s.name))

        for v in key.values():
            r.append((v, fmt_ls_colors("fi", v.name) if color else v.name))

        r.sort(key=lambda e: e[0].name)
        return r

    def do_cd(self, line: str) -> Optional[bool]:
        """change subkey"""
        self.chdir(line)

    def do_up(self, line: str) -> Optional[bool]:
        """go up a subkey"""
        parent = self.cwd.rpartition("\\")[0]
        if not parent:
            parent = "\\"
        self.chdir(parent)

    def do_pwd(self, line: str) -> Optional[bool]:
        """print current path"""
        print(self.cwd)

    def do_recommend(self, line: str) -> Optional[bool]:
        """recommend a key"""
        print(random.choice([name for _, name in self.scandir(None)]))

    @arg("path", nargs="?")
    def cmd_ls(self, args: argparse.Namespace, stdout: TextIO) -> Optional[bool]:
        key = self.check_key(args.path)
        if not key:
            return

        r = self.scandir(key, color=True)
        print("\n".join([name for _, name in r]), file=stdout)

    @arg("value")
    def cmd_cat(self, args: argparse.Namespace, stdout: TextIO) -> Optional[bool]:
        value = self.check_value(args.value)
        if not value:
            return

        print(repr(value.value), file=stdout)


def arg_str_to_arg_list(args: str) -> list[str]:
    """Convert a commandline string to a list of command line arguments."""
    lexer = shlex.shlex(args, posix=True, punctuation_chars=True)
    lexer.wordchars += "$"
    lexer.whitespace_split = True
    return list(lexer)


@contextmanager
def build_pipe(pipe_parts: list[str], pipe_stdout: int = subprocess.PIPE) -> Iterator[tuple[TextIO, BinaryIO]]:
    """
    Generator context manager that chains piped subprocessess and
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
    """
    Generator context manager that chains piped subprocessess, with a chain's
    outgoing stream configured to be parent's stdout.

    Generator returns a chain's input stream from `build_pipe` generator.
    """
    with build_pipe(pipe_parts, pipe_stdout=None) as (pipe_stdin, _):
        yield pipe_stdin


def open_shell(targets: list[Union[str, pathlib.Path]], python: bool, registry: bool) -> None:
    """Helper method for starting a regular, Python or registry shell for one or multiple targets."""
    targets = list(Target.open_all(targets))

    if python:
        python_shell(targets)
    else:
        cli_cls = RegistryCli if registry else TargetCli
        target_shell(targets, cli_cls=cli_cls)


def target_shell(targets: list[Target], cli_cls: type[TargetCmd]) -> None:
    """Helper method for starting a :class:`TargetCli` or :class:`TargetHubCli` for one or multiple targets."""
    if cli := create_cli(targets, cli_cls):
        run_cli(cli)


def python_shell(targets: list[Target]) -> None:
    """Helper method for starting a (I)Python shell with multiple targets."""
    banner = "Loaded targets in 'targets' variable. First target is in 't'."
    ns = {"targets": targets, "t": targets[0]}

    try:
        import IPython

        IPython.embed(header=banner, user_ns=ns, colors="linux")

        # IPython already prints an empty newline
    except ImportError:
        import code

        shell = code.InteractiveConsole(ns)
        shell.interact(banner)

        # Print an empty newline on exit
        print()


def create_cli(targets: list[Target], cli_cls: type[TargetCmd]) -> Optional[cmd.Cmd]:
    """Helper method for instatiating the appropriate CLI."""
    if len(targets) == 1:
        target = targets[0]
        if not cli_cls.check_compatible(target):
            return

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

            # Print an empty newline on exit
            print()
            return

        except KeyboardInterrupt:
            # Add a line when pressing ctrl+c, so the next one starts at a new line
            print()

        except Exception as e:
            if cli.debug:
                log.exception(e)
            else:
                log.info(e)
                print(f"*** Unhandled error: {e}")
                print("If you wish to see the full debug trace, enable debug mode.")


@catch_sigpipe
def main() -> None:
    help_formatter = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(
        description="dissect.target",
        fromfile_prefix_chars="@",
        formatter_class=help_formatter,
    )
    parser.add_argument("targets", metavar="TARGETS", nargs="*", help="targets to load")
    parser.add_argument("-p", "--python", action="store_true", help="(I)Python shell")
    parser.add_argument("-r", "--registry", action="store_true", help="registry shell")
    parser.add_argument(
        "-L",
        "--loader",
        action="store",
        default=None,
        help="select a specific loader (i.e. vmx, raw)",
    )

    configure_generic_arguments(parser)
    args, rest = parser.parse_known_args()
    args.targets = args_to_uri(args.targets, args.loader, rest) if args.loader else args.targets
    process_generic_arguments(args)

    # For the shell tool we want -q to log slightly more then just CRITICAL
    # messages.
    if args.quiet:
        logging.getLogger("dissect").setLevel(level=logging.ERROR)

    try:
        open_shell(args.targets, args.python, args.registry)
    except TargetError as e:
        log.error(e)
        log.debug("", exc_info=e)


if __name__ == "__main__":
    main()
