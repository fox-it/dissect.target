#!/usr/bin/env python
from __future__ import annotations

import argparse
import dataclasses
import logging
import os
import re
import shutil
import sys
from difflib import diff_bytes, unified_diff
from fnmatch import fnmatch, translate
from io import BytesIO
from typing import TYPE_CHECKING, TextIO

from dissect.cstruct import hexdump
from flow.record import Record, RecordOutput, ignore_fields_for_comparison

from dissect.target.exceptions import FileNotFoundError
from dissect.target.helpers import fsutil
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import alias, arg
from dissect.target.target import Target
from dissect.target.tools.fsutils import print_extensive_file_stat_listing
from dissect.target.tools.query import record_output
from dissect.target.tools.shell import (
    ExtendedCmd,
    TargetCli,
    _target_name,
    arg_str_to_arg_list,
    build_pipe_stdout,
    fmt_ls_colors,
    python_shell,
    run_cli,
)
from dissect.target.tools.utils import (
    catch_sigpipe,
    configure_generic_arguments,
    generate_argparse_for_bound_method,
    process_generic_arguments,
)

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.filesystem import FilesystemEntry

log = logging.getLogger(__name__)
logging.lastResort = None
logging.raiseExceptions = False

BLOCK_SIZE = 2048
FILE_LIMIT = BLOCK_SIZE * 16

FILE_DIFF_RECORD_FIELDS = [
    ("string", "src_target"),
    ("string", "dst_target"),
    ("string", "path"),
]
RECORD_DIFF_RECORD_FIELDS = [
    ("string", "src_target"),
    ("string", "dst_target"),
    ("record", "record"),
]

FileDeletedRecord = TargetRecordDescriptor("differential/file/deleted", FILE_DIFF_RECORD_FIELDS)
FileCreatedRecord = TargetRecordDescriptor("differential/file/created", FILE_DIFF_RECORD_FIELDS)
FileModifiedRecord = TargetRecordDescriptor(
    "differential/file/modified",
    [*FILE_DIFF_RECORD_FIELDS, ("bytes[]", "diff")],
)

RecordCreatedRecord = TargetRecordDescriptor("differential/record/created", RECORD_DIFF_RECORD_FIELDS)
RecordDeletedRecord = TargetRecordDescriptor("differential/record/deleted", RECORD_DIFF_RECORD_FIELDS)
RecordUnchangedRecord = TargetRecordDescriptor("differential/record/unchanged", RECORD_DIFF_RECORD_FIELDS)


@dataclasses.dataclass
class DifferentialEntry:
    """Signifies a change for a FilesystemEntry between two versions of a target."""

    path: str
    name: str
    src_target_entry: FilesystemEntry
    dst_target_entry: FilesystemEntry
    diff: list[bytes]


@dataclasses.dataclass
class DirectoryDifferential:
    """For a given directory, contains the unchanged, created, modified and deleted entries, as well as a list of
    subdirectories."""

    directory: str
    unchanged: list[FilesystemEntry] = dataclasses.field(default_factory=list)
    created: list[FilesystemEntry] = dataclasses.field(default_factory=list)
    modified: list[DifferentialEntry] = dataclasses.field(default_factory=list)
    deleted: list[FilesystemEntry] = dataclasses.field(default_factory=list)


def likely_unchanged(src: fsutil.stat_result, dst: fsutil.stat_result) -> bool:
    """Determine whether or not, based on the file stats, we can assume a file hasn't been changed."""
    return not (src.st_size != dst.st_size or src.st_mtime != dst.st_mtime or src.st_ctime != dst.st_ctime)


def get_plugin_output_records(plugin_name: str, plugin_arg_parts: list[str], target: Target) -> Iterator[Record]:
    """Command exection helper for target plugins.

    Highly similar to target-shell's ``_exec_target``, however this function
    only accepts plugins that outputs records, and returns an iterable of records rather than a function that outputs
    to stdout.
    """
    attr = target
    for part in plugin_name.split("."):
        attr = getattr(attr, part)

    if getattr(attr, "__output__", "default") != "record":
        raise ValueError("Comparing plugin output is only supported for plugins outputting records.")

    if callable(attr):
        argparser = generate_argparse_for_bound_method(attr)
        try:
            args = argparser.parse_args(plugin_arg_parts)
        except SystemExit:
            return False

        return attr(**vars(args))

    return attr


class TargetComparison:
    """This class wraps functionality that for two given targets can identify similarities and differences between them.

    Currently supports differentiating between the target filesystems, and between plugin outputs.
    """

    def __init__(
        self,
        src_target: Target,
        dst_target: Target,
        deep: bool = False,
        file_limit: int = FILE_LIMIT,
    ):
        self.src_target = src_target
        self.dst_target = dst_target
        self.deep = deep
        self.file_limit = file_limit

    def scandir(self, path: str) -> DirectoryDifferential:
        """Scan a given directory for files that have been unchanged, modified, created or deleted from one target to
        the next. Add these results (as well as subdirectories) to a DirectoryDifferential object."""
        unchanged = []
        modified = []
        exists_as_directory_src = self.src_target.fs.exists(path) and self.src_target.fs.get(path).is_dir()
        exists_as_directory_dst = self.dst_target.fs.exists(path) and self.dst_target.fs.get(path).is_dir()

        if not (exists_as_directory_src and exists_as_directory_dst):
            if exists_as_directory_src:
                # Path only exists on src target, hence all entries can be considered 'deleted'
                entries = list(self.src_target.fs.scandir(path))
                return DirectoryDifferential(path, deleted=entries)
            if exists_as_directory_dst:
                # Path only exists on dst target, hence all entries can be considered 'created'
                entries = list(self.dst_target.fs.scandir(path))
                return DirectoryDifferential(path, created=entries)
            raise ValueError(f"{path} is not a directory on either the source or destination target!")

        src_target_entries = list(self.src_target.fs.scandir(path))
        src_target_children_paths = {entry.path for entry in src_target_entries}

        dst_target_entries = list(self.dst_target.fs.scandir(path))
        dst_target_children_paths = {entry.path for entry in dst_target_entries}

        paths_only_on_src_target = src_target_children_paths - dst_target_children_paths
        paths_only_on_dst_target = dst_target_children_paths - src_target_children_paths

        deleted = [entry for entry in src_target_entries if entry.path in paths_only_on_src_target]
        created = [entry for entry in dst_target_entries if entry.path in paths_only_on_dst_target]

        paths_on_both = src_target_children_paths.intersection(dst_target_children_paths)
        entry_pairs = []

        for dst_entry in dst_target_entries:
            if dst_entry.path not in paths_on_both:
                continue
            src_entry = next((entry for entry in src_target_entries if entry.path == dst_entry.path), None)
            entry_pairs.append((src_entry, dst_entry))

        for entry_pair in entry_pairs:
            src_entry, dst_entry = entry_pair
            entry_path = src_entry.path

            # It's possible that there is an entry, but upon trying to retrieve its stats / content, we get a
            # FileNotFoundError. We account for this by wrapping both stat retrievals in a try except
            src_target_notfound = False
            dst_target_notfound = False
            src_target_isdir = None
            dst_target_isdir = None

            try:
                src_target_stat = src_entry.stat()
                src_target_isdir = src_entry.is_dir()
            except FileNotFoundError:
                src_target_notfound = True

            try:
                dst_target_stat = dst_entry.stat()
                dst_target_isdir = dst_entry.is_dir()
            except FileNotFoundError:
                dst_target_notfound = True

            if src_target_notfound or dst_target_notfound:
                if src_target_notfound and not dst_target_notfound:
                    created.append(dst_entry)
                elif dst_target_notfound and not src_target_notfound:
                    deleted.append(src_entry)
                else:
                    # Not found on both
                    unchanged.append(src_entry)
                # We can't continue as we cannot access the stats (or buffer)
                continue

            if src_target_isdir or dst_target_isdir:
                if src_target_isdir == dst_target_isdir:
                    unchanged.append(src_entry)
                else:
                    # Went from a file to a dir, or from a dir to a file. Either way, we consider the source entry
                    # 'deleted' and the dst entry 'Created'
                    deleted.append(src_entry)
                    created.append(dst_entry)
                continue

            if self.deep is False and likely_unchanged(src_target_stat, dst_target_stat):
                unchanged.append(src_entry)
                continue

            # If we get here, we have two files that we need to compare contents of
            src_fh = src_entry.open()
            dst_fh = dst_entry.open()

            # We reverse read the file object.
            chunk_size = 1024 * 10
            chunks_a = fsutil.reverse_read(src_fh, chunk_size, reverse_chunk=False)
            chunks_b = fsutil.reverse_read(dst_fh, chunk_size, reverse_chunk=False)

            chunk_count = 0

            while True:
                chunk_a = next(chunks_a, b"")
                chunk_b = next(chunks_b, b"")
                chunk_count += 1

                if chunk_a != chunk_b:
                    # We immediately break after discovering a difference in file contents
                    # This means that we won't return a full diff of the file, merely the first block where a difference
                    # is observed. The chunk is not reversed, so the difference is human-readable.
                    content_difference = list(diff_bytes(unified_diff, [chunk_a], [chunk_b]))
                    differential_entry = DifferentialEntry(
                        entry_path,
                        src_entry.name,
                        src_entry,
                        dst_entry,
                        content_difference,
                    )
                    modified.append(differential_entry)
                    break

                if self.file_limit and chunk_count * chunk_size > self.file_limit:
                    unchanged.append(src_entry)
                    break

                if not chunk_a:
                    # End of file
                    unchanged.append(src_entry)
                    break

        return DirectoryDifferential(path, unchanged, created, modified, deleted)

    def walkdir(
        self,
        path: str,
        exclude: list[str] | str | None = None,
        already_iterated: list[str] | None = None,
    ) -> Iterator[DirectoryDifferential]:
        """Recursively iterate directories and yield DirectoryDifferentials."""
        if already_iterated is None:
            already_iterated = []

        if path in already_iterated:
            return

        if exclude is not None and not isinstance(exclude, list):
            exclude = [exclude]

        already_iterated.append(path)

        # Do not scan the given path if it matches any excluded path.
        if exclude and next((pattern for pattern in exclude if fnmatch(path, pattern)), None):
            return

        diff = self.scandir(path)

        # Check if diff contains excluded paths
        if exclude:
            for t in ["created", "unchanged", "modified", "deleted"]:
                for i, d in enumerate(getattr(diff, t)):
                    if next((pattern for pattern in exclude if fnmatch(d.path, pattern)), None):
                        del getattr(diff, t)[i]
        yield diff

        subentries = diff.created + diff.unchanged + diff.deleted
        subdirectories = [entry for entry in subentries if entry.is_dir()]
        # Check if the scandir lead to the discovery of new directories that we have to scan for differentials
        # Directories are always in 'unchanged'
        for subdirectory in subdirectories:
            if subdirectory in already_iterated:
                continue

            # Right-pad with a '/'
            subdirectory_path = subdirectory.path if subdirectory.path.endswith("/") else subdirectory.path + "/"
            if exclude:
                match = next((pattern for pattern in exclude if fnmatch(subdirectory_path, pattern)), None)
                if match:
                    continue
            yield from self.walkdir(subdirectory.path, exclude, already_iterated)

    def differentiate_plugin_outputs(
        self, plugin_name: str, plugin_arg_parts: list[str], only_changed: bool = False
    ) -> Iterator[Record]:
        """Run a plugin on the source and destination targets and yield RecordUnchanged, RecordCreated and RecordDeleted
        records.

        There is no equivalent for the FileModifiedRecord. For files and directories, we can use the path to
        reliably track changes from one target to the next. There is no equivalent for plugin outputs, so we just assume
        that all records are either deleted (only on src), created (only on dst) or unchanged (on both).
        """
        with ignore_fields_for_comparison(["_generated", "_source", "hostname", "domain"]):
            src_records = set(get_plugin_output_records(plugin_name, plugin_arg_parts, self.src_target))
            src_records_seen = set()

            for dst_record in get_plugin_output_records(plugin_name, plugin_arg_parts, self.dst_target):
                if dst_record in src_records:
                    src_records_seen.add(dst_record)
                    if not only_changed:
                        yield RecordUnchangedRecord(
                            src_target=self.src_target.path, dst_target=self.dst_target.path, record=dst_record
                        )
                else:
                    yield RecordCreatedRecord(
                        src_target=self.src_target.path, dst_target=self.dst_target.path, record=dst_record
                    )
            for record in src_records - src_records_seen:
                yield RecordDeletedRecord(
                    src_target=self.src_target.path, dst_target=self.dst_target.path, record=record
                )


class DifferentialCli(ExtendedCmd):
    """CLI for browsing the differential between two or more targets."""

    doc_header_prefix = "target-diff\n==========\n"
    doc_header_suffix = "\n\nDocumented commands (type help <topic>):"
    doc_header_multiple_targets = "Use 'list', 'prev' and 'next' to list and select targets to differentiate between."

    def __init__(self, *targets: tuple[Target], deep: bool = False, limit: int = FILE_LIMIT):
        self.targets = targets
        self.deep = deep
        self.limit = limit

        self.src_index = 0
        self.dst_index = 0
        self.comparison: TargetComparison = None

        self.cwd = "/"
        self.alt_separator = "/"

        doc_header_middle = self.doc_header_multiple_targets if len(targets) > 2 else ""
        self.doc_header = self.doc_header_prefix + doc_header_middle + self.doc_header_suffix

        self._select_source_and_dest(0, 1)

        start_in_cyber = any(target.props.get("cyber") for target in self.targets)
        super().__init__(start_in_cyber)

        if len(self.targets) > 2:
            # Some help may be nice if you are diffing more than 2 targets at once
            self.do_help(arg=None)

    @property
    def src_target(self) -> Target:
        return self.targets[self.src_index]

    @property
    def dst_target(self) -> Target:
        return self.targets[self.dst_index]

    @property
    def prompt(self) -> str:
        """Determine the prompt of the cli."""

        src_name = _target_name(self.comparison.src_target)
        dst_name = _target_name(self.comparison.dst_target)

        prompt_base = f"{src_name}/{dst_name}" if src_name != dst_name else src_name

        if os.getenv("NO_COLOR"):
            suffix = f"{prompt_base}:{self.cwd}$ "
        else:
            suffix = f"\x1b[1;32m{prompt_base}\x1b[0m:\x1b[1;34m{self.cwd}\x1b[0m$ "

        if len(self.targets) <= 2:
            return f"(diff) {suffix}"

        chain_prefix = "[ "
        for i in range(len(self.targets)):
            char = "O " if i == self.src_index or i == self.dst_index else ". "
            chain_prefix += char
        chain_prefix += "] "

        return f"(diff) {chain_prefix}{suffix}"

    def _select_source_and_dest(self, src_index: int, dst_index: int) -> None:
        """Set local variables according to newly selected source and destination index, and re-instatiate
        TargetComparison."""
        self.src_index = src_index
        self.dst_index = dst_index
        if not self.src_target.fs.exists(self.cwd) and not self.dst_target.fs.exists(self.cwd):
            logging.warning("The current directory exists on neither of the selected targets")
        if self.src_target.fs.alt_separator != self.dst_target.fs.alt_separator:
            raise NotImplementedError("No support for handling targets with different path separators")

        self.alt_separator = self.src_target.fs.alt_separator
        self.comparison = TargetComparison(self.src_target, self.dst_target, self.deep, self.limit)

    def _annotate_differential(
        self,
        diff: DirectoryDifferential,
        unchanged: bool = True,
        created: bool = True,
        modified: bool = True,
        deleted: bool = True,
        absolute: bool = False,
    ) -> list[tuple[fsutil.TargetPath | DifferentialEntry], str]:
        """Given a DirectoryDifferential instance, construct a list of tuples where the first element is a Filesystem /
        DifferentialEntry and the second a color-formatted string."""
        r = []

        attr = "path" if absolute else "name"
        if unchanged:
            for entry in diff.unchanged:
                color = "di" if entry.is_dir() else "fi"
                r.append((entry, fmt_ls_colors(color, getattr(entry, attr))))

        if created:
            for entry in diff.created:
                color = "tw" if entry.is_dir() else "ex"
                r.append((entry, fmt_ls_colors(color, f"{getattr(entry, attr)} (created)")))

        if modified:
            for entry in diff.modified:
                # Modified entries are always files
                r.append((entry, fmt_ls_colors("ln", f"{getattr(entry, attr)} (modified)")))  # noqa: PERF401
        if deleted:
            for entry in diff.deleted:
                color = "su" if entry.is_dir() else "or"
                r.append((entry, fmt_ls_colors(color, f"{getattr(entry, attr)} (deleted)")))

        r.sort(key=lambda e: e[0].name)
        return r

    def _targets_with_directory(self, path: str, warn_when_incomplete: bool = False) -> int:
        """Return whether a given path is an existing directory for neither, one of, or both of the targets being
        compared. Optionally log a warning if the directory only exists on one of the two targets."""
        src_has_dir = False
        dst_has_dir = False
        try:
            entry = self.comparison.src_target.fs.get(path)
            src_has_dir = entry.is_dir()
        except FileNotFoundError:
            pass
        try:
            entry = self.comparison.dst_target.fs.get(path)
            dst_has_dir = entry.is_dir()
        except FileNotFoundError:
            pass

        if (src_has_dir is False or dst_has_dir is False) and warn_when_incomplete:
            if src_has_dir != dst_has_dir:
                target_with_dir = self.comparison.src_target if src_has_dir else self.comparison.dst_target
                log.warning("%r is only a valid path on '%s'", path, target_with_dir)
            else:
                log.warning("%r is not a valid path on either target", path)
        return int(src_has_dir) + int(dst_has_dir)

    def _write_entry_contents_to_stdout(self, entry: FilesystemEntry, stdout: TextIO) -> bool:
        """Copy the contents of a Filesystementry to stdout."""
        stdout = stdout.buffer
        fh = entry.open()
        shutil.copyfileobj(fh, stdout)
        stdout.flush()
        print()
        return False

    def completedefault(self, text: str, line: str, begidx: int, endidx: int) -> list[str]:
        """Autocomplete based on files / directories found in the current path."""
        path = line[:begidx].rsplit(" ")[-1]
        textlower = text.lower()

        path = fsutil.abspath(path, cwd=str(self.cwd), alt_separator=self.alt_separator)

        diff = self.comparison.scandir(path)
        items = [
            (item.entry.is_dir(), item.name) for group in [diff.created, diff.unchanged, diff.deleted] for item in group
        ]
        items += [
            (item.src_target_entry.is_dir() and item.dst_target_entry.is_dir(), item.name) for item in diff.modified
        ]
        suggestions = []
        for is_dir, fname in items:
            if not fname.lower().startswith(textlower):
                continue

            # Add a trailing slash to directories, to allow for easier traversal of the filesystem
            suggestion = f"{fname}/" if is_dir else fname
            suggestions.append(suggestion)
        return suggestions

    def do_list(self, line: str) -> bool:
        """print a list of targets to differentiate between

        Useful when differentiating between three or more targets. Looks quite bad on small terminal screens.
        """
        columns = ["#", "Name", "Path", "From", "To"]

        rows = []

        for i, target in enumerate(self.targets):
            rows.append(
                [
                    f"{i:2d}",
                    target.name,
                    str(target.path),
                    "**" if i == self.src_index else "",
                    "**" if i == self.dst_index else "",
                ]
            )

        longest_name = max(len(row[1]) + 4 for row in rows)
        longest_path = max(len(row[2]) + 4 for row in rows)
        name_len = max(10, longest_name)
        path_len = max(15, longest_path)

        fmt = "{:^5} | {:<" + str(name_len) + "} | {:<" + str(path_len) + "} | {:^6} | {:^6} |"
        print(fmt.format(*columns))
        print()
        for row in rows:
            print(fmt.format(*row))
            print()
        return False

    @alias("prev")
    @arg("-a", "--absolute", action="store_true", help="Only move the destination target one position back.")
    def cmd_previous(self, args: argparse.Namespace, line: str) -> bool:
        """when three or more targets are available, move the 'comparison window' one position back"""
        src_index = self.src_index - 1 if not args.absolute else 0
        if src_index < 0:
            src_index = len(self.targets) - 1
        dst_index = self.dst_index - 1
        if dst_index < 0:
            dst_index = len(self.targets) - 1
        if dst_index <= src_index:
            src_index, dst_index = dst_index, src_index
        self._select_source_and_dest(src_index, dst_index)
        return False

    @arg("-a", "--absolute", action="store_true", help="Only move the destination target one position forward.")
    def cmd_next(self, args: argparse.Namespace, line: str) -> bool:
        """when three or more targets are available, move the 'comparison window' one position forward"""
        dst_index = (self.dst_index + 1) % len(self.targets)
        src_index = self.src_index + 1 % len(self.targets) if not args.absolute else 0

        if dst_index <= src_index:
            src_index, dst_index = dst_index, src_index
        self._select_source_and_dest(src_index, dst_index)
        return False

    def do_cd(self, path: str) -> bool:
        """change directory to the given path"""
        path = fsutil.abspath(path, cwd=str(self.cwd), alt_separator=self.alt_separator)
        if self._targets_with_directory(path, warn_when_incomplete=True) != 0:
            self.cwd = path
        return False

    @arg("path", nargs="?")
    @arg("-l", action="store_true")
    @arg("-a", "--all", action="store_true")  # ignored but included for proper argument parsing
    @arg("-h", "--human-readable", action="store_true")
    def cmd_ls(self, args: argparse.Namespace, stdout: TextIO) -> bool:
        """list contents of a directory for two targets"""
        path = args.path if args.path is not None else self.cwd
        diff = self.comparison.scandir(path)
        results = self._annotate_differential(diff)
        if not args.l:
            print("\n".join([name for _, name in results]), file=stdout)
        else:
            for entry, name in results:
                if not isinstance(entry, DifferentialEntry):
                    print_extensive_file_stat_listing(stdout, name, entry, human_readable=args.human_readable)
                else:
                    # We have to choose for which version of this file we are going to print detailed info. The
                    # destination target seems to make the most sense: it is likely newer
                    print_extensive_file_stat_listing(
                        stdout, name, entry.dst_target_entry, human_readable=args.human_readable
                    )
        return False

    @arg("path", nargs="?")
    def cmd_cat(self, args: argparse.Namespace, stdout: TextIO) -> bool:
        """output the contents of a file"""
        base_dir, _, name = args.path.rpartition("/")
        if not base_dir:
            base_dir = self.cwd

        directory_differential = self.comparison.scandir(base_dir)
        entry = None
        for entry in directory_differential.unchanged:
            if entry.name == name:
                return self._write_entry_contents_to_stdout(entry, stdout)
        for entry in directory_differential.created:
            if entry.name == name:
                log.warning("%r is only present on '%s'", entry.name, self.comparison.dst_target.path)
                return self._write_entry_contents_to_stdout(entry, stdout)
        for entry in directory_differential.deleted:
            if entry.name == name:
                log.warning("%r is only present on '%s'", entry.name, self.comparison.src_target.path)
                return self._write_entry_contents_to_stdout(entry, stdout)
        for entry in directory_differential.modified:
            if entry.name == name:
                log.warning(
                    "Concatinating latest version of '%s'. Use 'diff' to differentiate between target versions.",
                    entry.name,
                )
                return self._write_entry_contents_to_stdout(entry.dst_target_entry, stdout)
        print(f"File {name} not found.")
        return False

    @arg("path", nargs="?")
    @arg("--hex", action="store_true")
    def cmd_diff(self, args: argparse.Namespace, stdout: TextIO) -> bool:
        """output the difference in file contents between two targets"""
        stdout = stdout.buffer
        base_dir, _, name = args.path.rpartition("/")
        if not base_dir:
            base_dir = self.cwd
        directory_differential = self.comparison.scandir(base_dir)
        for entry in directory_differential.modified:
            if entry.name == name:
                if args.hex:
                    primary_fh_lines = [
                        line.encode()
                        for line in hexdump(entry.src_target_entry.open().read(), output="string").split("\n")
                    ]
                    secondary_fh_lines = [
                        line.encode()
                        for line in hexdump(entry.dst_target_entry.open().read(), output="string").split("\n")
                    ]
                else:
                    primary_fh_lines = entry.src_target_entry.open().readlines()
                    secondary_fh_lines = entry.dst_target_entry.open().readlines()

                for chunk in diff_bytes(unified_diff, primary_fh_lines, secondary_fh_lines):
                    if chunk.startswith(b"@@"):
                        chunk = fmt_ls_colors("ln", chunk.decode()).encode()
                    elif chunk.startswith(b"+"):
                        chunk = fmt_ls_colors("ex", chunk.decode()).encode()
                    elif chunk.startswith(b"-"):
                        chunk = fmt_ls_colors("or", chunk.decode()).encode()

                    shutil.copyfileobj(BytesIO(chunk), stdout)

                    if args.hex:
                        stdout.write(b"\n")

                    stdout.flush()

                print()
                return False

        # Check if this file is even present on one of the targets
        files = directory_differential.unchanged + directory_differential.created + directory_differential.deleted
        match = next((entry for entry in files if entry.name == name), None)
        if match is None:
            print(f"File {name} not found.")
        else:
            print(f"No two versions available for {name} to differentiate between.")
        return False

    @arg("path", nargs="?")
    @alias("xxd")
    def cmd_hexdump(self, args: argparse.Namespace, stdout: TextIO) -> bool:
        """output difference of the given file between targets in hexdump"""
        args.hex = True
        return self.cmd_diff(args, stdout)

    @arg("index")
    @arg("type", choices=["src", "dst"])
    def cmd_set(self, args: argparse.Namespace, stdout: TextIO) -> bool:
        """change either the source or destination target for differentiation

        Index can be given relative (when prefixed with '+' or '-', e.g. "set dst +1") or absolute (e.g. set src 0).
        """
        index = args.index.strip()
        pos = self.src_index if args.type == "src" else self.dst_index

        if index.startswith(("+", "-")):
            multiplier = 1 if index[0] == "+" else -1
            index = index[1:].strip()
            if not index.isdigit():
                return False
            pos += int(index) * multiplier
        elif index.isdigit():
            pos = int(index)
        else:
            raise ValueError(f"Could not set {args.type} to {index}.")
        if args.type == "src":
            self._select_source_and_dest(pos, self.dst_index)
        else:
            self._select_source_and_dest(self.src_index, pos)
        return False

    @arg("target", choices=["src", "dst"])
    def cmd_enter(self, args: argparse.Namespace, stdout: TextIO) -> bool:
        """open a subshell for the source or destination target"""
        target = self.src_target if args.target == "src" else self.dst_target
        cli = TargetCli(target)
        if target.fs.exists(self.cwd):
            cli.chdir(self.cwd)

        # Cyber doesn't work well with subshells
        cli.cyber = False
        run_cli(cli)
        return False

    @arg("path", nargs="?")
    @arg("-name", default="*")
    @arg("-iname")
    @arg("-c", "--created", action="store_true")
    @arg("-m", "--modified", action="store_true")
    @arg("-d", "--deleted", action="store_true")
    @arg("-u", "--unchanged", action="store_true")
    def cmd_find(self, args: argparse.Namespace, stdout: TextIO) -> bool:
        """search for files in a directory hierarchy"""
        path = fsutil.abspath(args.path, cwd=str(self.cwd), alt_separator=self.comparison.src_target.fs.alt_separator)
        if not path:
            return False

        if self._targets_with_directory(path, warn_when_incomplete=True) == 0:
            return False

        pattern = re.compile(translate(args.iname), re.IGNORECASE) if args.iname else re.compile(translate(args.name))

        include_all_changes = not (args.created or args.modified or args.deleted or args.unchanged)

        include_unchanged = args.unchanged
        include_modified = include_all_changes or args.modified
        include_created = include_all_changes or args.created
        include_deleted = include_all_changes or args.deleted

        for differential in self.comparison.walkdir(path):
            for entry, line in self._annotate_differential(
                differential, include_unchanged, include_created, include_modified, include_deleted, absolute=True
            ):
                if not pattern.match(entry.name):
                    continue

                print(line, file=stdout)

        return False

    def do_plugin(self, line: str) -> bool:
        """yield RecordCreated, RecordUnchanged and RecordDeleted Records by comparing plugin outputs for two targets"""
        argparts = arg_str_to_arg_list(line)
        pipeparts = []
        if "|" in argparts:
            pipeidx = argparts.index("|")
            argparts, pipeparts = argparts[:pipeidx], argparts[pipeidx + 1 :]

        if len(argparts) < 1:
            raise ValueError("Provide a plugin name, and optionally parameters to pass to the plugin.")

        plugin = argparts.pop(0)

        iterator = self.comparison.differentiate_plugin_outputs(plugin, argparts)
        if pipeparts:
            try:
                with build_pipe_stdout(pipeparts) as pipe_stdin:
                    rs = RecordOutput(pipe_stdin.buffer)
                    for record in iterator:
                        rs.write(record)
            except OSError as e:
                # in case of a failure in a subprocess
                print(e)
        else:
            for record in iterator:
                print(record, file=sys.stdout)

        return False

    def do_python(self, line: str) -> bool:
        """drop into a Python shell"""
        python_shell(list(self.targets))
        return False


def make_target_pairs(targets: tuple[Target], absolute: bool = False) -> list[tuple[Target, Target]]:
    """Make 'pairs' of targets that we are going to compare against one another.

    A list of targets can be treated in two
    ways: compare every target with the one that came before it, or compare all targets against a 'base' target
    (which has to be supplied as initial target in the list).
    """
    target_pairs = []

    previous_target = targets[0]
    for target in targets[1:]:
        target_pairs.append((previous_target, target))
        if not absolute:
            # The next target should be compared against the one we just opened
            previous_target = target
    return target_pairs


def differentiate_target_filesystems(
    *targets: tuple[Target],
    deep: bool = False,
    limit: int = FILE_LIMIT,
    absolute: bool = False,
    include: list[str] | None = None,
    exclude: list[str] | None = None,
) -> Iterator[Record]:
    """Given a list of targets, compare targets against one another and yield File[Created|Modified|Deleted]Records
    indicating the differences between them.
    """

    for target_pair in make_target_pairs(targets, absolute):
        # Unpack the tuple and initialize the comparison class
        src_target, dst_target = target_pair
        comparison = TargetComparison(src_target, dst_target, deep, limit)

        paths = ["/"] if include is None else include

        for path in paths:
            for directory_diff in comparison.walkdir(path, exclude=exclude):
                for creation_entry in directory_diff.created:
                    yield FileCreatedRecord(
                        path=creation_entry.path,
                        src_target=src_target.path,
                        dst_target=dst_target.path,
                    )

                for deletion_entry in directory_diff.deleted:
                    yield FileDeletedRecord(
                        path=deletion_entry.path,
                        src_target=src_target.path,
                        dst_target=dst_target.path,
                    )

                for entry_difference in directory_diff.modified:
                    yield FileModifiedRecord(
                        path=entry_difference.path,
                        diff=entry_difference.diff,
                        src_target=src_target.path,
                        dst_target=dst_target.path,
                    )


def differentiate_target_plugin_outputs(
    *targets: tuple[Target], absolute: bool = False, only_changed: bool = False, plugin: str, plugin_args: str = ""
) -> Iterator[Record]:
    """Given a list of targets, yielding records indicating which records from this plugin are new, unmodified or
    deleted."""
    for target_pair in make_target_pairs(targets, absolute):
        src_target, dst_target = target_pair
        comparison = TargetComparison(src_target, dst_target)
        yield from comparison.differentiate_plugin_outputs(plugin, plugin_args, only_changed)


@catch_sigpipe
def main() -> int:
    help_formatter = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(
        description="target-diff",
        fromfile_prefix_chars="@",
        formatter_class=help_formatter,
    )

    parser.add_argument(
        "-d",
        "--deep",
        action="store_true",
        help="compare file contents even if metadata suggests they have been left unchanged",
    )
    parser.add_argument(
        "-l",
        "--limit",
        default=FILE_LIMIT,
        type=int,
        help="how many bytes to compare before assuming a file is left unchanged (0 for no limit)",
    )
    subparsers = parser.add_subparsers(help="mode for differentiating targets", dest="mode", required=True)

    shell_mode = subparsers.add_parser("shell", help="open an interactive shell to compare two or more targets.")
    shell_mode.add_argument("targets", metavar="TARGETS", nargs="+", help="targets to differentiate between")

    fs_mode = subparsers.add_parser("fs", help="yield records about differences between target filesystems.")
    fs_mode.add_argument("targets", metavar="TARGETS", nargs="+", help="targets to differentiate between")
    fs_mode.add_argument("-s", "--strings", action="store_true", help="print records as strings")
    fs_mode.add_argument("-e", "--exclude", action="append", help="path(s) on targets not to check for differences")
    fs_mode.add_argument(
        "-i",
        "--include",
        action="append",
        help="path(s) on targets to check for differences (all will be checked if left omitted)",
    )
    fs_mode.add_argument(
        "-a",
        "--absolute",
        action="store_true",
        help=(
            "treat every target as an absolute. The first given target is treated as the 'base' target to compare "
            "subsequent targets against. If omitted, every target is treated as a 'delta' and compared against the "
            "target that came before it."
        ),
    )

    query_mode = subparsers.add_parser("query", help="differentiate plugin outputs between two or more targets.")
    query_mode.add_argument("targets", metavar="TARGETS", nargs="+", help="targets to differentiate between")
    query_mode.add_argument("-s", "--strings", action="store_true", help="print records as strings")
    query_mode.add_argument(
        "-p",
        "--parameters",
        default="",
        help="parameters for the plugin",
    )
    query_mode.add_argument(
        "-f",
        "--plugin",
        required=True,
        help="function to execute",
    )
    query_mode.add_argument(
        "-a",
        "--absolute",
        action="store_true",
        help=(
            "treat every target as an absolute. The first given target is treated as the 'base' target to compare "
            "subsequent targets against. If omitted, every target is treated as a 'delta' and compared against the "
            "target that came before it."
        ),
    )
    query_mode.add_argument(
        "--only-changed",
        action="store_true",
        help="do not output unchanged records",
    )

    configure_generic_arguments(parser)

    args, rest = parser.parse_known_args()
    process_generic_arguments(args, rest)

    if len(args.targets) < 2:
        parser.error("at least two targets are required for target-diff")

    target_list = [Target.open(path) for path in args.targets]
    if args.mode == "shell":
        cli = DifferentialCli(*target_list, deep=args.deep, limit=args.limit)
        run_cli(cli)
    else:
        writer = record_output(args.strings)
        if args.mode == "fs":
            iterator = differentiate_target_filesystems(
                *target_list,
                deep=args.deep,
                limit=args.limit,
                absolute=args.absolute,
                include=args.include,
                exclude=args.exclude,
            )
        elif args.mode == "query":
            if args.deep:
                log.error("Argument --deep is not available in target-diff query mode")
                return 1

            if args.limit != FILE_LIMIT:
                log.error("Argument --limit is not available in target-diff query mode")
                return 1

            iterator = differentiate_target_plugin_outputs(
                *target_list,
                absolute=args.absolute,
                only_changed=args.only_changed,
                plugin=args.plugin,
                plugin_args=arg_str_to_arg_list(args.parameters),
            )

        try:
            for record in iterator:
                writer.write(record)

        except Exception as e:
            log.error(e)  # noqa: TRY400
            log.debug("", exc_info=e)
            return 1

    return 0


if __name__ == "__main__":
    main()
