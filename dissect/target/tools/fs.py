#!/usr/bin/env python
from __future__ import annotations

import argparse
import logging
import pathlib
import shutil
import sys
from typing import TYPE_CHECKING

from dissect.target.exceptions import TargetError
from dissect.target.target import Target
from dissect.target.tools.fsutils import print_ls, print_stat
from dissect.target.tools.utils import (
    catch_sigpipe,
    configure_generic_arguments,
    process_generic_arguments,
)

if TYPE_CHECKING:
    from dissect.target.helpers.fsutil import TargetPath

log = logging.getLogger(__name__)
logging.lastResort = None
logging.raiseExceptions = False


def ls(t: Target, path: TargetPath, args: argparse.Namespace) -> None:
    if args.use_ctime and args.use_atime:
        log.error("Can't specify -c and -u at the same time")
        return
    if not path or not path.exists():
        return

    # Only output with colors if stdout is a tty
    use_colors = sys.stdout.buffer.isatty()

    print_ls(
        path,
        0,
        sys.stdout,
        args.l,
        args.human_readable,
        args.recursive,
        args.use_ctime,
        args.use_atime,
        use_colors,
    )


def cat(t: Target, path: TargetPath, args: argparse.Namespace) -> None:
    stdout = sys.stdout
    if hasattr(stdout, "buffer"):
        stdout = stdout.buffer
    shutil.copyfileobj(path.open(), stdout)


def walk(t: Target, path: TargetPath, args: argparse.Namespace) -> None:
    for e in path.rglob("*"):
        print(str(e))


def cp(t: Target, path: TargetPath, args: argparse.Namespace) -> None:
    output = pathlib.Path(args.output).expanduser().resolve()

    if path.is_file():
        _extract_path(path, output.joinpath(path.name))
    elif path.is_dir():
        for extract_path in path.rglob("*"):
            out_path = output.joinpath(str(extract_path.relative_to(path)))
            _extract_path(extract_path, out_path)
    else:
        print(f"[!] Failed, unsuported file type: {path}")


def stat(t: Target, path: TargetPath, args: argparse.Namespace) -> None:
    if not path or not path.exists():
        return
    print_stat(path, sys.stdout, args.dereference)


def _extract_path(path: TargetPath, output_path: pathlib.Path) -> None:
    print(f"{path} -> {output_path}")

    out_dir = output_path if path.is_dir() else output_path.parent

    try:
        if not out_dir.exists():
            out_dir.mkdir(parents=True)

        if path.is_file():
            with output_path.open("wb") as fh:
                shutil.copyfileobj(path.open(), fh)

    except Exception:
        print(f"[!] Failed: {path}")
        log.exception("Error extracting file: %s -> %s", path, output_path)


@catch_sigpipe
def main() -> int:
    help_formatter = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(
        description="dissect.target",
        fromfile_prefix_chars="@",
        formatter_class=help_formatter,
    )
    parser.add_argument("target", type=pathlib.Path, help="Target to load", metavar="TARGET")

    baseparser = argparse.ArgumentParser(add_help=False)
    baseparser.add_argument("path", help="path to perform an action on", metavar="PATH")

    subparsers = parser.add_subparsers(dest="subcommand", help="subcommands for performing various actions")
    parser_ls = subparsers.add_parser(
        "ls", help="Show a directory listing", parents=[baseparser], conflict_handler="resolve"
    )
    parser_ls.add_argument("-l", action="store_true")
    parser_ls.add_argument("-a", "--all", action="store_true")  # ignored but included for proper argument parsing
    parser_ls.add_argument("-h", "--human-readable", action="store_true")
    parser_ls.add_argument("-R", "--recursive", action="store_true", help="recursively list subdirectories encountered")
    parser_ls.add_argument(
        "-c", action="store_true", dest="use_ctime", help="show time when file status was last changed"
    )
    parser_ls.add_argument("-u", action="store_true", dest="use_atime", help="show time of last access")
    parser_ls.set_defaults(handler=ls)

    parser_cat = subparsers.add_parser("cat", help="dump file contents", parents=[baseparser])
    parser_cat.set_defaults(handler=cat)

    parser_stat = subparsers.add_parser("stat", help="display file status", parents=[baseparser])
    parser_stat.add_argument("-L", "--dereference", action="store_true")
    parser_stat.set_defaults(handler=stat)

    parser_find = subparsers.add_parser("walk", help="perform a walk", parents=[baseparser])
    parser_find.set_defaults(handler=walk)

    parser_cp = subparsers.add_parser(
        "cp",
        help="copy multiple files to a directory specified by --output",
        parents=[baseparser],
    )
    parser_cp.add_argument("-o", "--output", default=".", help="output directory")
    parser_cp.set_defaults(handler=cp)
    configure_generic_arguments(parser)

    args, rest = parser.parse_known_args()
    process_generic_arguments(args, rest)

    if args.subcommand is None:
        parser.error("No subcommand specified")

    try:
        target = Target.open(args.target)
    except TargetError as e:
        log.error(e)  # noqa: TRY400
        log.debug("", exc_info=e)
        return 1

    path = target.fs.path(args.path)

    if not path.exists():
        print("[!] Path doesn't exist")
        return 1

    args.handler(target, path, args)

    return 0


if __name__ == "__main__":
    main()
