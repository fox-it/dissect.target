#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import logging
import os
import pathlib
import shutil
import sys

from dissect.target import Target
from dissect.target.exceptions import TargetError
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.tools.fsutils import print_ls, print_stat
from dissect.target.tools.utils import (
    catch_sigpipe,
    configure_generic_arguments,
    process_generic_arguments,
)

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
    output = os.path.abspath(os.path.expanduser(args.output))
    if path.is_file():
        _extract_path(path, os.path.join(output, path.name))
    elif path.is_dir():
        for extract_path in path.rglob("*"):
            out_path = os.path.join(output, str(extract_path.relative_to(path)))
            _extract_path(extract_path, out_path)
    else:
        print("[!] Failed, unsuported file type: %s" % path)


def stat(t: Target, path: TargetPath, args: argparse.Namespace) -> None:
    if not path or not path.exists():
        return
    print_stat(path, sys.stdout, args.dereference)


def _extract_path(path: TargetPath, output_path: str) -> None:
    print("%s -> %s" % (path, output_path))

    out_dir = ""
    if path.is_dir():
        out_dir = output_path
    elif path.is_file():
        out_dir = os.path.dirname(output_path)

    try:
        if not os.path.exists(out_dir):
            os.makedirs(out_dir)

        if path.is_file():
            with open(output_path, "wb") as fh:
                shutil.copyfileobj(path.open(), fh)

    except Exception as e:
        print("[!] Failed: %s" % path)
        log.exception(e)


@catch_sigpipe
def main() -> None:
    help_formatter = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(
        description="dissect.target",
        fromfile_prefix_chars="@",
        formatter_class=help_formatter,
    )
    parser.add_argument("target", type=pathlib.Path, help="Target to load", metavar="TARGET")

    baseparser = argparse.ArgumentParser(add_help=False)
    baseparser.add_argument("path", type=str, help="path to perform an action on", metavar="PATH")

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
    parser_cp.add_argument("-o", "--output", type=str, default=".", help="output directory")
    parser_cp.set_defaults(handler=cp)

    configure_generic_arguments(parser)

    args = parser.parse_args()

    if args.subcommand is None:
        parser.error("No subcommand specified")

    process_generic_arguments(args)

    try:
        target = Target.open(args.target)
    except TargetError as e:
        log.error(e)
        log.debug("", exc_info=e)
        parser.exit(1)

    path = target.fs.path(args.path)

    if not path.exists():
        print("[!] Path doesn't exist")
        sys.exit(1)

    args.handler(target, path, args)


if __name__ == "__main__":
    main()
