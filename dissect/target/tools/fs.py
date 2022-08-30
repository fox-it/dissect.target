#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse
import logging
import operator
import os
import shutil
import sys

from dissect.target import Target
from dissect.target.helpers.fsutil import TargetPath
from dissect.target.tools.utils import (
    configure_generic_arguments,
    process_generic_arguments,
)

log = logging.getLogger(__name__)
logging.lastResort = None
logging.raiseExceptions = False


def ls(t, path, args):
    for e in sorted(path.iterdir(), key=operator.attrgetter("name")):
        print(e.name)


def cat(t, path, args):
    stdout = sys.stdout
    if hasattr(stdout, "buffer"):
        stdout = stdout.buffer
    shutil.copyfileobj(path.open(), stdout)


def walk(t, path, args):
    for e in path.rglob("*"):
        print(str(e))


def cp(t, path, args):
    output = os.path.abspath(os.path.expanduser(args.output))
    if path.is_file():
        _extract_path(path, os.path.join(output, path.name))
    elif path.is_dir():
        for extract_path in path.rglob("*"):
            out_path = os.path.join(output, str(extract_path.relative_to(path)))
            _extract_path(extract_path, out_path)
    else:
        print("[!] Failed, unsuported file type: %s" % path)


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


def main():
    help_formatter = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(
        description="dissect.target",
        fromfile_prefix_chars="@",
        formatter_class=help_formatter,
    )
    parser.add_argument("target", metavar="TARGET", help="Target to load")

    baseparser = argparse.ArgumentParser(add_help=False)
    baseparser.add_argument("path", type=str, help="Path to perform an action on")

    subparsers = parser.add_subparsers(help="Subcommands for performing various actions")
    parser_ls = subparsers.add_parser("ls", help="Show a directory listing", parents=[baseparser])
    parser_ls.set_defaults(handler=ls)

    parser_cat = subparsers.add_parser("cat", help="Dump file contents", parents=[baseparser])
    parser_cat.set_defaults(handler=cat)

    parser_find = subparsers.add_parser("walk", help="Perform a walk", parents=[baseparser])
    parser_find.set_defaults(handler=walk)

    parser_cp = subparsers.add_parser(
        "cp",
        help="Copy multiple files to a directory specified by --output",
        parents=[baseparser],
    )
    parser_cp.add_argument("-o", "--output", type=str, default=".", help="Output directory")
    parser_cp.set_defaults(handler=cp)

    configure_generic_arguments(parser)

    args = parser.parse_args()

    process_generic_arguments(args)

    t = Target.open(args.target)
    path = t.fs.path(args.path)

    if not path.exists():
        print("[!] Path doesn't exist")
        sys.exit(1)

    args.handler(t, path, args)


if __name__ == "__main__":
    main()
