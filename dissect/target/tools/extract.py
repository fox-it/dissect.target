#!/usr/bin/env python

from __future__ import annotations

import argparse
import logging

from dissect.target.exceptions import (
    TargetError,
)
from dissect.target.helpers.logging import get_logger
from dissect.target.tools.shell import TargetCli
from dissect.target.tools.utils.cli import (
    catch_sigpipe,
    configure_generic_arguments,
    configure_plugin_arguments,
    find_and_filter_plugins,
    open_targets,
    process_generic_arguments,
    process_plugin_arguments,
)

log = get_logger(__name__)
logging.lastResort = None
logging.raiseExceptions = False


@catch_sigpipe
def main() -> int:
    help_formatter = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(
        description="dissect.target",
        fromfile_prefix_chars="@",
        formatter_class=help_formatter,
        add_help=False,
    )
    parser.add_argument("targets", metavar="TARGETS", nargs="*", help="Targets to load")
    parser.add_argument("-o", "--out", default=".", help="Output location")
    parser.add_argument("--path", nargs=None)  # Internal argument needed to pass to cmd_save
    configure_plugin_arguments(parser)
    configure_generic_arguments(parser)
    args, rest = parser.parse_known_args()

    # Show help for target-extract
    if not args.function and ("-h" in rest or "--help" in rest):
        parser.print_help()
        return 0

    process_generic_arguments(parser, args)

    if not args.targets:
        parser.error("too few arguments - missing targets")

    process_plugin_arguments(parser, args, rest)

    try:
        for target in open_targets(args):
            cli = TargetCli(target)
            for func_def in find_and_filter_plugins(args.function, target, args.excluded_functions):
                try:
                    paths = func_def.cls(target).get_paths()
                    args.path = list(paths)
                    cli.cmd_save(args, None)
                except NotImplementedError:
                    target.log.exception(
                        "Cannot extract paths for %s, get_paths is not implemented",
                        func_def.name,
                    )
                    return 1

    except TargetError as e:
        log.exception("Target error")
        log.debug("", exc_info=e)
        return 1

    return 0


if __name__ == "__main__":
    main()
