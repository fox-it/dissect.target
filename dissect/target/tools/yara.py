#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import logging

from dissect.target import Target
from dissect.target.exceptions import TargetError
from dissect.target.plugins.filesystem.yara import HAS_YARA, YaraPlugin
from dissect.target.tools.query import record_output
from dissect.target.tools.utils import (
    args_to_uri,
    catch_sigpipe,
    configure_generic_arguments,
    process_generic_arguments,
)

log = logging.getLogger(__name__)


@catch_sigpipe
def main():
    help_formatter = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(
        description="target-yara",
        fromfile_prefix_chars="@",
        formatter_class=help_formatter,
    )

    parser.add_argument("targets", metavar="TARGETS", nargs="*", help="Targets to load")
    parser.add_argument("-s", "--strings", default=False, action="store_true", help="print output as string")
    parser.add_argument("-L", "--loader", action="store", default=None, help="select a specific loader (i.e. vmx, raw)")
    parser.add_argument("--children", action="store_true", help="include children")

    for args, kwargs in getattr(YaraPlugin.yara, "__args__", []):
        parser.add_argument(*args, **kwargs)

    configure_generic_arguments(parser)

    args, rest = parser.parse_known_args()
    process_generic_arguments(args)

    if not HAS_YARA:
        log.error("yara-python is not installed: pip install yara-python")
        parser.exit(1)

    if not args.targets:
        log.error("No targets provided")
        parser.exit(1)

    targets = args_to_uri(args.targets, args.loader, rest) if args.loader else args.targets

    try:
        for target in Target.open_all(targets, args.children):
            rs = record_output(args.strings, False)
            for record in target.yara(args.rules, args.path, args.max_size, args.check):
                rs.write(record)

    except TargetError as e:
        log.error(e)
        log.debug("", exc_info=e)
        parser.exit(1)


if __name__ == "__main__":
    main()
