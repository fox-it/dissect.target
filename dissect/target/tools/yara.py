#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import logging

from dissect.target import Target
from dissect.target.exceptions import TargetError
from dissect.target.plugins.filesystem.yara import HAS_YARA, MAX_SCAN_SIZE
from dissect.target.tools.query import record_output
from dissect.target.tools.utils import (
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
    parser.add_argument("-r", "--rules", required=True, help="path to YARA rule file(s) or folder with YARA rule files")
    parser.add_argument("-p", "--path", default="/", help="path on target(s) to recursively scan")
    parser.add_argument("-m", "--max-size", default=MAX_SCAN_SIZE, help="maximum file size in bytes to scan")
    parser.add_argument(
        "-c", "--check-rules", default=False, action="store_true", help="check if every YARA rule is valid"
    )
    parser.add_argument("-s", "--string", default=False, action="store_true", help="output string records")
    configure_generic_arguments(parser)

    args = parser.parse_args()
    process_generic_arguments(args)

    if not HAS_YARA:
        log.error("Please install 'yara-python' to use 'target-yara'.")
        parser.exit(1)

    if not args.targets:
        log.error("No targets provided")
        parser.exit(1)

    try:
        for target in Target.open_all(args.targets):
            target.log.info("Scanning target %s", target)
            rs = record_output(args.string, False)
            for record in target.yara(args.rules.split(","), args.path, args.max_size, args.check_rules):
                rs.write(record)

    except TargetError as e:
        log.error(e)
        log.debug("", exc_info=e)
        parser.exit(1)


if __name__ == "__main__":
    main()
