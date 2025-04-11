#!/usr/bin/env python
from __future__ import annotations

import argparse
import logging

from dissect.target.exceptions import TargetError
from dissect.target.plugins.scrape.qfind import QFindPlugin
from dissect.target.target import Target
from dissect.target.tools.utils import (
    catch_sigpipe,
    configure_generic_arguments,
    process_generic_arguments,
)

log = logging.getLogger(__name__)


@catch_sigpipe
def main() -> int:
    help_formatter = argparse.ArgumentDefaultsHelpFormatter
    parser = argparse.ArgumentParser(
        description="Find a needle in a haystack.",
        fromfile_prefix_chars="@",
        formatter_class=help_formatter,
    )

    parser.add_argument("targets", metavar="TARGETS", nargs="*", help="Targets to load")
    parser.add_argument("--children", action="store_true", help="include children")

    for args, kwargs in getattr(QFindPlugin.qfind, "__args__", []):
        parser.add_argument(*args, **kwargs)

    configure_generic_arguments(parser)

    args, rest = parser.parse_known_args()
    process_generic_arguments(args, rest)

    if not args.targets:
        log.error("No targets provided")
        return 1

    try:
        for target in Target.open_all(args.targets, args.children):
            target.qfind(
                args.needles,
                args.needle_file,
                args.encoding,
                args.no_hex_decode,
                args.raw,
                args.ignore_case,
                args.allow_non_ascii,
                args.unique,
                args.window,
            )

    except TargetError as e:
        log.error(e)  # noqa: TRY400
        log.debug("", exc_info=e)
        return 1

    return 0


if __name__ == "__main__":
    main()
