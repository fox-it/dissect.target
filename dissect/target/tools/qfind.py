#!/usr/bin/env python
from __future__ import annotations

import argparse
import logging
import sys

from dissect.cstruct import utils

from dissect.target.exceptions import TargetError
from dissect.target.helpers.scrape import recover_string
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
    parser.add_argument(
        "-R", "--raw", action="store_true", help="show raw hex dumps instead of post-processed string output"
    )
    parser.add_argument("--allow-non-ascii", action="store_true", help="allow non-ASCII characters in the output")

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
            for hit in target.qfind(
                args.needles,
                args.needle_file,
                args.encoding,
                args.no_hex_decode,
                args.regex,
                args.ignore_case,
                args.unique,
                args.window,
                args.strip_null_bytes,
                progress=True,
            ):
                header = f"\r{utils.COLOR_WHITE}[{hit.offset:#08x} @ {hit.needle} ({hit.codec})]{utils.COLOR_NORMAL}"
                before_offset = max(0, hit.offset - args.window)
                needle_len = len(hit.match)

                if args.raw:
                    print(header)
                    palette = [(hit.offset - before_offset, utils.COLOR_NORMAL), (needle_len, utils.COLOR_BG_RED)]
                    utils.hexdump(hit.content, palette, offset=before_offset)

                else:
                    codec = "utf-8" if hit.codec == "hex" else hit.codec
                    before_part = recover_string(
                        hit.content[: hit.offset - before_offset], codec, reverse=True, ascii=not args.allow_non_ascii
                    )
                    after_part = recover_string(
                        hit.content[hit.offset - before_offset :], codec, ascii=not args.allow_non_ascii
                    )
                    hit = (
                        before_part
                        + utils.COLOR_BG_RED
                        + after_part[:needle_len]
                        + utils.COLOR_NORMAL
                        + after_part[needle_len:]
                    )

                    print(header)
                    print(hit)

            print("\r\n" if sys.platform in ["win32", "cygwin"] else "\n", flush=True)

    except TargetError as e:
        log.error(e)  # noqa: TRY400
        log.debug("", exc_info=e)
        return 1

    return 0


if __name__ == "__main__":
    main()
