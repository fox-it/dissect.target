#!/usr/bin/env python
from __future__ import annotations

import argparse
import logging
import os
import random
import sys
from typing import TYPE_CHECKING

from dissect.cstruct import utils

from dissect.target.exceptions import TargetError
from dissect.target.helpers.scrape import recover_string
from dissect.target.plugins.scrape.qfind import QFindMatchRecord, QFindPlugin
from dissect.target.target import Target
from dissect.target.tools.query import record_output
from dissect.target.tools.utils import (
    catch_sigpipe,
    configure_generic_arguments,
    process_generic_arguments,
)

if TYPE_CHECKING:
    from typing import Callable

    from dissect.target.container import Container
    from dissect.target.volume import Volume

log = logging.getLogger(__name__)

NO_COLOR = os.getenv("NO_COLOR")
COLOR_GREY = "\033[38;5;248m"


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
    parser.add_argument("-j", "--json", action="store_true", help="output records as json")
    parser.add_argument("-r", "--record", action="store_true", help="output records")
    parser.add_argument("-s", "--strings", action="store_true", help="print record output as string")

    for args, kwargs in getattr(QFindPlugin.qfind, "__args__", []):
        parser.add_argument(*args, **kwargs)

    configure_generic_arguments(parser)

    args, _ = parser.parse_known_args()
    process_generic_arguments(args)

    if not args.targets:
        log.error("No targets provided")
        return 1

    rs = None
    if args.record or args.json:
        rs = record_output(args.strings, args.json)

    try:
        for target in Target.open_all(args.targets, args.children):
            hit: QFindMatchRecord
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
                progress=progress_handler(target),
            ):
                if rs:
                    rs.write(hit)
                    continue

                header = f"[{hit.offset:#08x} @ {hit.needle} ({hit.codec})]"

                if not NO_COLOR:
                    header = utils.COLOR_WHITE + header + utils.COLOR_NORMAL

                before_offset = max(0, hit.offset - args.window)
                needle_len = len(hit.match)

                print(f"\r{header}")

                if args.raw:
                    palette = (
                        [(hit.offset - before_offset, utils.COLOR_NORMAL), (needle_len, utils.COLOR_BG_RED)]
                        if not NO_COLOR
                        else None
                    )
                    utils.hexdump(hit.buffer, palette, offset=before_offset)

                else:
                    codec = "utf-8" if hit.codec == "hex" else hit.codec
                    before_part = recover_string(
                        hit.buffer[: hit.offset - before_offset], codec, reverse=True, ascii=not args.allow_non_ascii
                    )
                    after_part = recover_string(
                        hit.buffer[hit.offset - before_offset :], codec, ascii=not args.allow_non_ascii
                    )
                    hit = (
                        before_part,
                        (utils.COLOR_BG_RED if not NO_COLOR else ""),
                        after_part[:needle_len],
                        (utils.COLOR_NORMAL if not NO_COLOR else ""),
                        after_part[needle_len:],
                    )
                    print("".join(hit))

    except TargetError as e:
        log.error(e)  # noqa: TRY400
        log.debug("", exc_info=e)
        return 1

    if not rs:
        print(end="\r\n")

    return 0


def progress_handler(target: Target) -> Callable[[Container | Volume, int, int], None]:
    """Progress handler of the qfind plugin."""
    current_disk = None
    animations = [
        ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"],
        ["⠄", "⠆", "⠇", "⠋", "⠙", "⠸", "⠰", "⠠", "⠰", "⠸", "⠙", "⠋", "⠇", "⠆"],
        [
            "⢀⠀",
            "⡀⠀",
            "⠄⠀",
            "⢂⠀",
            "⡂⠀",
            "⠅⠀",
            "⢃⠀",
            "⡃⠀",
            "⠍⠀",
            "⢋⠀",
            "⡋⠀",
            "⠍⠁",
            "⢋⠁",
            "⡋⠁",
            "⠍⠉",
            "⠋⠉",
            "⠋⠉",
            "⠉⠙",
            "⠉⠙",
            "⠉⠩",
            "⠈⢙",
            "⠈⡙",
            "⢈⠩",
            "⡀⢙",
            "⠄⡙",
            "⢂⠩",
            "⡂⢘",
            "⠅⡘",
            "⢃⠨",
            "⡃⢐",
            "⠍⡐",
            "⢋⠠",
            "⡋⢀",
            "⠍⡁",
            "⢋⠁",
            "⡋⠁",
            "⠍⠉",
            "⠋⠉",
            "⠋⠉",
            "⠉⠙",
            "⠉⠙",
            "⠉⠩",
            "⠈⢙",
            "⠈⡙",
            "⠈⠩",
            "⠀⢙",
            "⠀⡙",
            "⠀⠩",
            "⠀⢘",
            "⠀⡘",
            "⠀⠨",
            "⠀⢐",
            "⠀⡐",
            "⠀⠠",
            "⠀⢀",
            "⠀⡀",
        ],
        [
            "⠁",
            "⠂",
            "⠄",
            "⡀",
            "⡈",
            "⡐",
            "⡠",
            "⣀",
            "⣁",
            "⣂",
            "⣄",
            "⣌",
            "⣔",
            "⣤",
            "⣥",
            "⣦",
            "⣮",
            "⣶",
            "⣷",
            "⣿",
            "⡿",
            "⠿",
            "⢟",
            "⠟",
            "⡛",
            "⠛",
            "⠫",
            "⢋",
            "⠋",
            "⠍",
            "⡉",
            "⠉",
            "⠑",
            "⠡",
            "⢁",
        ],
        [
            "[010010]",
            "[001100]",
            "[100101]",
            "[111010]",
            "[111101]",
            "[010111]",
            "[101011]",
            "[111000]",
            "[110011]",
            "[110101]",
        ],
        ["◐", "◓", "◑", "◒"],
        ["🕛 ", "🕐 ", "🕑 ", "🕒 ", "🕓 ", "🕔 ", "🕕 ", "🕖 ", "🕗 ", "🕘 ", "🕙 ", "🕚 "],
        [
            "▐⠂       ▌",
            "▐⠈       ▌",
            "▐ ⠂      ▌",
            "▐ ⠠      ▌",
            "▐  ⡀     ▌",
            "▐  ⠠     ▌",
            "▐   ⠂    ▌",
            "▐   ⠈    ▌",
            "▐    ⠂   ▌",
            "▐    ⠠   ▌",
            "▐     ⡀  ▌",
            "▐     ⠠  ▌",
            "▐      ⠂ ▌",
            "▐      ⠈ ▌",
            "▐       ⠂▌",
            "▐       ⠠▌",
            "▐       ⡀▌",
            "▐      ⠠ ▌",
            "▐      ⠂ ▌",
            "▐     ⠈  ▌",
            "▐     ⠂  ▌",
            "▐    ⠠   ▌",
            "▐    ⡀   ▌",
            "▐   ⠠    ▌",
            "▐   ⠂    ▌",
            "▐  ⠈     ▌",
            "▐  ⠂     ▌",
            "▐ ⠠      ▌",
            "▐ ⡀      ▌",
            "▐⠠       ▌",
        ],
        [
            " 🤜\u3000\u3000\u3000\u3000🤛 ",
            " 🤜\u3000\u3000\u3000\u3000🤛 ",
            " 🤜\u3000\u3000\u3000\u3000🤛 ",
            " \u3000🤜\u3000\u3000🤛\u3000 ",
            " \u3000\u3000🤜🤛\u3000\u3000 ",
            " \u3000🤜✨🤛\u3000\u3000 ",
            " 🤜\u3000✨\u3000🤛\u3000 ",
        ],
        [
            "😐 ",
            "😐 ",
            "😮 ",
            "😮 ",
            "😦 ",
            "😦 ",
            "😧 ",
            "😧 ",
            "🤯 ",
            "💥 ",
            "✨ ",
            "\u3000 ",
            "\u3000 ",
            "\u3000 ",
        ],
        ["_", "_", "_", "-", "`", "`", "'", "´", "-", "_", "_", "_"],  # noqa: RUF001
    ]
    animation = random.choice(animations)
    char = 0

    def update(disk: Container | Volume, offset: int, size: int) -> None:
        nonlocal current_disk, char

        if current_disk is None:
            sys.stderr.write(f"{utils.COLOR_WHITE}{target}{utils.COLOR_NORMAL}\n")

        if current_disk != disk:
            sys.stderr.write(f"\n{utils.COLOR_WHITE}[Current disk: {disk}]{utils.COLOR_NORMAL}\n")
            current_disk = disk

        sys.stderr.write(f"\r{COLOR_GREY}{offset / float(size) * 100:0.2f}% {animation[char]}{utils.COLOR_NORMAL}")
        sys.stderr.flush()

        if offset % (1337 * 3) == 0:
            char = 0 if char == (len(animation) - 1) else char + 1

    return update


if __name__ == "__main__":
    main()
