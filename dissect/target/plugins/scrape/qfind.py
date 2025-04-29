from __future__ import annotations

import codecs
import re
import string
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from dissect.cstruct import utils

from dissect.target.helpers.scrape import recover_string
from dissect.target.plugin import Plugin, arg, export

if TYPE_CHECKING:
    from dissect.target.container import Container
    from dissect.target.target import Target
    from dissect.target.volume import Volume


class QFindPlugin(Plugin):
    """Basically ``grep -a "malware"`` on steroids."""

    def check_compatible(self) -> None:
        pass

    @arg("-n", "--needles", nargs="*", metavar="NEEDLES", help="needles to search for")
    @arg("-nf", "--needle-file", type=Path, help="file containing the needles to search for")
    @arg("-e", "--encoding", help="encode text needles with these comma separated encodings")
    @arg("--no-hex-decode", action="store_true", help="do not automatically add decoded hex needles (only in raw mode)")
    @arg("-R", "--raw", action="store_true", help="show raw hex dumps instead of post-processed string output")
    @arg("-i", "--ignore-case", action="store_true", help="case insensitive search")
    @arg("--allow-non-ascii", action="store_true", help="allow non-ASCII characters in the output")
    @arg("-u", "--unique", action="store_true", help="only show unique string hits (does not apply to raw output)")
    @arg("-W", "--window", type=int, default=256, help="maximum window size in bytes for context around each hit")
    @export(output="none")
    def qfind(
        self,
        needles: list[str] | None = None,
        needle_file: Path | None = None,
        encoding: str = "",
        no_hex_decode: bool = False,
        raw: bool = False,
        ignore_case: bool = False,
        allow_non_ascii: bool = False,
        unique: bool = False,
        window: int = 256,
    ) -> None:
        """Find a needle in a haystack.

        Example:
            .. code-block::

                # find all instances of "malware" in the target
                target-qfind <TARGET> --needles malware

                # find all instances of "malware" in the target, ignoring case
                target-qfind <TARGET> --needles MaLwArE --ignore-case

                # find all instances of "malware" in the target and show raw hex dumps
                target-qfind <TARGET> --needles malware --raw

                # find all instances of "malware" in the target, in UTF-8 and UTF-16-LE (UTF-8 is default)
                target-qfind <TARGET> --needles malware --encoding utf-16-le

                # use target-query instead of target-qfind
                target-query <TARGET> -f qfind --needles malware
        """
        all_needles = set(needles or [])
        if needle_file and needle_file.exists():
            with needle_file.open("r") as fh:
                for line in fh:
                    if (line := line.strip()) and not line.startswith("#"):
                        all_needles.add(line)

        encodings = set()
        for codec in (encoding or "").split(","):
            codec = codec.strip()

            try:
                codecs.lookup(codec.strip())
            except LookupError:
                self.target.log.warning("Unknown encoding: %s", codec)
            else:
                encodings.add(codec)

        needle_lookup = {}
        for needle in all_needles:
            encoded_needle = needle.encode("utf-8")
            needle_lookup[encoded_needle] = (needle, "utf-8")

            if not no_hex_decode and len(needle) % 2 == 0 and all(c in string.hexdigits for c in needle):
                encoded_needle = bytes.fromhex(needle)
                needle_lookup[encoded_needle] = (needle, "hex")

            for codec in encodings:
                try:
                    encoded_needle = needle.encode(codec)
                except UnicodeEncodeError:  # noqa: PERF203
                    self.target.log.warning("Cannot encode needle with %s: %s", codec, needle)
                else:
                    needle_lookup[encoded_needle] = (needle, codec)

        if not needle_lookup:
            self.target.log.error("No needles to search for")
            return

        if ignore_case:
            tmp = {}
            for encoded_needle, _ in needle_lookup.items():
                tmp[re.compile(re.escape(encoded_needle), re.IGNORECASE)] = _
            needle_lookup = tmp

        seen = set()
        for _, stream, needle, offset in self.target.scrape.find(
            list(needle_lookup.keys()), progress=progress(self.target)
        ):
            original_needle, codec = needle_lookup[needle]
            needle_len = len(needle.pattern if isinstance(needle, re.Pattern) else needle)
            before_offset = max(0, offset - window)
            stream.seek(before_offset)
            buf = stream.read((offset - before_offset) + max(window, needle_len))

            header = f"\r[{offset:#08x} @ {original_needle} ({codec})]"

            if raw:
                print(header)
                palette = [(offset - before_offset, utils.COLOR_NORMAL), (needle_len, utils.COLOR_BG_RED)]
                utils.hexdump(buf, palette, offset=before_offset)
            else:
                codec = "utf-8" if codec == "hex" else codec
                before_part = recover_string(
                    buf[: offset - before_offset], codec, reverse=True, ascii=not allow_non_ascii
                )
                after_part = recover_string(buf[offset - before_offset :], codec, ascii=not allow_non_ascii)
                hit = (
                    before_part
                    + utils.COLOR_BG_RED
                    + after_part[:needle_len]
                    + utils.COLOR_NORMAL
                    + after_part[needle_len:]
                )

                if unique:
                    if hit in seen:
                        continue
                    seen.add(hit)

                print(header)
                print(hit)


def progress(target: Target) -> Callable[[Container | Volume, int, int], None]:
    """Progress handler of the qfind plugin."""
    current_disk = None

    def update(disk: Container | Volume, offset: int, size: int) -> None:
        nonlocal current_disk
        if current_disk is None:
            sys.stderr.write(f"{target}\n")

        if current_disk != disk:
            sys.stderr.write(f"[Current disk: {disk}]\n")
            current_disk = disk

        sys.stderr.write(f"\r{offset / float(size) * 100:0.2f}%")
        sys.stderr.flush()

    return update
