from __future__ import annotations

import codecs
import hashlib
import re
import string
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Iterator

from dissect.cstruct import utils

from dissect.target.container import Container
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, arg, export

if TYPE_CHECKING:
    from dissect.target.container import Container
    from dissect.target.target import Target
    from dissect.target.volume import Volume

COLOR_GREY = "\033[38;5;248m"

QFindHitRecord = TargetRecordDescriptor(
    "qfind/hit",
    [
        ("varint", "offset"),
        ("string", "needle"),
        ("string", "codec"),
        ("string", "match"),
        ("bytes", "content"),
    ],
)


class QFindPlugin(Plugin):
    """Basically ``grep -a "malware"`` on steroids."""

    def check_compatible(self) -> None:
        pass

    @arg("-n", "--needles", type=str, nargs="*", metavar="NEEDLES", help="needles to search for")
    @arg("-nf", "--needle-file", type=Path, help="file containing the needles to search for")
    @arg("-e", "--encoding", type=str, help="encode text needles with these comma separated encodings")
    @arg("--regex", action="store_true", help="parse needles as regexes")
    @arg("--no-hex-decode", action="store_true", help="do not automatically add decoded hex needles (only in raw mode)")
    @arg("-i", "--ignore-case", action="store_true", help="case insensitive search")
    @arg("-u", "--unique", action="store_true", help="only yield unique string hits (does not apply to raw output)")
    @arg("-W", "--window", type=int, default=256, help="maximum window size in bytes for context around each hit")
    @arg("--strip-null-bytes", action="store_true", help="strip null bytes from matched content")
    @export(record=QFindHitRecord)
    def qfind(
        self,
        needles: list[str] | None = None,
        needle_file: Path | None = None,
        encoding: str = "",
        no_hex_decode: bool = False,
        regex: bool = False,
        ignore_case: bool = False,
        unique: bool = False,
        window: int = 256,
        strip_null_bytes: bool = False,
        *,
        progress: bool = False,
    ) -> Iterator[QFindHitRecord]:
        """Find a needle in a haystack.

        Hex encode needles starting with ``#`` in needle files, otherwise these needles are ignored.

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

                # find all matches of regular expression "malware\\s\\d+" in the target (e.g. ``malware 1337``)
                target-qfind <TARGET> --needles "malware\\s\\d+" --regex

                # use a file for needles
                target-qfind <TARGET> --needle-file needles.txt

                # use target-query instead of target-qfind (output in records)
                target-query <TARGET> -f qfind --needles malware
        """
        all_needles = set(needles or [])
        if needle_file and needle_file.exists():
            with needle_file.open("r") as fh:
                for line in fh:
                    if line := line.strip():
                        if line.startswith("#"):
                            self.target.log.warning("Ignoring needle %r", line)
                        else:
                            all_needles.add(line)

        self.target.log.info("Loaded %s needles", len(all_needles))

        encodings = set()
        for codec in (encoding or "").split(","):
            if not (codec := codec.strip()):
                continue

            try:
                codecs.lookup(codec)
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
            self.target.log.error("No needles to search for (use '--needles' or '--needle-file')")
            return

        if strip_null_bytes and progress:
            self.target.log.error(
                "Cannot use --strip-null-bytes in 'target-qfind', only applicable to 'target-query -f qfind'"
            )
            return

        if ignore_case and not regex:
            tmp = {}
            for encoded_needle, _ in needle_lookup.items():
                tmp[re.compile(re.escape(encoded_needle), re.IGNORECASE)] = _
            needle_lookup = tmp

        elif regex:
            tmp = {}
            for needle, _ in needle_lookup.items():
                tmp[re.compile(needle, re.IGNORECASE if ignore_case else re.NOFLAG)] = _
            needle_lookup = tmp

        seen = set()
        for _, stream, needle, offset, match in self.target.scrape.find(
            list(needle_lookup.keys()), progress=progress_handler(self.target) if progress else None
        ):
            original_needle, codec = needle_lookup[needle]
            needle_len = len(needle.pattern if isinstance(needle, re.Pattern) else needle)
            before_offset = max(0, offset - window)
            stream.seek(before_offset)
            buf = stream.read((offset - before_offset) + max(window, needle_len))

            if unique:
                if window > 20:
                    m = hashlib.sha1()
                    m.update(buf)
                    digest = m.digest()
                else:
                    digest = buf

                if digest in seen:
                    continue
                seen.add(digest)

            if isinstance(needle, re.Pattern) and match:
                match = match.group()
            else:
                match = original_needle

            yield QFindHitRecord(
                offset=offset,
                needle=original_needle,
                codec=codec,
                match=match,
                content=buf.strip(b"\x00") if strip_null_bytes else buf,
                _target=self.target if self.target._os else None,
            )


def progress_handler(target: Target) -> Callable[[Container | Volume, int, int], None]:
    """Progress handler of the qfind plugin."""
    current_disk = None
    animation = ["-", "\\", "|", "/"]
    char = 0

    def update(disk: Container | Volume, offset: int, size: int) -> None:
        nonlocal current_disk, char

        if current_disk is None:
            sys.stderr.write(f"{utils.COLOR_WHITE}{target}{utils.COLOR_NORMAL}\n")

        if current_disk != disk:
            sys.stderr.write(f"\n{utils.COLOR_WHITE}[Current disk: {disk}]{utils.COLOR_NORMAL}\n")
            current_disk = disk

        sys.stderr.write(
            f"\r{COLOR_GREY}{offset / float(size) * 100:0.2f}% {animation[char]}{utils.COLOR_NORMAL}"
        )
        sys.stderr.flush()

        if offset % 1337 * 42 == 0:
            char = 0 if char == 3 else char + 1

    return update
