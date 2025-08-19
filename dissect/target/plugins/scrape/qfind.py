from __future__ import annotations

import codecs
import hashlib
import re
import string
from pathlib import Path
from typing import TYPE_CHECKING, Callable

from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, arg, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target.container import Container
    from dissect.target.volume import Volume


re_NOFLAG = 0  # re.NOFLAG is Python 3.11 and newer only

QFindMatchRecord = TargetRecordDescriptor(
    "qfind/match",
    [
        ("string", "disk"),
        ("varint", "offset"),
        ("string", "needle"),
        ("string", "codec"),
        ("bytes", "match"),
        ("bytes", "buffer"),
    ],
)


class QFindPlugin(Plugin):
    """Basically ``grep -a "malware"`` on steroids."""

    def check_compatible(self) -> None:
        pass

    @arg("-n", "--needles", nargs="*", metavar="NEEDLES", help="needles to search for")
    @arg("-nf", "--needle-file", type=Path, help="file containing the needles to search for")
    @arg("-e", "--encoding", help="encode text needles with these comma separated encodings")
    @arg("--regex", action="store_true", help="parse needles as regex patterns")
    @arg("--no-hex-decode", action="store_true", help="do not automatically add decoded hex needles (only in raw mode)")
    @arg("-i", "--ignore-case", action="store_true", help="case insensitive search")
    @arg("-u", "--unique", action="store_true", help="only yield unique string hits (does not apply to raw output)")
    @arg("-W", "--window", type=int, default=256, help="maximum window size in bytes for context around each hit")
    @arg("--strip-null-bytes", action="store_true", help="strip null bytes from matched buffer")
    @export(record=QFindMatchRecord)
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
        progress: Callable[[Container | Volume, int, int], None] | None = None,
    ) -> Iterator[QFindMatchRecord]:
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

        needle_lookup: dict[bytes, tuple[str, str]] = {}
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

        if ignore_case or regex:
            tmp = {}
            for encoded_needle, _ in needle_lookup.items():
                encoded_needle = encoded_needle if regex else re.escape(encoded_needle)
                tmp[re.compile(encoded_needle, re.IGNORECASE if ignore_case else re_NOFLAG)] = _
            needle_lookup = tmp

        seen = set()
        for disk, stream, needle, offset, match in self.target.scrape.find(
            list(needle_lookup.keys()), progress=progress
        ):
            original_needle, codec = needle_lookup[needle]
            needle_len = len(needle.pattern if isinstance(needle, re.Pattern) else needle)
            before_offset = max(0, offset - window)
            stream.seek(before_offset)
            buf = stream.read((offset - before_offset) + max(window, needle_len))

            if unique:
                digest = hashlib.sha1(buf).digest() if window > 20 else buf

                if digest in seen:
                    continue
                seen.add(digest)

            match = match.group() if match else original_needle.encode()

            yield QFindMatchRecord(
                disk=repr(disk),
                offset=offset,
                needle=original_needle,
                codec=codec,
                match=match,
                buffer=buf.strip(b"\x00") if strip_null_bytes else buf,
                _target=self.target,
            )
