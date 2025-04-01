from pathlib import Path

from dissect.target.filesystem import Filesystem
from dissect.target.plugins.os.unix.bsd._os import BsdPlugin
from dissect.target.target import Target

# https://en.wikipedia.org/wiki/Mach-O
ARCH_MAP = {
    b"\x0c\x00\x00\x01": "arm64",  # big endian, x64
    b"\x01\x00\x00\x0c": "arm64",  # little endian, x64
    b"\x0c\x00\x00\x00": "arm32",  # big endian, x32
    b"\x00\x00\x00\x0c": "arm32",  # little endian, x32
}


class DarwinPlugin(BsdPlugin):
    """"""

    def __init__(self, target: Target):
        super().__init__(target)


def detect_macho_arch(paths: list[str | Path], suffix: str, fs: Filesystem | None = None) -> str | None:
    """Detect the architecture of the system by reading the Mach-O headers of the provided binaries.

    We could use the mach-o magic headers (feedface, feedfacf, cafebabe), but the mach-o cpu type
    also contains bitness.

    Args:
        paths: List of strings or ``Path`` objects.
        suffix: String to append to returned architecture, e.g. providing ``suffix`` returns ``arm64-suffix``.
        fs: Optional filesystem to search the provided paths in. Required if ``paths`` is a list of strings.

    Returns:
        Detected architecture or ``None``.

    Resources:
        - https://github.com/opensource-apple/cctools/blob/master/include/mach/machine.h
    """
    for path in paths:
        if isinstance(path, str):
            if not fs:
                raise ValueError("Provided string paths but no filesystem!")
            path = fs.path(path)

        if not path.is_file():
            continue

        try:
            with path.open("rb") as fh:
                fh.seek(4)
                arch = ARCH_MAP.get(fh.read(4))  # mach-o cpu type
                return f"{arch}-{suffix}"
        except Exception:
            pass
