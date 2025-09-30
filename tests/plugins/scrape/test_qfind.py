from __future__ import annotations

import io
import re
from typing import TYPE_CHECKING

import pytest

from dissect.target.containers.raw import RawContainer
from dissect.target.plugins.scrape.qfind import QFindPlugin

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.plugins.scrape.qfind import QFindMatchRecord
    from dissect.target.target import Target

re_ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


@pytest.fixture
def mock_target(target_bare: Target) -> Target:
    target_bare.add_plugin(QFindPlugin)

    buf = (
        (b"\x00" * 1024 * 64)
        + (b"ABCD" + b"\x00" * ((1024 * 4) - 4))
        + (b"A\x00B\x00C\x00D\x00" + b"\x00" * ((1024 * 4) - 8))
        + (b"\xab\xcd" + b"\x00" * ((1024 * 4) - 2))
        + (b"\x00" * 1024 * 52)
    )
    mock_disk = RawContainer(io.BytesIO(buf))
    target_bare.disks.add(mock_disk)

    return target_bare


def test_qfind(mock_target: Target) -> None:
    """Test if qfind can find a simple short needle."""

    results = list(mock_target.qfind(["B"]))

    assert len(results) == 2


def test_qfind_hex(mock_target: Target) -> None:
    """Test if qfind can find hex needles."""

    results: list[QFindMatchRecord] = list(mock_target.qfind(["ABCD"]))

    assert len(results) == 2

    assert results[0].disk == "<Container type=raw size=131072 vs=None>"
    assert results[0].offset == 0x10000
    assert results[0].needle == "ABCD"
    assert results[0].codec == "utf-8"

    assert results[1].disk == "<Container type=raw size=131072 vs=None>"
    assert results[1].offset == 0x12000
    assert results[1].needle == "ABCD"
    assert results[1].codec == "hex"


def test_qfind_needle_file(mock_target: Target, tmp_path: Path) -> None:
    """Test if qfind can work with a needle file."""

    needle_file = tmp_path.joinpath("needles.txt")
    needle_file.write_text("ABCD\n")

    results: list[QFindMatchRecord] = list(mock_target.qfind(needle_file=needle_file))

    assert len(results) == 2

    assert results[0].disk == "<Container type=raw size=131072 vs=None>"
    assert results[0].offset == 0x10000
    assert results[0].needle == "ABCD"

    assert results[1].disk == "<Container type=raw size=131072 vs=None>"
    assert results[1].offset == 0x12000
    assert results[1].needle == "ABCD"


def test_qfind_codecs(mock_target: Target) -> None:
    """Test if qfind can handle utf-8, utf-16-le and hex needles."""

    results: list[QFindMatchRecord] = list(mock_target.qfind(["ABCD"], encoding="utf-16-le"))
    assert len(results) == 3

    assert results[0].disk == "<Container type=raw size=131072 vs=None>"
    assert results[0].offset == 0x10000
    assert results[0].needle == "ABCD"
    assert results[0].codec == "utf-8"
    assert results[0].match == b"ABCD"

    assert results[1].offset == 0x11000
    assert results[1].needle == "ABCD"
    assert results[1].codec == "utf-16-le"
    assert results[1].match == b"ABCD"

    assert results[2].offset == 0x12000
    assert results[2].needle == "ABCD"
    assert results[2].codec == "hex"
    assert results[2].match == b"ABCD"

    results: list[QFindMatchRecord] = list(mock_target.qfind(["ABCD"], no_hex_decode=True))
    assert len(results) == 1

    assert results[0].disk == "<Container type=raw size=131072 vs=None>"
    assert results[0].offset == 0x10000
    assert results[0].needle == "ABCD"
    assert results[0].codec == "utf-8"
    assert results[0].match == b"ABCD"


def test_qfind_ignore_case(mock_target: Target) -> None:
    """Test if qfind can ignore case sensitivity of utf-8 needles."""

    results: list[QFindMatchRecord] = list(mock_target.qfind(["abcd"], ignore_case=True))

    assert len(results) == 2

    assert results[0].disk == "<Container type=raw size=131072 vs=None>"
    assert results[0].offset == 0x10000
    assert results[0].codec == "utf-8"
    assert results[0].needle == "abcd"
    assert results[0].match == b"ABCD"

    assert results[1].offset == 0x12000
    assert results[1].codec == "hex"
    assert results[1].needle == "abcd"
    assert results[1].match == b"\xab\xcd"


def test_qfind_regex(mock_target: Target) -> None:
    """Test if qfind can compile and search for regex needles."""

    results: list[QFindMatchRecord] = list(mock_target.qfind([r"[a-d]{4}"], regex=True, ignore_case=True))

    assert len(results) == 1
    assert results[0].offset == 0x10000
    assert results[0].needle == r"[a-d]{4}"
    assert results[0].codec == "utf-8"
    assert results[0].match == b"ABCD"
    assert results[0].buffer == (b"\x00" * 256) + b"ABCD" + (b"\x00" * 252)


def test_qfind_unique(target_bare: Target, capsys: pytest.CaptureFixture) -> None:
    """Test if qfind returns unique records when using the ``unique`` argument."""

    target_bare.add_plugin(QFindPlugin)

    buf = (b"\x00" * 512) + (b"ABCD" + b"\x00" * ((1024 * 8) - 4)) + (b"ABCD" + b"\x00" * ((1024 * 8) - 4))
    mock_disk = RawContainer(io.BytesIO(buf))
    target_bare.disks.add(mock_disk)

    results = list(target_bare.qfind(["ABCD"]))
    assert len(results) == 2

    results = list(target_bare.qfind(["ABCD"], unique=True))
    assert len(results) == 1
