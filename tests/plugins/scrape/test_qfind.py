from __future__ import annotations

import io
import re
from typing import TYPE_CHECKING

import pytest

from dissect.target.containers.raw import RawContainer
from dissect.target.plugins.scrape.qfind import QFindPlugin

if TYPE_CHECKING:
    from pathlib import Path

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


def test_qfind(mock_target: Target, capsys: pytest.CaptureFixture) -> None:
    mock_target.qfind(["B"])
    out = re_ansi_escape.sub("", capsys.readouterr().out)
    assert "[0x010001 @ B (utf-8)]" in out
    assert "ABCD" in out

    mock_target.qfind(["ABCD"], raw=True)
    out = re_ansi_escape.sub("", capsys.readouterr().out)
    assert "[0x010000 @ ABCD (utf-8)]" in out
    assert "00010000  41 42 43 44 00 00 00 00  00 00 00 00 00 00 00 00   ABCD............" in out
    assert "[0x012000 @ ABCD (hex)]" in out
    assert "00012000  ab cd 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ................" in out


def test_qfind_needle_file(mock_target: Target, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    nf = tmp_path.joinpath("needles")
    nf.write_text("ABCD\n")

    mock_target.qfind(needle_file=nf, raw=True)
    out = re_ansi_escape.sub("", capsys.readouterr().out)
    assert "[0x010000 @ ABCD (utf-8)]" in out
    assert "00010000  41 42 43 44 00 00 00 00  00 00 00 00 00 00 00 00   ABCD............" in out
    assert "[0x012000 @ ABCD (hex)]" in out
    assert "00012000  ab cd 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ................" in out


def test_qfind_codec(mock_target: Target, tmp_path: Path, capsys: pytest.CaptureFixture) -> None:
    mock_target.qfind(["ABCD"], encoding="utf-16-le", raw=True)
    out = re_ansi_escape.sub("", capsys.readouterr().out)
    assert "[0x010000 @ ABCD (utf-8)]" in out
    assert "00010000  41 42 43 44 00 00 00 00  00 00 00 00 00 00 00 00   ABCD............" in out
    assert "[0x011000 @ ABCD (utf-16-le)]" in out
    assert "00011000  41 00 42 00 43 00 44 00  00 00 00 00 00 00 00 00   A.B.C.D........." in out
    assert "[0x012000 @ ABCD (hex)]" in out
    assert "00012000  ab cd 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ................" in out

    mock_target.qfind(["ABCD"], no_hex_decode=True, raw=True)
    out = re_ansi_escape.sub("", capsys.readouterr().out)
    assert "[0x010000 @ ABCD (utf-8)]" in out
    assert "[0x012000 @ ABCD (hex)]" not in out


def test_qfind_ignore_case(mock_target: Target, capsys: pytest.CaptureFixture) -> None:
    mock_target.qfind(["abcd"], ignore_case=True, raw=True)
    out = re_ansi_escape.sub("", capsys.readouterr().out)
    assert "[0x010000 @ abcd (utf-8)]" in out
    assert "00010000  41 42 43 44 00 00 00 00  00 00 00 00 00 00 00 00   ABCD............" in out


def test_qfind_unique(target_bare: Target, capsys: pytest.CaptureFixture) -> None:
    target_bare.add_plugin(QFindPlugin)

    buf = (b"ABCD" + b"\x00" * ((1024 * 8) - 4)) + (b"ABCD" + b"\x00" * ((1024 * 8) - 4))
    mock_disk = RawContainer(io.BytesIO(buf))
    target_bare.disks.add(mock_disk)

    target_bare.qfind(["ABCD"])
    out = re_ansi_escape.sub("", capsys.readouterr().out)
    assert out.count("ABCD") == 4  # two headers and two recovered strings

    target_bare.qfind(["ABCD"], unique=True)
    out = re_ansi_escape.sub("", capsys.readouterr().out)
    assert out.count("ABCD") == 2  # one header and one recovered string
