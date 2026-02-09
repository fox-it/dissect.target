from __future__ import annotations

import io
import re
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.containers.raw import RawContainer
from dissect.target.tools.qfind import main as target_qfind

if TYPE_CHECKING:
    from dissect.target.target import Target

re_ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")

buf = (
    (b"\x00" * 1024 * 64)
    + (b"ABCD" + b"\x00" * ((1024 * 4) - 4))
    + (b"A\x00B\x00C\x00D\x00" + b"\x00" * ((1024 * 4) - 8))
    + (b"\xab\xcd" + b"\x00" * ((1024 * 4) - 2))
    + (b"\x00" * 1024 * 52)
)

buf_unique = (b"\x00" * 512) + (b"ABCD" + b"\x00" * ((1024 * 8) - 4)) + (b"ABCD" + b"\x00" * ((1024 * 8) - 4))


@pytest.mark.parametrize(
    ("buf", "argv", "expected_out", "not_expected_out", "expected_count"),
    [
        pytest.param(
            buf,
            ["target-qfind", "example.img", "--needles", "ABCD"],
            [
                "[0x010000 @ ABCD (utf-8)]\nABCD\n",
                "[0x012000 @ ABCD (hex)]\n\n",  # No printable string
            ],
            None,
            None,
            id="input-simple",
        ),
        pytest.param(
            buf,
            ["target-qfind", "example.img", "--needles", "B"],
            [
                "[0x010001 @ B (utf-8)]",
                "ABCD",
            ],
            None,
            None,
            id="input-short",
        ),
        pytest.param(
            buf,
            ["target-qfind", "example.img", "--needles", "ABCD", "--raw"],
            [
                "[0x010000 @ ABCD (utf-8)]",
                "00010000  41 42 43 44 00 00 00 00  00 00 00 00 00 00 00 00   ABCD............",
                "[0x012000 @ ABCD (hex)]",
                "00012000  ab cd 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ................",
            ],
            None,
            None,
            id="output-raw",
        ),
        pytest.param(
            buf,
            ["target-qfind", "example.img", "--needles", "ABCD", "--encoding", "utf-16-le", "--raw"],
            [
                "[0x010000 @ ABCD (utf-8)]",
                "00010000  41 42 43 44 00 00 00 00  00 00 00 00 00 00 00 00   ABCD............",
                "[0x011000 @ ABCD (utf-16-le)]",
                "00011000  41 00 42 00 43 00 44 00  00 00 00 00 00 00 00 00   A.B.C.D.........",
                "[0x012000 @ ABCD (hex)]",
                "00012000  ab cd 00 00 00 00 00 00  00 00 00 00 00 00 00 00   ................",
            ],
            None,
            None,
            id="input-utf-16-le",
        ),
        pytest.param(
            buf,
            ["target-qfind", "example.img", "--needles", "ABCD", "--no-hex-decode", "--raw"],
            [
                "[0x010000 @ ABCD (utf-8)]",
            ],
            [
                "[0x012000 @ ABCD (hex)]",
            ],
            None,
            id="behavior-no-hex-decode",
        ),
        pytest.param(
            buf,
            ["target-qfind", "example.img", "--needles", "abcd", "--ignore-case", "--raw"],
            [
                "[0x010000 @ abcd (utf-8)]",
                "00010000  41 42 43 44 00 00 00 00  00 00 00 00 00 00 00 00   ABCD............",
            ],
            None,
            None,
            id="behavior-ignore-case-output-raw",
        ),
        pytest.param(
            buf,
            ["target-qfind", "example.img", "--needles", r"[a-d]{4}", "--regex", "--ignore-case", "--raw"],
            [
                "[0x010000 @ [a-d]{4} (utf-8)]",
                "00010000  41 42 43 44 00 00 00 00  00 00 00 00 00 00 00 00   ABCD............",
            ],
            None,
            None,
            id="input-regex-behavior-ignore-case-output-raw",
        ),
        pytest.param(
            buf_unique,
            ["target-qfind", "example.img", "--needles", "ABCD"],
            None,
            None,
            [("ABCD", 4)],  # two headers and two recovered strings
            id="output-not-unique",
        ),
        pytest.param(
            buf_unique,
            ["target-qfind", "example.img", "--needles", "ABCD", "--unique"],
            None,
            None,
            [("ABCD", 2)],
            id="output-unique",  # one header and one recovered string
        ),
    ],
)
def test_qfind(
    target_bare: Target,
    buf: bytes,
    argv: list[str],
    expected_out: list[str],
    not_expected_out: list[str] | None,
    expected_count: list[tuple] | None,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
) -> None:
    """Test if target-qfind behaves as expected by inspecting stdout contents."""

    mock_disk = RawContainer(io.BytesIO(buf))
    target_bare.disks.add(mock_disk)

    with patch("dissect.target.Target.open_all", return_value=[target_bare]), monkeypatch.context() as m:
        m.setenv("NO_COLOR", "1")
        m.setattr("sys.argv", argv)
        target_qfind()

        out = re_ansi_escape.sub("", capsys.readouterr().out)

        if expected_out:
            for exp_out in expected_out:
                assert exp_out in out

        if not_expected_out:
            for ne_out in not_expected_out:
                assert ne_out not in out

        if expected_count:
            for c_out, count in expected_count:
                assert out.count(c_out) == count
