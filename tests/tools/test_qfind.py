import io
import re
from unittest.mock import patch

import pytest

from dissect.target import Target
from dissect.target.containers.raw import RawContainer
from dissect.target.tools.qfind import main as target_qfind

re_ansi_escape = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")


def test_yara(target_bare: Target, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
    buf = (
        (b"\x00" * 1024 * 64)
        + (b"ABCD" + b"\x00" * ((1024 * 4) - 4))
        + (b"A\x00B\x00C\x00D\x00" + b"\x00" * ((1024 * 4) - 8))
        + (b"\xab\xcd" + b"\x00" * ((1024 * 4) - 2))
        + (b"\x00" * 1024 * 52)
    )
    mock_disk = RawContainer(io.BytesIO(buf))
    target_bare.disks.add(mock_disk)

    with patch("dissect.target.Target.open_all", return_value=[target_bare]), monkeypatch.context() as m:
        m.setattr(
            "sys.argv",
            [
                "target-qfind",
                "example.img",
                "--needles",
                "ABCD",
            ],
        )
        target_qfind()

        out = re_ansi_escape.sub("", capsys.readouterr().out)
        assert "[0x010000 @ ABCD (utf-8)]\nABCD\n" in out
        assert "[0x012000 @ ABCD (hex)]\n\n" in out  # No printable string
