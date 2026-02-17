from __future__ import annotations

import gzip
from textwrap import dedent
from typing import TYPE_CHECKING

from dissect.target.filesystems.ntds import NtdsFilesystem
from dissect.target.target import Target
from dissect.target.tools.shell import TargetCli
from dissect.target.tools.utils import fs
from tests._utils import absolute_path

if TYPE_CHECKING:
    import pytest


def test_ntds() -> None:
    """Test that the NTDS filesystem can be detected and read correctly."""
    with gzip.open(absolute_path("_data/plugins/os/windows/ad/ntds/goad/ntds.dit.gz"), "rb") as fh:
        assert NtdsFilesystem.detect(fh)

        fs = NtdsFilesystem(fh)

        root = fs.get("/")
        assert root.is_dir()
        assert root.name == ""

        users = fs.get("local/sevenkingdoms/Users")
        assert users.is_dir()
        assert users.name == "Users"
        assert (
            users.open()
            .read()
            .decode()
            .startswith(
                dedent(
                    """
                    DNT: 2050
                    Pdnt: 2043
                    Obj: True
                    RdnType: cn
                    """
                ).strip()
            )
        )

        administrator = fs.get("local/sevenkingdoms/Users/Administrator")
        assert administrator.is_file()
        assert administrator.name == "Administrator"
        assert (
            administrator.open()
            .read()
            .decode()
            .startswith(
                dedent(
                    """
                    DNT: 3802
                    Pdnt: 2050
                    Obj: True
                    RdnType: cn
                    """
                ).strip()
            )
        )


def test_shell(capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch) -> None:
    """Test that the shell can be used to read files and directories from the NTDS filesystem."""
    # disable colorful output in `target-shell`
    monkeypatch.setattr(fs, "LS_COLORS", {})

    with gzip.open(absolute_path("_data/plugins/os/windows/ad/ntds/goad/ntds.dit.gz"), "rb") as fh:
        t = Target()
        t.fs.mount("/", NtdsFilesystem(fh))

        cli = TargetCli(t)

        cli.onecmd("cat local/sevenkingdoms/Users")
        captured = capsys.readouterr()
        assert captured.out.startswith("DNT: 2050")

        cli.onecmd("cat local/sevenkingdoms/Users/Administrator")
        captured = capsys.readouterr()
        assert captured.out.startswith("DNT: 3802")
