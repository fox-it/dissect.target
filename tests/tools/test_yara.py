from __future__ import annotations

import gzip
import os
from io import BytesIO
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest
from flow.record import fieldtypes

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.tools.yara import HAS_YARA
from dissect.target.tools.yara import main as target_yara
from tests._utils import absolute_path

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target


@pytest.mark.skipif(not HAS_YARA, reason="requires yara-python")
def test_yara(target_default: Target, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture) -> None:
    vfs = VirtualFilesystem()
    vfs.map_file_fh("test_file", BytesIO(b"hello there this is a test string!"))
    vfs.map_file_fh("/test/dir/to/test_file", BytesIO(b"this is another test string for YARA testing."))
    vfs.map_file_fh("should_not_hit", BytesIO(b"this is another file."))
    target_default.fs.mount("/", vfs)

    with patch("dissect.target.Target.open_all", return_value=[target_default]), monkeypatch.context() as m:
        m.setattr(
            "sys.argv",
            [
                "target-yara",
                "example.img",
                "--rules",
                str(absolute_path("_data/plugins/filesystem/yara/rule-dir/rule.yar")),
                "--path",
                "/",
                "--check",
                "-s",
            ],
        )
        target_yara()

        out, _ = capsys.readouterr()

        hit1 = "<filesystem/yara/match hostname=None domain=None ts_mtime=1970-01-01 00:00:00+00:00 ts_atime=1970-01-01 00:00:00+00:00 ts_ctime=1970-01-01 00:00:00+00:00 ts_btime=None path='/test_file' rule='test_rule_name' matches=['$=test string'] tags=['tag1', 'tag2', 'tag3'] digest=(md5=d690ba32b59d28614aebefe9b03c74d4, sha1=4b1ced217aabe37138e96fb93bf40026639b9d3b, sha256=7a644118588ff0dcf2fadbe198ae1f1629c29374bac491ba41d5cf957edf0dfc)"  # noqa E501
        hit2 = "<filesystem/yara/match hostname=None domain=None ts_mtime=1970-01-01 00:00:00+00:00 ts_atime=1970-01-01 00:00:00+00:00 ts_ctime=1970-01-01 00:00:00+00:00 ts_btime=None path='/test/dir/to/test_file' rule='test_rule_name' matches=['$=test string'] tags=['tag1', 'tag2', 'tag3'] digest=(md5=bd7490dd2978ce983e2e1613ac8444c0, sha1=849a062cf09280f5c7dce4c7f87c69a1d9262e08, sha256=9bf7629a67c7ce8019910f1c1251fe44b61b3fff55a59a5e148af3c207dc102f)"  # noqa E501

        assert len(out.splitlines()) == 2

        assert hit1 in out
        assert hit2 in out


@pytest.mark.skipif(not HAS_YARA, reason="requires yara-python")
@pytest.mark.parametrize("no_decompress", [False, True], ids=["decompress", "no-decompress"])
def test_yara_decompress(
    target_default: Target,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
    tmp_path: Path,
    no_decompress: bool,
) -> None:
    """Test that the yara plugin can automatically decompress files for scanning,
    and that this can be disabled with the --no-decompress flag.
    """
    vfs = VirtualFilesystem()
    target_default.fs.mount("/", vfs)

    gzip_path = tmp_path / "messages.gz"
    gzip_path.write_bytes(gzip.compress(b"test string for YARA testing (gzipped).", mtime=0))
    os.utime(gzip_path, (0, 0))  # ensure mtime is set to 0 for consistent testing
    vfs.map_file("/var/log/messages.gz", gzip_path)

    with (
        patch("dissect.target.Target.open_all", return_value=[target_default]),
        monkeypatch.context() as m,
    ):
        m.setattr(
            "sys.argv",
            [
                "target-yara",
                "example.img",
                "--rules",
                str(absolute_path("_data/plugins/filesystem/yara/rule-dir/rule.yar")),
                "--strings",
                "--no-decompress" if no_decompress else "",
            ],
        )
        target_yara()

        out, _ = capsys.readouterr()

        gzstat = gzip_path.stat()
        ts_ctime = fieldtypes.datetime(gzstat.st_ctime)
        ts_btime = fieldtypes.datetime(gzstat.st_birthtime) if hasattr(gzstat, "st_birthtime") else None
        hit = f"<filesystem/yara/match hostname=None domain=None ts_mtime=1970-01-01 00:00:00+00:00 ts_atime=1970-01-01 00:00:00+00:00 ts_ctime={ts_ctime} ts_btime={ts_btime} path='/var/log/messages.gz' rule='test_rule_name' matches=['$=test string'] tags=['tag1', 'tag2', 'tag3'] digest=(md5=485a4c5e37cd08a0cdf028cc2b1f32b4, sha1=7716bff4d3282184a17f35f5f0dde25aede762f9, sha256=d175bb08145c0be3338b058f8b7a775cc08967ba6aa7448fa2af9957eb1ab37f)"  # noqa E501

        if no_decompress:
            assert len(out.splitlines()) == 0
            assert hit not in out
        else:
            assert len(out.splitlines()) == 1
            assert hit in out
