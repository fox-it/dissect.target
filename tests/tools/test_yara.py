from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.tools.yara import HAS_YARA
from dissect.target.tools.yara import main as target_yara
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.target import Target


@pytest.mark.skipif(not HAS_YARA, reason="requires python-yara")
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
                str(absolute_path("_data/plugins/filesystem/yara/rule.yar")),
                "--path",
                "/",
                "--check",
                "-s",
            ],
        )
        target_yara()

        out, _ = capsys.readouterr()

        hit1 = "<filesystem/yara/match hostname=None domain=None path='/test_file' digest=(md5=d690ba32b59d28614aebefe9b03c74d4, sha1=4b1ced217aabe37138e96fb93bf40026639b9d3b, sha256=7a644118588ff0dcf2fadbe198ae1f1629c29374bac491ba41d5cf957edf0dfc) rule='test_rule_name' tags=['tag1', 'tag2', 'tag3']"  # noqa E501
        hit2 = "<filesystem/yara/match hostname=None domain=None path='/test/dir/to/test_file' digest=(md5=bd7490dd2978ce983e2e1613ac8444c0, sha1=849a062cf09280f5c7dce4c7f87c69a1d9262e08, sha256=9bf7629a67c7ce8019910f1c1251fe44b61b3fff55a59a5e148af3c207dc102f) rule='test_rule_name' tags=['tag1', 'tag2', 'tag3']"  # noqa E501

        assert hit1 in out
        assert hit2 in out
