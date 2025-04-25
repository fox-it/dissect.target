from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from dissect.target.plugins.apps.other.env import EnvironmentFilePlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_envfile(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    target_unix.add_plugin(EnvironmentFilePlugin)
    fs_unix.map_file("/root/foo.env", absolute_path("_data/plugins/apps/other/env/test.env"))
    fs_unix.map_file("/root/foo/bar/test.env", absolute_path("_data/plugins/apps/other/env/test.env"))

    records = list(target_unix.envfile(env_path="/root"))

    assert len(records) == 4 * 2

    assert isinstance(records[0].ts_mtime, datetime)
    assert records[0].key == "DEBUG"
    assert records[0].value == "True"
    assert records[0].comment is None
    assert records[0].path == "/root/foo.env"

    assert isinstance(records[1].ts_mtime, datetime)
    assert records[1].key == "OPTIONAL"
    assert records[1].value == ""
    assert records[1].comment == "comment"
    assert records[1].path == "/root/foo.env"

    assert isinstance(records[2].ts_mtime, datetime)
    assert records[2].key == "FOO"
    assert records[2].value == "bar"
    assert records[2].comment == "this is a comment"
    assert records[2].path == "/root/foo.env"

    assert isinstance(records[3].ts_mtime, datetime)
    assert records[3].key == "HELLO"
    assert records[3].value == "world"
    assert records[3].comment is None
    assert records[3].path == "/root/foo.env"
