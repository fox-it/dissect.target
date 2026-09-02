from __future__ import annotations

import io
from typing import TYPE_CHECKING
from unittest.mock import Mock, patch

import pytest

from dissect.target.filesystem import VirtualFile, VirtualFilesystem
from dissect.target.tools.extract import main as target_extract
from tests._utils import absolute_path
from dissect.target.plugins.apps.webserver import iis

if TYPE_CHECKING:
    from pathlib import Path


def test_target_extract(
        capsys: pytest.CaptureFixture, monkeypatch: pytest.MonkeyPatch, target_win_tzinfo: Target,
        fs_win: VirtualFilesystem, tmp_path: Path
) -> None:
    with monkeypatch.context() as m:
        config_path = absolute_path("_data/plugins/apps/webserver/iis/iis-applicationHost-iis.config")
        data_dir = absolute_path("_data/plugins/apps/webserver/iis/iis-logs-iis")
        fs_win.map_file("windows/system32/inetsrv/config/applicationHost.config", config_path)
        fs_win.map_dir("Users/John/iis-logs", data_dir)
        target_win_tzinfo.add_plugin(iis.IISLogsPlugin)

        output_path = tmp_path / "out"
        output_path.mkdir(parents=True, exist_ok=True)

        with (
            patch("dissect.target.tools.extract.open_targets", return_value=[target_win_tzinfo]),
        ):
            m.setattr(
                "sys.argv", ["target-extract", "-t", "target-mock", "-f" "iis", "-v", "--out", str(output_path)],
            )

            target_extract()
            assert output_path.joinpath("iis-logs/W3SVC1/u_in211001.log").exists()

