from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.loaders.velociraptor import VelociraptorLoader
from dissect.target.plugins.apps.edr.velociraptor import VelociraptorPlugin
from tests._utils import absolute_path
from tests.loaders.test_velociraptor import create_root

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target


def test_windows_velociraptor(target_win: Target, tmp_path: Path) -> None:
    """Test that a Windows Velociraptor artefact result is correctly parsed."""
    root = create_root("ntfs", tmp_path)

    with absolute_path("_data/plugins/apps/edr/velociraptor/windows-uploads.json").open("rb") as fh:
        root.joinpath("uploads.json").write_bytes(fh.read())

    with absolute_path("_data/plugins/apps/edr/velociraptor/Windows.Memory.ProcessInfo.json").open("rb") as fh:
        root.joinpath("results/Windows.Memory.ProcessInfo.json").write_bytes(fh.read())

    assert VelociraptorLoader.detect(root) is True

    loader = VelociraptorLoader(root)
    loader.map(target_win)
    target_win.apply()

    target_win.add_plugin(VelociraptorPlugin)

    results = list(target_win.velociraptor())

    record = results[0]

    assert record.name == "Microsoft.SharePoint.exe"
    assert record.pebbaseaddress == "0x295000"
    assert record.pid == 8120
    assert (
        record.imagepathname
        == "C:\\Users\\IEUser\\AppData\\Local\\Microsoft\\OneDrive\\24.070.0407.0003\\Microsoft.SharePoint.exe"
    )
    assert record.commandline == "/silentConfig"
    assert record.currentdirectory == "C:\\Windows\\system32\\"
    assert record._desc.name == "velociraptor/windows_memory_processinfo"
    assert record.env.allusersprofile == "C:\\ProgramData"
