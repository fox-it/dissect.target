from pathlib import Path

from dissect.target import Target
from dissect.target.loaders.velociraptor import VelociraptorLoader
from dissect.target.plugins.apps.edr.velociraptor import VelociraptorPlugin
from tests._utils import absolute_path
from tests.loaders.test_velociraptor import create_root


def test_windows_velociraptor(target_bare: Target, tmp_path: Path) -> None:
    root = create_root("ntfs", tmp_path)

    with open(absolute_path("_data/plugins/apps/edr/velociraptor/windows-uploads.json"), "rb") as fh:
        root.joinpath("uploads.json").write_bytes(fh.read())

    with open(absolute_path("_data/plugins/apps/edr/velociraptor/Windows.Memory.ProcessInfo.json"), "rb") as fh:
        root.joinpath("results/Windows.Memory.ProcessInfo.json").write_bytes(fh.read())

    assert VelociraptorLoader.detect(root) is True

    loader = VelociraptorLoader(root)
    loader.map(target_bare)
    target_bare.apply()

    target_bare.add_plugin(VelociraptorPlugin)

    results = list(target_bare.velociraptor())

    record = results[0]

    # FIXME: assert
