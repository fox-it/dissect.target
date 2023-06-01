import io
import platform

import pytest

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.loaders.log import LogLoader


@pytest.mark.parametrize(
    "input_file, expected_mapping",
    [
        ("/dir/test.evtx", "/sysvol/windows/system32/winevt/logs/test.evtx"),
        ("/dir/test.evt", "/sysvol/windows/system32/config/test.evt"),
    ],
)
@pytest.mark.skipif(
    platform.system() == "Windows", reason="Assertion fails because of Unix-specific path. Needs to be fixed."
)
def test_log_loader(input_file: str, expected_mapping: str) -> None:
    vfs = VirtualFilesystem()
    vfs.map_file_fh(input_file, io.BytesIO(b"\x00"))
    target = Target()
    log_loader = LogLoader(vfs.path("/dir/*.evt*"))
    log_loader.map(target)
    observed_mapping = next(target.filesystems[0].path("/").rglob("*.evt*"))
    assert str(expected_mapping) == str(observed_mapping)
