import io
import platform
from urllib.parse import urlparse

import pytest

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.loaders.log import LogLoader


@pytest.mark.parametrize(
    "path, uri, input_file, expected_mapping",
    [
        ("/dir/*.evt*", None, "/dir/test.evtx", "/sysvol/windows/system32/winevt/logs/test.evtx"),
        ("/dir/*.evt*", None, "/dir/test.evt", "/sysvol/windows/system32/config/test.evt"),
        ("/source/iis.log", "log:///dir/with/files/*.log?hint=iis", "/source/iis.log", "/sysvol/files/logs/iis.log"),
    ],
)
@pytest.mark.skipif(
    platform.system() == "Windows", reason="Assertion fails because of Unix-specific path. Needs to be fixed."
)
def test_log_loader(path: str, uri: str, input_file: str, expected_mapping: str) -> None:
    vfs = VirtualFilesystem()
    vfs.map_file_fh(input_file, io.BytesIO(b"\x00"))
    target = Target()
    log_loader = LogLoader(vfs.path(path), parsed_path=urlparse(uri))
    log_loader.map(target)
    observed_mapping = next(target.filesystems[0].path("/").rglob("*.*"))
    assert str(expected_mapping) == str(observed_mapping)
