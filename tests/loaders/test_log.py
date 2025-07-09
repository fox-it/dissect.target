from __future__ import annotations

import io
from typing import TYPE_CHECKING
from urllib.parse import urlparse

import pytest
from flow.record.fieldtypes import path as flow_path

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.loaders.log import LogLoader

if TYPE_CHECKING:
    from dissect.target.target import Target


@pytest.mark.parametrize(
    ("path", "uri", "input_file", "expected_mapping"),
    [
        ("/dir/*.evt*", None, "/dir/test.evtx", "/sysvol/windows/system32/winevt/logs/test.evtx"),
        ("/dir/*.evt*", None, "/dir/test.evt", "/sysvol/windows/system32/config/test.evt"),
        ("/source/iis.log", "log:///dir/with/files/*.log?hint=iis", "/source/iis.log", "/sysvol/files/logs/iis.log"),
    ],
)
def test_log_loader(target_default: Target, path: str, uri: str, input_file: str, expected_mapping: str) -> None:
    with pytest.deprecated_call(match="The LogLoader is deprecated in favor of direct files"):
        vfs = VirtualFilesystem()
        vfs.map_file_fh(input_file, io.BytesIO(b"\x00"))
        log_loader = LogLoader(vfs.path(path), parsed_path=urlparse(uri))
        log_loader.map(target_default)
        # TODO: RGLOB does not take into account the seperator of the target, so maybe an issue with the flavour?
        observed_mapping = next(target_default.fs.path("/").rglob("*.*"))
        assert expected_mapping == flow_path(observed_mapping)
