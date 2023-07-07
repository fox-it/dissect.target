import platform
import tempfile
from io import BytesIO
from pathlib import Path

import pytest

from dissect.target.filesystem import VirtualFilesystem

yara = pytest.importorskip("dissect.target.plugins.filesystem.yara", reason="yara-python module unavailable")


@pytest.mark.skipif(platform.system() == "Windows", reason="Permission Error. Needs to be fixed.")
def test_yara_plugin(mock_target):
    test_rule = """
    rule test_rule_name {
        strings:
            $ = "test string"

        condition:
            any of them
    }
    """
    vfs = VirtualFilesystem()
    vfs.map_file_fh("test_file", BytesIO(b"test string"))
    vfs.map_file_fh("/test/dir/to/test_file", BytesIO(b"test string"))

    mock_target.filesystems.add(vfs)

    with tempfile.NamedTemporaryFile("w+t") as tmp_file:
        tmp_file.write(test_rule)
        tmp_file.flush()

        mock_target.add_plugin(yara.YaraPlugin)
        results = list(mock_target.yara(rule_files=[Path(tmp_file.name)]))

    assert len(results) == 2
    assert results[0].path == "/test_file"
    assert results[1].path == "/test/dir/to/test_file"
    assert results[0].rule == "test_rule_name"
