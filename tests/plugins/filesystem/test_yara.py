import tempfile
from io import BytesIO
from pathlib import Path

import pytest

from dissect.target.filesystem import VirtualFilesystem

yara = pytest.importorskip("dissect.target.plugins.filesystem.yara", reason="yara-python module unavailable")


def test_yara_plugin(tmp_path, target_default):
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

    target_default.fs.mount("/", vfs)

    with tempfile.NamedTemporaryFile(mode="w+t", dir=tmp_path, delete=False) as tmp_file:
        tmp_file.write(test_rule)
        tmp_file.close()

        target_default.add_plugin(yara.YaraPlugin)
        results = list(target_default.yara(rule_files=[Path(tmp_file.name)]))

    assert len(results) == 2
    assert results[0].path == "/test_file"
    assert results[1].path == "/test/dir/to/test_file"
    assert results[0].rule == "test_rule_name"
