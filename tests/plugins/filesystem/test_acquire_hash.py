from dissect.target import Target
from dissect.target.plugins.filesystem.acquire_hash import AcquireHashPlugin
from tests._utils import absolute_path


def test_acquire_hash_plugin():
    file_hashes_target = Target().open(absolute_path("_data/plugins/filesystem/acquire_hash/test-acquire-hash.tar"))
    file_hashes_target.add_plugin(AcquireHashPlugin)

    results = list(file_hashes_target.acquire_hashes())

    assert results[0].path == "/sysvol/Windows/bfsvc.exe"
    assert len(results) == 998
