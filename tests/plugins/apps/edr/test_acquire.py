from __future__ import annotations

from dissect.target.plugins.apps.edr.acquire import AcquirePlugin
from dissect.target.target import Target
from tests._utils import absolute_path


def test_acquire_handles_plugin() -> None:
    file_hashes_target = Target().open(absolute_path("_data/plugins/apps/edr/acquire/handles/test-acquire-handles.tar"))
    file_hashes_target.add_plugin(AcquirePlugin)

    results = list(file_hashes_target.acquire.handles())
    first_result = results[0]

    assert first_result.name == r"\Windows\Fonts"
    assert first_result.handle_type == "EtwRegistration"
    assert first_result.unique_process_id == 1
    assert first_result.object == "0xfffftest"
    assert results[-1].unique_process_id == 124
    assert len(results) == 124


def test_acquire_hash_plugin() -> None:
    file_hashes_target = Target().open(absolute_path("_data/plugins/apps/edr/acquire/hash/test-acquire-hash.tar"))
    file_hashes_target.add_plugin(AcquirePlugin)

    results = list(file_hashes_target.acquire.hashes())

    assert results[0].path == "/sysvol/Windows/bfsvc.exe"
    assert len(results) == 998
