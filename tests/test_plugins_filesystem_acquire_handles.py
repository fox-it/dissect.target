import platform

import pytest

from dissect.target import Target
from dissect.target.plugins.filesystem.acquire_handles import OpenHandlesPlugin

from ._utils import absolute_path


@pytest.mark.skipif(platform.system() == "Windows", reason="Assertion Error. Needs to be fixed.")
def test_acquire_hash_plugin():
    file_hashes_target = Target().open(absolute_path("data/test-acquire-handles.tar"))
    file_hashes_target.add_plugin(OpenHandlesPlugin)

    results = list(file_hashes_target.acquire_handles())
    first_result = results[0]

    assert first_result.name.name == r"\Windows\Fonts"
    assert first_result.handle_type == "EtwRegistration"
    assert first_result.unique_process_id == 1
    assert first_result.object == "0xfffftest"
    assert results[-1].unique_process_id == 124
    assert len(results) == 124
