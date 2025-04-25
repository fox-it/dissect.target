from __future__ import annotations

import pytest

from dissect.target.loaders.itunes import translate_file_path


@pytest.mark.parametrize(
    ("domain", "relative_path", "result"),
    [
        pytest.param(
            "HomeDomain",
            "Library/Safari/SafariTabs.db",
            "/private/var/mobile/Library/Safari/SafariTabs.db",
            id="HomeDomain",
        ),
        pytest.param("ProtectedDomain", "", "ProtectedDomain", id="ProtectedDomain"),
        pytest.param(
            "AppDomain-com.apple.freeform",
            "",
            "/private/var/mobile/Containers/Data/Application/com.apple.freeform",
            id="AppDomain",
        ),
    ],
)
def test_translate_file_path(domain: str, relative_path: str, result: str) -> None:
    assert translate_file_path(domain, relative_path) == result
