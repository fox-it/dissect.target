from __future__ import annotations

import pytest

from dissect.target.helpers.localeutil import normalize_language, normalize_timezone


def test_helpers_localeutil_normalize_timezone() -> None:
    assert normalize_timezone("W. Europe Standard Time") == "Europe/Berlin"
    assert normalize_timezone("GMT Standard Time") == "Europe/London"
    assert normalize_timezone("UTC") == "UTC"


@pytest.mark.parametrize(
    ("language_input", "expected_output"),
    [
        ("en_US.UTF-8", "en_US"),
        ("nl", "nl_NL"),
        ("en", "en_US"),
        ("en-US", "en_US"),
    ],
)
def test_helpers_localeutil_normalize_language(language_input: str, expected_output: str) -> None:
    """Test if we normalize languages to ISO-3166 correctly."""

    assert normalize_language(language_input) == expected_output
