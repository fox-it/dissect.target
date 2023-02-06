from dissect.target.helpers.localeutil import normalize_language, normalize_timezone


def test_helpers_localeutil_normalize_timezone():
    assert normalize_timezone("W. Europe Standard Time") == "Europe/Berlin"
    assert normalize_timezone("GMT Standard Time") == "Europe/London"
    assert normalize_timezone("UTC") == "Etc/UTC"


def test_helpers_localeutil_normalize_language():
    assert normalize_language("en_US.UTF-8") == "en_US"
    assert normalize_language("nl") == "nl_NL"
