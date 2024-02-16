from typing import Iterator

import pytest
from flow.record.fieldtypes import datetime as dt

from dissect.target import Target
from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.apps.browser.firefox import FirefoxPlugin
from tests._utils import absolute_path

# NOTE: Missing extensions tests for Firefox.


@pytest.fixture
def target_firefox_win(target_win_users: Target, fs_win: VirtualFilesystem) -> Iterator[Target]:
    fs_win.map_dir(
        "Users\\John\\AppData\\Local\\Mozilla\\Firefox\\Profiles\\g1rbw8y7.default-release\\",
        absolute_path("_data/plugins/apps/browser/firefox/"),
    )

    target_win_users.add_plugin(FirefoxPlugin)

    yield target_win_users


@pytest.fixture
def target_firefox_unix(target_unix_users: Target, fs_unix: VirtualFilesystem) -> Iterator[Target]:
    fs_unix.map_dir(
        "/root/.mozilla/firefox/g1rbw8y7.default-release/", absolute_path("_data/plugins/apps/browser/firefox/")
    )
    fs_unix.map_dir(
        "/root/.mozilla/firefox/g1rbw8y7.default-release/",
        absolute_path("_data/plugins/apps/browser/firefox/passwords/default/"),
    )

    target_unix_users.add_plugin(FirefoxPlugin)

    yield target_unix_users


@pytest.mark.parametrize(
    "target_platform",
    ["target_firefox_win", "target_firefox_unix"],
)
def test_firefox_history(target_platform: Target, request: pytest.FixtureRequest) -> None:
    target_platform = request.getfixturevalue(target_platform)
    records = list(target_platform.firefox.history())

    assert len(records) == 24
    assert set(["firefox"]) == set(record.browser for record in records)

    assert records[0].url == "https://www.mozilla.org/privacy/firefox/"
    assert records[0].id == "1"
    assert records[0].description == "47356411089529"
    assert records[0].visit_count == 1
    assert records[0].ts == dt("2021-12-01T10:42:05.742000+00:00")


@pytest.mark.parametrize(
    "target_platform",
    ["target_firefox_win", "target_firefox_unix"],
)
def test_firefox_downloads(target_platform: Target, request: pytest.FixtureRequest) -> None:
    target_platform = request.getfixturevalue(target_platform)
    records = list(target_platform.firefox.downloads())

    assert len(records) == 3
    assert set(["firefox"]) == set(record.browser for record in records)

    assert records[0].id == 1
    assert records[0].ts_start == dt("2021-12-01T10:57:01.175000+00:00")
    assert records[0].ts_end == dt("2021-12-01T10:57:01.321000+00:00")
    assert (
        records[0].url
        == "https://dl.google.com/tag/s/appguid%3D%7B8A69D345-D564-463C-AFF1-A69D9E530F96%7D%26iid%3D%7B2098EF96-29DB"
        "-B268-0B90-01AD59CD5C17%7D%26lang%3Dnl%26browser%3D3%26usagestats%3D1%26appname%3DGoogle%2520Chrome%26needs"
        "admin%3Dprefers%26ap%3Dx64-stable-statsdef_1%26installdataindex%3Dempty/update2/installers/ChromeSetup.exe"
    )


@pytest.mark.parametrize(
    "target_platform",
    ["target_firefox_win", "target_firefox_unix"],
)
def test_firefox_cookies(target_platform: Target, request: pytest.FixtureRequest) -> None:
    target_platform = request.getfixturevalue(target_platform)

    records = list(target_platform.firefox.cookies())

    assert len(records) == 4
    assert set(["firefox"]) == set(record.browser for record in records)

    assert sorted([*map(lambda c: c.name, records)]) == [
        "_lr_env_src_ats",
        "_lr_retry_request",
        "_uc_referrer",
        "_uc_referrer",
    ]


@pytest.mark.parametrize(
    "target_platform",
    ["target_firefox_win", "target_firefox_unix"],
)
def test_firefox_password_plugin(target_platform: Target, request: pytest.FixtureRequest) -> None:
    target_platform = request.getfixturevalue(target_platform)

    records = list(target_platform.firefox.passwords())
    assert len(records) == 2

    for record in records:
        assert record.browser == "firefox"
        assert record.decrypted_username == "username"
        assert record.decrypted_password == "password"


def test_unix_firefox_password_plugin_with_primary_password(
    target_unix_users: Target, fs_unix: VirtualFilesystem
) -> None:
    fs_unix.map_dir(
        "/root/.mozilla/firefox/g1rbw8y7.default-release/",
        absolute_path("_data/plugins/apps/browser/firefox/passwords/primary/"),
    )
    target_unix_users.add_plugin(FirefoxPlugin)

    records = list(target_unix_users.firefox.passwords(firefox_primary_password="PrimaryPassword"))

    assert len(records) == 1

    for record in records:
        assert record.browser == "firefox"
        assert record.decrypted_username == "username"
        assert record.decrypted_password == "password"
