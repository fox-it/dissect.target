from __future__ import annotations

from typing import TYPE_CHECKING
from unittest.mock import patch

import pytest

from dissect.target.helpers.record import UnixUserRecord
from dissect.target.plugins.os.unix.bsd.darwin.macos.global_user_preferences import GlobalUserPreferencesPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.mark.parametrize(
    ("names", "paths"),
    [
        (
            (
                "user.plist",
                "securityagent.plist",
                "root.plist",
            ),
            (
                "/Users/user/Library/Preferences/.GlobalPreferences.plist",
                "/private/var/db/securityagent/Library/Preferences/.GlobalPreferences.plist",
                "/private/var/root/Library/Preferences/.GlobalPreferences.plist",
            ),
        ),
    ],
)
def test_global_user_preferences(
    names: tuple[str, ...],
    paths: tuple[str, ...],
    target_unix: Target,
    fs_unix: VirtualFilesystem,
) -> None:
    user = UnixUserRecord(
        name="user",
        uid=501,
        gid=20,
        home="/Users/user",
        shell="/bin/zsh",
    )
    securityagent = UnixUserRecord(
        name="securityagent",
        uid=92,
        gid=92,
        home="/private/var/db/securityagent",
        shell="/usr/bin/false",
    )
    root = UnixUserRecord(
        name="root",
        uid=0,
        gid=0,
        home="/private/var/root",
        shell="/bin/sh",
    )
    target_unix.users = lambda: [
        user,
        securityagent,
        root,
    ]

    for name, path in zip(names, paths, strict=True):
        data_file = absolute_path(f"_data/plugins/os/unix/bsd/darwin/macos/global_user_preferences/{name}")
        fs_unix.map_file(path, data_file)
        entry = fs_unix.get(path)
        stat_result = entry.stat()
        stat_result.st_mtime = 1704067199

    with patch.object(entry, "stat") as mock_stat:
        mock_stat.return_value = stat_result

        target_unix.add_plugin(GlobalUserPreferencesPlugin)

        results = list(target_unix.global_user_preferences())
        results.sort(key=lambda r: r.source)

        assert len(results) == 3

        assert results[0].AKLastLocale == "en_US@rg=nlzzzz"
        assert results[0].com_apple_sound_beep_flash == 0
        assert results[0].NSLinguisticDataAssetsRequested == "['en', 'en_US', 'nl', 'nl_NL']"
        assert not results[0].AppleMiniaturizeOnDoubleClick
        assert results[0].NSAutomaticPeriodSubstitutionEnabled
        assert results[0].NSSpellCheckerDictionaryContainerTransitionComplete
        assert results[0].com_apple_springing_delay == "0.5"
        assert results[0].ACDMonthlyAnalyticsLastPosted == "796140692.59226"
        assert results[0].AKLastIDMSEnvironment == 0
        assert results[0].NSAutomaticCapitalizationEnabled
        assert results[0].NSLinguisticDataAssetsRequestedByChecker == "[]"
        assert results[0].NSUserDictionaryReplacementItems == ("[{'replace': 'omw', 'on': 1, 'with': 'On my way!'}]")
        assert results[0].NSLinguisticDataAssetsRequestTime == "2026-03-25 14:12:53.295950"
        assert results[0].AppleAntiAliasingThreshold == 4
        assert results[0].com_apple_springing_enabled
        assert results[0].AppleLanguages == "['en-US', 'nl-NL']"
        assert results[0].AppleLocale == "en_US@rg=nlzzzz"
        assert results[0].com_apple_trackpad_forceClick
        assert results[0].NSLinguisticDataAssetsRequestLastInterval == "86400.0"
        assert results[0].AppleLanguagesSchemaVersion == 5400
        assert results[0].source == "/Users/user/Library/Preferences/.GlobalPreferences.plist"

        assert results[1].AppleKeyboardUIMode == 2
        assert results[1].source == ("/private/var/db/securityagent/Library/Preferences/.GlobalPreferences.plist")

        assert results[2].AppleLocale == "en_US"
        assert results[2].AppleKeyboardUIMode == 3
        assert results[2].com_apple_sound_beep_flash == 0
        assert results[2].source == ("/private/var/root/Library/Preferences/.GlobalPreferences.plist")
