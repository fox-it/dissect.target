from __future__ import annotations

import datetime
from typing import TYPE_CHECKING

from dissect.target.plugins.os.unix.linux.android.applications import AndroidApplicationsPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_android_apps(target_android: Target, fs_android: VirtualFilesystem) -> None:
    """Test if a installed app is detected in packages.xml and if the apk can be parsed correcly."""
    # packages.xml originates from DigitalCorpora Android 14 image.
    fs_android.map_file(
        "/data/system/packages.xml", absolute_path("_data/plugins/os/unix/linux/android/applications/packages.xml")
    )

    # We hi-jack a random record with a public domain APK from https://f-droid.org/en/packages/dev.serwin.AnarchRE/
    fs_android.map_file(
        "/system/priv-app/SharedStorageBackup",
        absolute_path("_data/plugins/os/unix/linux/android/applications/dev.serwin.AnarchRE_3.apk"),
    )

    target_android.add_plugin(AndroidApplicationsPlugin)
    records = sorted(
        target_android.applications(),
        key=lambda r: getattr(r, "ts_modified", datetime.datetime.fromtimestamp(0, tz=datetime.timezone.utc)),
    )
    assert len(records) == 369 + 2

    app = next(r for r in records if getattr(r, "path", "") == "/system/priv-app/SharedStorageBackup")
    assert app.ts_modified
    assert not app.ts_installed
    assert app.name == "com.android.sharedstoragebackup"
    assert app.app_id == "com.android.sharedstoragebackup"
    assert app.version == "34"
    assert not app.author
    assert app.type == "app, priv-app"
    assert app.path == "/system/priv-app/SharedStorageBackup"
    assert app.source == "/data/system/packages.xml"

    cert = next(r for r in records if hasattr(r, "fingerprint"))
    assert cert.app_id == "com.android.sharedstoragebackup"
    assert cert.fingerprint.sha1 == "15cb7b27f96e5ed60d64a38bd1028755269836b5"
    assert cert.serial_number == 8624090640635966175
    assert cert.serial_number_hex == "77aeecbec9e0b2df"
    assert cert.not_valid_before == datetime.datetime.fromisoformat("2025-07-06 08:48:03+00:00")
    assert cert.not_valid_after == datetime.datetime.fromisoformat("2052-11-21 08:48:03+00:00")
    assert cert.issuer_dn == "C=UK,ST=ORG,L=ORG,O=fdroid.org,OU=FDroid,CN=FDroid"
    assert cert.subject_dn == "C=UK,ST=ORG,L=ORG,O=fdroid.org,OU=FDroid,CN=FDroid"

    exports = next(r for r in records if hasattr(r, "permissions"))
    assert exports.app_id == "com.android.sharedstoragebackup"
    assert not exports.app_label
    assert not exports.app_manifest_name
    assert exports.permissions == ["android.permission.VIBRATE"]
    assert exports.features == [
        "android.hardware.touchscreen",
        "android.hardware.bluetooth",
        "android.hardware.gamepad",
        "android.hardware.usb.host",
        "android.hardware.type.pc",
    ]
    assert exports.exported_activities == ["dev.serwin.AnarchRE.AnarchreActivity"]
    assert exports.exported_receivers == []
    assert exports.exported_services == []
    assert exports.exported_providers == []
    assert exports.intent_actions == [
        "android.intent.action.MAIN",
        "android.hardware.usb.action.USB_DEVICE_ATTACHED",
    ]
    assert exports.intent_categories == ["android.intent.category.LAUNCHER"]
    assert exports.source == "/system/priv-app/SharedStorageBackup"
