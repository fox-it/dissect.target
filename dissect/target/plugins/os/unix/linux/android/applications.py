from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING

from asn1crypto import cms, pem

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.filesystems.zip import ZipFilesystem
from dissect.target.helpers.certificate import COMMON_CERTIFICATE_FIELDS, parse_x509
from dissect.target.helpers.record import (
    COMMON_APPLICATION_FIELDS,
    TargetRecordDescriptor,
)
from dissect.target.plugin import OperatingSystem, Plugin, export
from dissect.target.plugins.os.unix.linux.android.util.xml import read_android_xml

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


AndroidApplicationRecord = TargetRecordDescriptor(
    "android/application",
    [
        *COMMON_APPLICATION_FIELDS,
        ("string", "app_id"),
        ("path", "source"),
    ],
)

AndroidApplicationCertificateRecord = TargetRecordDescriptor(
    "android/application/certificate",
    [
        *COMMON_CERTIFICATE_FIELDS,
        ("string", "app_id"),
    ],
)

AndroidApplicationExportsRecord = TargetRecordDescriptor(
    "android/application/exports",
    [
        ("string", "app_id"),
        ("string", "app_label"),
        ("string", "app_manifest_name"),
        ("string[]", "permissions"),
        ("string[]", "features"),
        ("string[]", "exported_activities"),
        ("string[]", "exported_receivers"),
        ("string[]", "exported_services"),
        ("string[]", "exported_providers"),
        ("string[]", "intent_actions"),
        ("string[]", "intent_categories"),
        ("path", "source"),
    ],
)


PERMISSION_TAG = ".//uses-permission"
FEATURE_TAG = ".//uses-feature"
APPLICATION_TAG = ".//application"
INTENT_FILTER_TAG = ".//intent-filter"
ANDROID_NAME_ATTRIBUTE = "{http://schemas.android.com/apk/res/android}name"
ANDROID_LABEL_ATTRIBUTE = "{http://schemas.android.com/apk/res/android}name"
ANDROID_EXPORTED_ATTRIBUTE = "{http://schemas.android.com/apk/res/android}exported"

EXPORTABLE_TAGS = {
    "activity": "exported_activities",
    "receiver": "exported_receivers",
    "provider": "exported_providers",
    "service": "exported_services",
}


class AndroidApplicationsPlugin(Plugin):
    """Android applications plugin."""

    def check_compatible(self) -> None:
        if self.target.os != OperatingSystem.ANDROID:
            raise UnsupportedPluginError("Target is not Android")

    @export(
        record=[
            AndroidApplicationRecord,
            AndroidApplicationCertificateRecord,
            AndroidApplicationExportsRecord,
        ]
    )
    def applications(
        self,
    ) -> Iterator[AndroidApplicationRecord | AndroidApplicationCertificateRecord | AndroidApplicationExportsRecord]:
        """Yield installed Android apps."""
        for package_file in self.target.fs.path("/").glob("*/system/packages.xml"):
            try:
                root = read_android_xml(package_file.open("rb"))
            except Exception as e:
                self.target.log.warning("Failed to parse %s: %s", package_file, e)
                continue

            for pkg in root.findall(".//package"):
                name = pkg.get("name")
                code_path = pkg.get("codePath")
                version = pkg.get("version")
                installed_time = pkg.get("it")
                updated_time = pkg.get("ut")

                if installed_time is not None:
                    seconds = int(installed_time, 16) // 1000
                    installed_time = datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()

                if updated_time is not None:
                    seconds = int(updated_time, 16) // 1000
                    updated_time = datetime.fromtimestamp(seconds, tz=timezone.utc).isoformat()

                app_type = "app"
                if code_path:
                    if "apex/" in code_path:
                        app_type += ", apex"
                    if "/priv-app/" in code_path:
                        app_type += ", priv-app"

                yield AndroidApplicationRecord(
                    ts_installed=installed_time,
                    ts_modified=updated_time,
                    name=name,
                    app_id=name,
                    version=version,
                    author=None,
                    type=app_type,
                    path=code_path,
                    source=package_file,
                    _target=self.target,
                )

                if (apk_path := self.target.fs.path(code_path)).is_file():
                    try:
                        yield from self.read_apk(name, apk_path)
                    except Exception as e:
                        self.target.log.warning("Failed to read APK %s: %s", apk_path, e)
                        continue

    def read_apk(self, app_id: str | None, path: Path) -> Iterator[AndroidApplicationCertificateRecord]:
        """Read an APK file and return metadata from the manifest and certificate."""
        permissions = []
        features = []
        exports = {
            "exported_activities": [],
            "exported_receivers": [],
            "exported_services": [],
            "exported_providers": [],
        }
        intent_actions = []
        intent_categories = []
        app_manifest_name = None
        app_label = None

        # Sometimes, an apk referenced in packages.xml is a directory, containing the actual apk.
        if path.is_dir():
            apks = list(path.glob("*.apk"))
            if len(apks) == 1:
                path = apks[0]
            else:
                return None

        fs = ZipFilesystem(path.open())
        et = read_android_xml(fs.get("AndroidManifest.xml").open())

        permissions = [
            pe.get(ANDROID_NAME_ATTRIBUTE)
            for pe in et.findall(PERMISSION_TAG)
            if pe.get(ANDROID_NAME_ATTRIBUTE) is not None
        ]

        features = [
            pe.get(ANDROID_NAME_ATTRIBUTE)
            for pe in et.findall(FEATURE_TAG)
            if pe.get(ANDROID_NAME_ATTRIBUTE) is not None
        ]

        application = et.find(APPLICATION_TAG)
        app_manifest_name = application.get(ANDROID_NAME_ATTRIBUTE)
        app_label = application.get(ANDROID_LABEL_ATTRIBUTE)

        for tag, result_key in EXPORTABLE_TAGS.items():
            for item in application.findall(".//" + tag):
                should_export = item.get(ANDROID_EXPORTED_ATTRIBUTE) != "false"
                actions = [action.get(ANDROID_NAME_ATTRIBUTE) for action in item.findall(".//action")]
                categories = [category.get(ANDROID_NAME_ATTRIBUTE) for category in item.findall(".//category")]
                if "android.intent.action.MAIN" in actions or "android.intent.category.LAUNCHER" in categories:
                    should_export = True
                if should_export:
                    exports[result_key].append(item.get(ANDROID_NAME_ATTRIBUTE))
                    intent_actions.extend(actions)
                    intent_categories.extend(categories)

        for cert in fs.path("/").glob("META-INF/*.RSA"):
            yield from parse_pkcs7_der(app_id, cert)

        yield AndroidApplicationExportsRecord(
            app_id=app_id,
            app_label=app_label,
            app_manifest_name=app_manifest_name,
            permissions=permissions,
            features=features,
            intent_actions=intent_actions,
            intent_categories=intent_categories,
            **exports,
            source=path,
            _target=self.target,
        )


def parse_pkcs7_der(app_id: str | None, path: Path) -> Iterator[AndroidApplicationCertificateRecord]:
    """Reads the Java CERT.RSA file, a pkcs7-encoded signing structure."""
    with path.open() as fh:
        der_data = fh.read()

    for cert in cms.ContentInfo.load(der_data)["content"]["certificates"]:
        cert = parse_x509(pem.armor("CERTIFICATE", cert.chosen.dump()))
        yield AndroidApplicationCertificateRecord(app_id=app_id, **cert._asdict())
