from __future__ import annotations

from typing import TYPE_CHECKING

from flow.record.fieldtypes import digest

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import arg, export
from dissect.target.plugins.os.unix.linux.redhat.rpm.rpm import Packages
from dissect.target.plugins.os.unix.packagemanager import (
    PackageManagerPackageFileRecord,
    PackageManagerPackageRecord,
    PackageManagerPlugin,
)

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from dissect.target.target import Target


class RpmPlugin(PackageManagerPlugin):
    """Red Hat Package Manager (RPM).

    References:
        - https://rpm.org
        - https://github.com/rpm-software-management/rpm
        - https://man7.org/linux/man-pages/man8/rpmdb.8.html
    """

    __namespace__ = "rpm"

    SYSTEM_PATHS = (
        "/var/lib/rpm",
        "/usr/lib/sysimage/rpm",
    )

    def __init__(self, target: Target):
        super().__init__(target)
        self.databases = set(self.find_databases())

    def find_databases(self) -> Iterator[Path]:
        seen = set()
        for base_str in self.SYSTEM_PATHS:
            if (dir := self.target.fs.path(base_str)).is_dir():
                for file in ("rpmdb.sqlite", "Packages", "Packages.db"):
                    if (db := dir.joinpath(file).resolve()).is_file() and db not in seen:
                        seen.add(db)
                        yield db

    def check_compatible(self) -> None:
        if not self.databases:
            raise UnsupportedPluginError("No RPM database file(s) found on target")

    @export(record=PackageManagerPackageRecord)
    @arg("--output-files", action="store_true", help="output package file content records")
    def packages(self, output_files: bool = False) -> Iterator[PackageManagerPackageRecord]:
        """Yield currently installed RPM packages from SQLite3, BerkleyDB or NDB (Native DB) databases."""
        for path in self.databases:
            try:
                packages = Packages(path)
            except Exception as e:
                self.target.log.warning("Unable to parse RPM Packages database %s: %s", path, e)
                continue

            for package in packages:
                yield PackageManagerPackageRecord(
                    ts=package.install_time,
                    package_manager="rpm",
                    package_name=package.name,
                    package_name_full=package.full_name,
                    package_version=package.version,
                    package_release=package.release,
                    package_arch=package.arch,
                    package_vendor=package.vendor,
                    package_summary=package.summary,
                    package_size=package.size,
                    package_archive=package.source,
                    digest=package.digest,
                    package_files=package.entry_paths,
                    package_files_digests=package.entry_digests,
                    source=path,
                    _target=self.target,
                )

                if output_files:
                    digest_algo = package.entry_digest_algo.name.lower()

                    for entry in package.entries():
                        actual_digest = None
                        digest_match = None

                        actual_size = None
                        size_match = None

                        file_path = self.target.fs.path(entry.path)
                        stored_digest = entry.digest
                        stored_size = entry.size

                        if file_path.is_file():
                            actual_digest = digest()
                            hexdigest = file_path.get().hash([digest_algo])[0]
                            setattr(actual_digest, digest_algo, hexdigest)

                            if stored_digest:
                                digest_match = getattr(actual_digest, digest_algo) == getattr(
                                    stored_digest, digest_algo
                                )

                            if entry.is_file():
                                size_match = stored_size == file_path.lstat().st_size

                        yield PackageManagerPackageFileRecord(
                            ts=package.install_time,
                            package_manager="rpm",
                            package_name=package.name,
                            package_name_full=package.full_name,
                            path=file_path,
                            exists=file_path.exists(),
                            stored_size=stored_size,
                            stored_digest=stored_digest,
                            actual_size=actual_size,
                            actual_digest=actual_digest,
                            digest_match=digest_match,
                            size_match=size_match,
                            source=path,
                            _target=self.target,
                        )
