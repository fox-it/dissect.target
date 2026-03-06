from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.database.bsd import DB
from dissect.database.sqlite3 import SQLite3
from flow.record.fieldtypes import digest

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import arg, export
from dissect.target.plugins.os.unix.linux.redhat.rpm.c_rpm import c_rpm
from dissect.target.plugins.os.unix.linux.redhat.rpm.ndb import NDB
from dissect.target.plugins.os.unix.linux.redhat.rpm.rpm import parse_blob
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
            blobs: set[bytes] = set()

            # SQLite3 format
            if path.suffix == ".sqlite":
                db = SQLite3(path)
                blobs.update(row.blob for row in db.table("Packages").rows())

            # Native DB (NDB) format
            elif path.suffix == ".db":
                db = NDB(path.open("rb"))
                blobs.update(db.records())

            # Berkley DB format
            else:
                db = DB(path.open("rb"))
                blobs.update(blob for i, (_, blob) in enumerate(db.records()) if i > 0)

            for blob in blobs:
                package = parse_blob(blob)
                full_name = get_full_name(package)
                files = get_files(package)
                file_sizes = get_file_sizes(package)
                digests = get_file_digests(package)
                package_digest = get_package_digest(package)

                yield PackageManagerPackageRecord(
                    ts=package.get("installtime"),
                    package_manager="rpm",
                    package_name=package.get("name"),
                    package_name_full=full_name,
                    package_version=package.get("version"),
                    package_release=package.get("release"),
                    package_arch=package.get("arch"),
                    package_vendor=package.get("vendor"),
                    package_summary=package.get("summary"),
                    package_size=package.get("size"),
                    package_archive=package.get("sourcerpm"),
                    digest=package_digest,
                    package_files=files,
                    package_files_digests=digests,
                    source=path,
                    _target=self.target,
                )

                if output_files:
                    digest_algo = c_rpm.HashAlgo(package.get("filedigestalgo", 1))
                    digest_algo_name = digest_algo.name.lower()

                    for i, file in enumerate(files):
                        stored_digest = None
                        actual_digest = None
                        digest_match = None

                        file_path = self.target.fs.path(file)
                        if hexdigest := package.get("filedigests", [])[i]:
                            stored_digest = digest()
                            setattr(stored_digest, digest_algo_name, hexdigest)

                        if file_path.is_file():
                            actual_digest = digest()
                            hexdigest = file_path.get().hash([digest_algo_name])[0]
                            setattr(actual_digest, digest_algo_name, hexdigest)

                            if stored_digest:
                                digest_match = getattr(actual_digest, digest_algo_name) == getattr(
                                    stored_digest, digest_algo_name
                                )
                            else:
                                digest_match = False

                        yield PackageManagerPackageFileRecord(
                            ts=package.get("installtime"),
                            package_manager="rpm",
                            package_name=package.get("name"),
                            package_name_full=full_name,
                            path=file_path,
                            exists=file_path.exists(),
                            stored_size=file_sizes[i],
                            stored_digest=stored_digest,
                            actual_size=file_path.lstat().st_size if file_path.is_file() else None,
                            actual_digest=actual_digest,
                            digest_match=digest_match,
                            source=path,
                            _target=self.target,
                        )


def get_full_name(package: dict) -> str:
    """Reconstruct the full name of the RPM package."""

    full_name = "-".join([package.get(name, "") for name in ("name", "version", "release")])
    if arch := package.get("arch"):
        full_name += f".{arch}"
    return full_name


def get_files(package: dict) -> list[str]:
    """Reconstruct the full file paths for all files contained in the package."""

    dirnames = package.get("dirnames", [])
    basenames = package.get("basenames", [])
    dirindexes = package.get("dirindexes", [])

    if not isinstance(dirindexes, list) and len(dirnames) == 1:
        dirindexes = [0]

    return [f"{dirnames[dirindexes[i]]}{file}" for i, file in enumerate(basenames)]


def get_file_sizes(package: dict) -> list[int]:
    """Get file sizes of files in the package."""

    file_sizes = package.get("filesizes", [])
    if not isinstance(file_sizes, list):
        file_sizes = [file_sizes]

    return file_sizes


def get_file_digests(package: dict) -> list[digest]:
    """Group digests of the files in the package together.

    Digest by default are sha256 (8). For backwards compatibility if no int is set md5 should be selected.

    References:
        - docs/manual/tags.md
    """

    digests = []
    digest_algo = c_rpm.HashAlgo(package.get("filedigestalgo", 1))

    for hexdigest in package.get("filedigests", []):
        if not hexdigest:
            continue
        d = digest()
        setattr(d, digest_algo.name.lower(), hexdigest)
        digests.append(d)

    return digests


def get_package_digest(package: dict) -> digest:
    """Group the digests of the packed package."""

    package_digest = digest()
    for hexdigest, algo_num in zip(
        package.get("packagedigests", []), package.get("packagedigestalgos", []), strict=True
    ):
        setattr(package_digest, c_rpm.HashAlgo(algo_num).name.lower(), hexdigest)

    return package_digest
