from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING

from dissect.target.plugins.os.unix.linux.debian.dpkg import DpkgPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_packages(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we can parse Debian dpkg status files."""

    fs_unix.map_file("/var/lib/dpkg/status", absolute_path("_data/plugins/os/unix/linux/debian/dpkg/dpkg-status"))

    target_unix.add_plugin(DpkgPlugin)
    records = list(target_unix.dpkg.packages())

    assert len(records) == 9
    assert [r.package_name for r in records] == [
        "accountsservice",
        "acl",
        "acpi-support",
        "acpid",
        "adduser",
        "zip",
        "zlib1g",
        "zlib1g-dev",
        "zstd",
    ]

    assert records[0].package_manager == "dpkg"
    assert records[0].package_name == "accountsservice"
    assert records[0].package_name_full == "accountsservice-0.6.55-0ubuntu12~20.04.5.amd64"
    assert records[0].package_version == "0.6.55-0ubuntu12~20.04.5"
    assert records[0].package_release == "0ubuntu12~20.04.5"
    assert records[0].package_arch == "amd64"
    assert records[0].package_vendor == "Ubuntu Developers <ubuntu-devel-discuss@lists.ubuntu.com>"
    assert records[0].package_summary == "query and manipulate user account information"
    assert records[0].package_files == []
    assert records[0].package_files_digests == []
    assert records[0].source == "/var/lib/dpkg/status"


def test_packages_file_output(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we can parse Debian dpkg list and md5sums files."""

    fs_unix.map_file("/var/lib/dpkg/status", absolute_path("_data/plugins/os/unix/linux/debian/dpkg/dpkg-status"))
    fs_unix.map_file("/var/lib/dpkg/info/zstd.list", absolute_path("_data/plugins/os/unix/linux/debian/dpkg/zstd.list"))
    fs_unix.map_file(
        "/var/lib/dpkg/info/zstd.md5sums", absolute_path("_data/plugins/os/unix/linux/debian/dpkg/zstd.md5sums")
    )
    fs_unix.map_file_fh("/usr/bin/zstd", BytesIO(b"this-aint-zstd"))

    target_unix.add_plugin(DpkgPlugin)
    records = list(target_unix.dpkg.packages(output_files=True))
    assert len(records) == 38

    package = next(r for r in records if r.package_name == "zstd")
    assert package.package_files == [
        "/usr/bin/pzstd",
        "/usr/bin/zstd",
        "/usr/bin/zstdgrep",
        "/usr/bin/zstdless",
        "/usr/share/doc/zstd/CODE_OF_CONDUCT.md",
        "/usr/share/doc/zstd/CONTRIBUTING.md.gz",
        "/usr/share/doc/zstd/README.md.gz",
        "/usr/share/doc/zstd/SECURITY.md",
        "/usr/share/doc/zstd/TESTING.md",
        "/usr/share/doc/zstd/changelog.Debian.gz",
        "/usr/share/doc/zstd/changelog.gz",
        "/usr/share/doc/zstd/copyright",
        "/usr/share/man/man1/pzstd.1.gz",
        "/usr/share/man/man1/unzstd.1.gz",
        "/usr/share/man/man1/zstd.1.gz",
        "/usr/share/man/man1/zstdcat.1.gz",
        "/usr/share/man/man1/zstdgrep.1.gz",
        "/usr/share/man/man1/zstdless.1.gz",
        "/usr/share/man/man1/zstdmt.1.gz",
        "/usr",
        "/usr/bin",
        "/usr/share",
        "/usr/share/doc",
        "/usr/share/doc/zstd",
        "/usr/share/man",
        "/usr/share/man/man1",
        "/usr/bin/unzstd",
        "/usr/bin/zstdcat",
        "/usr/bin/zstdmt",
    ]

    assert [d.md5 for d in package.package_files_digests] == [
        "18b1987989ce0b8cf894baf14378b15b",
        "992a3ab4ea6043b1e6fa7cef4b0e6cf6",
        "4e16657238c1d51e2067380425cea68c",
        "f96f2accbe640e420a7cfd312d411732",
        "92ec4f1796f26fd2f2cde346e6f59a4f",
        "6b4f092884a64d3984d8c906540ee508",
        "7dd2b34350cf1831ca378d736e449109",
        "8e2cf92470ce744fe05fa1c2c26297a6",
        "ff7ee524ccedddcb6e2ac9a128d8b101",
        "6c32a4d3eaba388aa58e5d269cd90fed",
        "01c9b6177a7b83b1ea5d63e72d0479cb",
        "d0cee8d965d48151ca3ad4c4777435f8",
        "8d8a31fd20601d6944e1e0919d693161",
        "3c83c4fb52801ad218a872baee10c294",
        "3c83c4fb52801ad218a872baee10c294",
        "3c83c4fb52801ad218a872baee10c294",
        "351665948d32a6ba0a3818314b0373b6",
        "b8ac251a295c8af39cfe8e793fae10de",
        "3c83c4fb52801ad218a872baee10c294",
    ]

    files = sorted([r for r in records if hasattr(r, "digest_match")], key=lambda r: r.path)
    assert len(files) == 29  # this includes directories

    assert files[4].path == "/usr/bin/zstd"
    assert files[4].exists == True  # noqa: E712
    assert files[4].stored_digest.md5 == "992a3ab4ea6043b1e6fa7cef4b0e6cf6"
    assert files[4].actual_digest.md5 == "fcb6ef82ae18cabe556f59137c456c80"
    assert files[4].digest_match == False  # noqa: E712
    assert files[4].source == "/var/lib/dpkg/info/zstd.list"


def test_logs(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we can parse Debian dpkg log files."""

    log_file = absolute_path("_data/plugins/os/unix/linux/debian/dpkg/dpkg.log")
    fs_unix.map_file("/var/log/dpkg.log", log_file)

    target_unix.add_plugin(DpkgPlugin)

    results = list(target_unix.dpkg.logs())
    assert len(results) == 362
    assert all(r.package_name for r in results)

    # No remove operations are present in this test set.
    assert all(r.package_version for r in results)
    assert {r.operation for r in results} == {"install", "upgrade", "status"}

    assert results[0].ts
    assert results[0].package_manager == "dpkg"
    assert results[0].operation == "upgrade"
    assert results[0].package_name == "python3.8-dev"
    assert results[0].package_version == "3.8.10-0ubuntu1~20.04.2"
    assert results[0].message == "upgrade python3.8-dev:amd64 3.8.10-0ubuntu1~20.04.1 3.8.10-0ubuntu1~20.04.2"
    assert results[0].source == "/var/log/dpkg.log"


def test_logs_compressed(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we can parse Debian dpkg compressed log files."""

    log_file_gz = absolute_path("_data/plugins/os/unix/linux/debian/dpkg/dpkg.log.2.gz")
    fs_unix.map_file("/var/log/dpkg.log.2.gz", log_file_gz)

    target_unix.add_plugin(DpkgPlugin)

    results = list(target_unix.dpkg.logs())
    assert len(results) == 97
    assert all(r.package_name for r in results)

    # Remove operations are present in this test set.
    seen_versions = {r.package_version for r in results}
    assert None in seen_versions
    assert len(seen_versions) > 1

    assert {r.operation for r in results} == {"trigproc", "upgrade", "status", "remove"}
