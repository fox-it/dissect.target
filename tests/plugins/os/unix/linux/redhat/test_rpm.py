from __future__ import annotations

import json
from datetime import datetime, timezone
from io import BytesIO
from typing import TYPE_CHECKING

import pytest

from dissect.target.plugins.os.unix.linux.redhat.rpm._plugin import RpmPlugin
from dissect.target.plugins.os.unix.linux.redhat.rpm.rpm import parse_blob
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


def test_packages_sqlite(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we can find and parse RPM SQLite3 database files.

    Test file originates from an unmodified Fedora docker image (docker.io/library/fedora:latest).
    """

    fs_unix.map_dir("/usr/lib/sysimage/rpm", absolute_path("_data/plugins/os/unix/linux/redhat/rpm/sqlite"))
    fs_unix.symlink("/usr/lib/sysimage/rpm", "/var/lib/rpm")
    target_unix.add_plugin(RpmPlugin)
    records = sorted(target_unix.rpm.packages(), key=lambda r: r.package_name_full)

    assert len(records) == 142

    # output compared using ``rpm -qa``
    assert [r.package_name_full for r in records] == sorted(
        [
            "libgcc-15.2.1-7.fc43.x86_64",
            "publicsuffix-list-dafsa-20260116-1.fc43.noarch",
            "libssh-config-0.11.3-1.fc43.noarch",
            "fedora-release-identity-container-43-26.noarch",
            "fedora-gpg-keys-43-1.noarch",
            "fedora-repos-43-1.noarch",
            "fedora-release-common-43-26.noarch",
            "fedora-release-container-43-26.noarch",
            "setup-2.15.0-26.fc43.noarch",
            "filesystem-3.18-50.fc43.x86_64",
            "pcre2-syntax-10.47-1.fc43.noarch",
            "gnulib-l10n-20241231-1.fc43.noarch",
            "coreutils-common-9.7-7.fc43.x86_64",
            "ncurses-base-6.5-7.20250614.fc43.noarch",
            "bash-5.3.0-2.fc43.x86_64",
            "glibc-common-2.42-9.fc43.x86_64",
            "glibc-2.42-9.fc43.x86_64",
            "ncurses-libs-6.5-7.20250614.fc43.x86_64",
            "glibc-minimal-langpack-2.42-9.fc43.x86_64",
            "zlib-ng-compat-2.3.2-2.fc43.x86_64",
            "libstdc++-15.2.1-7.fc43.x86_64",
            "libgpg-error-1.55-2.fc43.x86_64",
            "bzip2-libs-1.0.8-21.fc43.x86_64",
            "xz-libs-5.8.1-4.fc43.x86_64",
            "libassuan-2.5.7-4.fc43.x86_64",
            "libgcrypt-1.11.1-3.fc43.x86_64",
            "libzstd-1.5.7-2.fc43.x86_64",
            "gmp-6.3.0-4.fc43.x86_64",
            "popt-1.19-9.fc43.x86_64",
            "libxcrypt-4.5.2-1.fc43.x86_64",
            "npth-1.8-3.fc43.x86_64",
            "libxml2-2.12.10-5.fc43.x86_64",
            "fmt-11.2.0-3.fc43.x86_64",
            "readline-8.3-2.fc43.x86_64",
            "json-c-0.18-7.fc43.x86_64",
            "sqlite-libs-3.50.2-2.fc43.x86_64",
            "libuuid-2.41.3-7.fc43.x86_64",
            "gnupg2-gpgconf-2.4.9-5.fc43.x86_64",
            "libeconf-0.7.9-2.fc43.x86_64",
            "gdbm-libs-1.23-10.fc43.x86_64",
            "pcre2-10.47-1.fc43.x86_64",
            "libtasn1-4.20.0-2.fc43.x86_64",
            "libunistring-1.1-10.fc43.x86_64",
            "libidn2-2.3.8-2.fc43.x86_64",
            "libffi-3.5.2-1.fc43.x86_64",
            "p11-kit-0.25.8-1.fc43.x86_64",
            "crypto-policies-20251125-1.git63291f8.fc43.noarch",
            "grep-3.12-2.fc43.x86_64",
            "libblkid-2.41.3-7.fc43.x86_64",
            "elfutils-libelf-0.194-1.fc43.x86_64",
            "libksba-1.6.7-4.fc43.x86_64",
            "lz4-libs-1.10.0-3.fc43.x86_64",
            "libattr-2.5.2-6.fc43.x86_64",
            "libacl-2.3.2-4.fc43.x86_64",
            "libsepol-3.9-2.fc43.x86_64",
            "libselinux-3.9-5.fc43.x86_64",
            "libmount-2.41.3-7.fc43.x86_64",
            "sed-4.9-5.fc43.x86_64",
            "libsmartcols-2.41.3-7.fc43.x86_64",
            "lua-libs-5.4.8-4.fc43.x86_64",
            "libcom_err-1.47.3-2.fc43.x86_64",
            "findutils-4.10.0-6.fc43.x86_64",
            "gnupg2-keyboxd-2.4.9-5.fc43.x86_64",
            "libpsl-0.21.5-6.fc43.x86_64",
            "cyrus-sasl-lib-2.1.28-33.fc43.x86_64",
            "gdbm-1.23-10.fc43.x86_64",
            "gnupg2-verify-2.4.9-5.fc43.x86_64",
            "mpfr-4.2.2-2.fc43.x86_64",
            "nettle-3.10.1-2.fc43.x86_64",
            "file-libs-5.46-8.fc43.x86_64",
            "libyaml-0.2.5-17.fc43.x86_64",
            "libgomp-15.2.1-7.fc43.x86_64",
            "keyutils-libs-1.6.3-6.fc43.x86_64",
            "libverto-0.3.2-11.fc43.x86_64",
            "libcap-ng-0.9-7.fc43.x86_64",
            "audit-libs-4.1.3-1.fc43.x86_64",
            "pam-libs-1.7.1-4.fc43.x86_64",
            "libcap-2.76-3.fc43.x86_64",
            "systemd-libs-258.3-3.fc43.x86_64",
            "sdbus-cpp-2.1.0-3.fc43.x86_64",
            "libusb1-1.0.29-4.fc43.x86_64",
            "systemd-standalone-sysusers-258.3-3.fc43.x86_64",
            "libsemanage-3.9-4.fc43.x86_64",
            "libtool-ltdl-2.5.4-8.fc43.x86_64",
            "alternatives-1.33-3.fc43.x86_64",
            "p11-kit-trust-0.25.8-1.fc43.x86_64",
            "gnutls-3.8.11-5.fc43.x86_64",
            "glib2-2.86.3-1.fc43.x86_64",
            "openssl-libs-3.5.4-2.fc43.x86_64",
            "coreutils-9.7-7.fc43.x86_64",
            "ca-certificates-2025.2.80_v9.0.304-1.1.fc43.noarch",
            "krb5-libs-1.21.3-7.fc43.x86_64",
            "libtirpc-1.3.7-1.fc43.x86_64",
            "zchunk-libs-1.5.1-3.fc43.x86_64",
            "tpm2-tss-4.1.3-8.fc43.x86_64",
            "ima-evm-utils-libs-1.6.2-6.fc43.x86_64",
            "gnupg2-gpg-agent-2.4.9-5.fc43.x86_64",
            "libnsl2-2.0.1-4.fc43.x86_64",
            "libssh-0.11.3-1.fc43.x86_64",
            "gzip-1.13-4.fc43.x86_64",
            "cracklib-2.9.11-8.fc43.x86_64",
            "libpwquality-1.4.5-14.fc43.x86_64",
            "pam-1.7.1-4.fc43.x86_64",
            "authselect-libs-1.6.2-1.fc43.x86_64",
            "libevent-2.1.12-16.fc43.x86_64",
            "openldap-2.6.10-4.fc43.x86_64",
            "gnupg2-dirmngr-2.4.9-5.fc43.x86_64",
            "gnupg2-2.4.9-5.fc43.x86_64",
            "libfsverity-1.6-3.fc43.x86_64",
            "rpm-sequoia-1.10.0-1.fc43.x86_64",
            "rpm-libs-6.0.1-1.fc43.x86_64",
            "libmodulemd-2.15.2-4.fc43.x86_64",
            "rpm-sign-libs-6.0.1-1.fc43.x86_64",
            "libsolv-0.7.35-3.fc43.x86_64",
            "libarchive-3.8.4-1.fc43.x86_64",
            "libnghttp2-1.66.0-2.fc43.x86_64",
            "libbrotli-1.2.0-1.fc43.x86_64",
            "libcurl-8.15.0-5.fc43.x86_64",
            "librepo-1.20.0-4.fc43.x86_64",
            "libdnf5-5.2.18.0-1.fc43.x86_64",
            "libdnf5-cli-5.2.18.0-1.fc43.x86_64",
            "dnf5-5.2.18.0-1.fc43.x86_64",
            "curl-8.15.0-5.fc43.x86_64",
            "elfutils-default-yama-scope-0.194-1.fc43.noarch",
            "elfutils-libs-0.194-1.fc43.x86_64",
            "rpm-build-libs-6.0.1-1.fc43.x86_64",
            "vim-data-9.1.2128-2.fc43.noarch",
            "vim-minimal-9.1.2128-2.fc43.x86_64",
            "dnf5-plugins-5.2.18.0-1.fc43.x86_64",
            "rpm-6.0.1-1.fc43.x86_64",
            "sudo-1.9.17-6.p2.fc43.x86_64",
            "authselect-1.6.2-1.fc43.x86_64",
            "shadow-utils-4.18.0-3.fc43.x86_64",
            "util-linux-core-2.41.3-7.fc43.x86_64",
            "gawk-5.3.2-2.fc43.x86_64",
            "tar-1.35-6.fc43.x86_64",
            "zstd-1.5.7-2.fc43.x86_64",
            "xz-5.8.1-4.fc43.x86_64",
            "bzip2-1.0.8-21.fc43.x86_64",
            "tzdata-2025c-1.fc43.noarch",
            "rootfiles-9.0-4.fc43.noarch",
            "gpg-pubkey-c6e7f081cf80e13146676e88829b606631645531-66b6dccf",
        ]
    )

    assert records[0].ts == datetime(2026, 2, 9, 6, 48, 5, tzinfo=timezone.utc)
    assert records[0].package_manager == "rpm"
    assert records[0].package_name == "alternatives"
    assert records[0].package_name_full == "alternatives-1.33-3.fc43.x86_64"
    assert records[0].package_version == "1.33"
    assert records[0].package_release == "3.fc43"
    assert records[0].package_arch == "x86_64"
    assert records[0].package_vendor == "Fedora Project"
    assert records[0].package_summary == "A tool to maintain symbolic links determining default commands"
    assert records[0].package_size == 63712
    assert records[0].package_archive == "chkconfig-1.33-3.fc43.src.rpm"
    assert records[0].digest.sha256 == "cef71f413b915453384711db020d657edcbc0b37187f577fb4e24e27532a3436"
    assert records[0].package_files == [
        "/etc/alternatives",
        "/etc/alternatives.admindir",
        "/usr/bin/alternatives",
        "/usr/bin/update-alternatives",
        "/usr/lib/.build-id",
        "/usr/lib/.build-id/6c",
        "/usr/lib/.build-id/6c/3b697ccb05f8aced0137e66d880c019c03df72",
        "/usr/share/licenses/alternatives",
        "/usr/share/licenses/alternatives/COPYING",
        "/usr/share/man/man8/alternatives.8.gz",
        "/usr/share/man/man8/update-alternatives.8.gz",
        "/var/lib/alternatives",
    ]
    assert (
        records[0].package_files_digests[0].sha256 == "bb95ff7cacfb4b31d5e1eb38fd50280f0c659f3e9a68c84d0fbc61ddf4c8b00c"
    )
    assert (
        records[0].package_files_digests[1].sha256 == "8177f97513213526df2cf6184d8ff986c675afb514d4e68a404010521b880643"
    )
    assert (
        records[0].package_files_digests[2].sha256 == "486f5011e513cfe9f2aa0fc837f38927c8c2af7b1a54e0d919d43645e552d829"
    )
    assert records[0].source == "/usr/lib/sysimage/rpm/rpmdb.sqlite"


def test_packages_bsddb(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we can find and parse RPM BSD DB database files.

    Test file originates from an unmodified Rocky Linux docker image (docker.io/rockylinux/rockylinux:8).
    """

    fs_unix.map_dir("/usr/lib/sysimage/rpm", absolute_path("_data/plugins/os/unix/linux/redhat/rpm/bsddb"))
    fs_unix.symlink("/usr/lib/sysimage/rpm", "/var/lib/rpm")
    target_unix.add_plugin(RpmPlugin)
    records = list(target_unix.rpm.packages())

    assert len(records) == 148

    # output compared using ``rpm -qa``
    assert sorted([r.package_name_full for r in records]) == sorted(
        [
            "crypto-policies-20230731-1.git3177e06.el8.noarch",
            "python3-pip-wheel-9.0.3-23.el8.rocky.0.noarch",
            "rocky-gpg-keys-8.9-1.6.el8.noarch",
            "rocky-repos-8.9-1.6.el8.noarch",
            "filesystem-3.8-6.el8.x86_64",
            "ncurses-base-6.1-10.20180224.el8.noarch",
            "libselinux-2.9-8.el8.x86_64",
            "glibc-minimal-langpack-2.28-236.el8_9.7.x86_64",
            "glibc-2.28-236.el8_9.7.x86_64",
            "libsepol-2.9-3.el8.x86_64",
            "xz-libs-5.2.4-4.el8_6.x86_64",
            "libgpg-error-1.31-1.el8.x86_64",
            "libcap-2.48-5.el8_8.x86_64",
            "libzstd-1.4.4-1.el8.x86_64",
            "libxcrypt-4.1.1-6.el8.x86_64",
            "libuuid-2.32.1-43.el8.x86_64",
            "chkconfig-1.19.2-1.el8.x86_64",
            "expat-2.2.5-11.el8.x86_64",
            "json-c-0.13.1-3.el8.x86_64",
            "libacl-2.2.53-1.el8.1.x86_64",
            "libblkid-2.32.1-43.el8.x86_64",
            "sed-4.5-5.el8.x86_64",
            "libsmartcols-2.32.1-43.el8.x86_64",
            "lua-libs-5.3.4-12.el8.x86_64",
            "file-libs-5.33-25.el8.x86_64",
            "audit-libs-3.0.7-5.el8.x86_64",
            "p11-kit-0.23.22-1.el8.x86_64",
            "libunistring-0.9.9-3.el8.x86_64",
            "libassuan-2.5.1-3.el8.x86_64",
            "keyutils-libs-1.5.10-9.el8.x86_64",
            "p11-kit-trust-0.23.22-1.el8.x86_64",
            "grep-3.1-6.el8.x86_64",
            "dbus-libs-1.12.8-26.el8.x86_64",
            "libusbx-1.0.23-4.el8.x86_64",
            "openssl-libs-1.1.1k-9.el8_7.x86_64",
            "libdb-utils-5.3.28-42.el8_4.x86_64",
            "libarchive-3.3.3-5.el8.x86_64",
            "libsemanage-2.9-9.el8_6.x86_64",
            "libutempter-1.1.6-14.el8.x86_64",
            "ima-evm-utils-1.3.2-12.el8.x86_64",
            "gzip-1.9-13.el8_5.x86_64",
            "cracklib-dicts-2.9.6-15.el8.x86_64",
            "mpfr-3.1.6-1.el8.x86_64",
            "gnutls-3.6.16-7.el8.x86_64",
            "libcomps-0.1.18-1.el8.x86_64",
            "libnghttp2-1.33.0-5.el8_8.x86_64",
            "libsigsegv-2.11-5.el8.x86_64",
            "libverto-0.3.2-2.el8.x86_64",
            "libtirpc-1.1.4-8.el8.x86_64",
            "platform-python-setuptools-39.2.0-7.el8.noarch",
            "python3-libs-3.6.8-56.el8_9.rocky.0.x86_64",
            "pam-1.3.1-27.el8.x86_64",
            "libcurl-minimal-7.61.1-33.el8.x86_64",
            "rpm-4.14.3-26.el8.x86_64",
            "libsolv-0.7.20-6.el8.x86_64",
            "device-mapper-libs-1.02.181-13.el8_9.x86_64",
            "elfutils-default-yama-scope-0.189-3.el8.noarch",
            "dbus-common-1.12.8-26.el8.noarch",
            "systemd-pam-239-78.el8.x86_64",
            "dbus-1.12.8-26.el8.x86_64",
            "cyrus-sasl-lib-2.1.27-6.el8_5.x86_64",
            "libyaml-0.1.7-5.el8.x86_64",
            "npth-1.5-4.el8.x86_64",
            "gpgme-1.13.1-11.el8.x86_64",
            "libdnf-0.63.0-17.el8_9.x86_64",
            "python3-hawkey-0.63.0-17.el8_9.x86_64",
            "rpm-build-libs-4.14.3-26.el8.x86_64",
            "libreport-filesystem-2.9.5-15.el8.rocky.6.3.x86_64",
            "python3-dnf-4.7.0-19.el8.noarch",
            "yum-4.7.0-19.el8.noarch",
            "binutils-2.30-123.el8.x86_64",
            "vim-minimal-8.0.1763-19.el8_6.4.x86_64",
            "less-530-1.el8.x86_64",
            "rootfiles-8.1-22.el8.noarch",
            "libgcc-8.5.0-20.el8.x86_64",
            "python3-setuptools-wheel-39.2.0-7.el8.noarch",
            "tzdata-2023c-2.el8.noarch",
            "rocky-release-8.9-1.6.el8.noarch",
            "setup-2.12.2-9.el8.noarch",
            "basesystem-11-5.el8.noarch",
            "pcre2-10.32-3.el8_6.x86_64",
            "ncurses-libs-6.1-10.20180224.el8.x86_64",
            "glibc-common-2.28-236.el8_9.7.x86_64",
            "bash-4.4.20-4.el8_6.x86_64",
            "zlib-1.2.11-25.el8.x86_64",
            "bzip2-libs-1.0.6-26.el8.x86_64",
            "sqlite-libs-3.26.0-18.el8_8.x86_64",
            "info-6.5-7.el8.x86_64",
            "elfutils-libelf-0.189-3.el8.x86_64",
            "libxml2-2.9.7-16.el8_8.1.x86_64",
            "popt-1.18-1.el8.x86_64",
            "readline-7.0-10.el8.x86_64",
            "gmp-6.1.2-10.el8.x86_64",
            "libattr-2.4.48-3.el8.x86_64",
            "coreutils-single-8.30-15.el8.x86_64",
            "libmount-2.32.1-43.el8.x86_64",
            "libcom_err-1.45.6-5.el8.x86_64",
            "libstdc++-8.5.0-20.el8.x86_64",
            "libgcrypt-1.8.5-7.el8_6.x86_64",
            "libcap-ng-0.7.11-1.el8.x86_64",
            "libffi-3.1-24.el8.x86_64",
            "lz4-libs-1.8.3-3.el8_4.x86_64",
            "libidn2-2.2.0-1.el8.x86_64",
            "gdbm-libs-1.18-2.el8.x86_64",
            "libtasn1-4.13-4.el8_7.x86_64",
            "pcre-8.42-6.el8.x86_64",
            "systemd-libs-239-78.el8.x86_64",
            "dbus-tools-1.12.8-26.el8.x86_64",
            "ca-certificates-2023.2.60_v7.0.306-80.0.el8_8.noarch",
            "libdb-5.3.28-42.el8_4.x86_64",
            "kmod-libs-25-19.el8.x86_64",
            "gdbm-1.18-2.el8.x86_64",
            "shadow-utils-4.6-19.el8.x86_64",
            "tpm2-tss-2.3.2-5.el8.x86_64",
            "libfdisk-2.32.1-43.el8.x86_64",
            "cracklib-2.9.6-15.el8.x86_64",
            "acl-2.2.53-1.el8.1.x86_64",
            "nettle-3.4.1-7.el8.x86_64",
            "glib2-2.56.4-161.el8.x86_64",
            "libksba-1.3.5-9.el8_7.x86_64",
            "libseccomp-2.5.2-1.el8.x86_64",
            "gawk-4.2.1-4.el8.x86_64",
            "krb5-libs-1.18.2-26.el8.x86_64",
            "libnsl2-1.2.0-2.20180605git4a062cf.el8.x86_64",
            "platform-python-3.6.8-56.el8_9.rocky.0.x86_64",
            "libpwquality-1.4.4-6.el8.x86_64",
            "util-linux-2.32.1-43.el8.x86_64",
            "curl-7.61.1-33.el8.x86_64",
            "rpm-libs-4.14.3-26.el8.x86_64",
            "device-mapper-1.02.181-13.el8_9.x86_64",
            "cryptsetup-libs-2.3.7-7.el8.x86_64",
            "elfutils-libs-0.189-3.el8.x86_64",
            "dbus-daemon-1.12.8-26.el8.x86_64",
            "systemd-239-78.el8.x86_64",
            "python3-libcomps-0.1.18-1.el8.x86_64",
            "openldap-2.4.46-18.el8.x86_64",
            "libmodulemd-2.13.0-1.el8.x86_64",
            "gnupg2-2.2.20-3.el8_6.x86_64",
            "librepo-1.14.2-4.el8.x86_64",
            "python3-libdnf-0.63.0-17.el8_9.x86_64",
            "python3-gpg-1.13.1-11.el8.x86_64",
            "python3-rpm-4.14.3-26.el8.x86_64",
            "dnf-data-4.7.0-19.el8.noarch",
            "dnf-4.7.0-19.el8.noarch",
            "iputils-20180629-11.el8.x86_64",
            "tar-1.30-9.el8.x86_64",
            "hostname-3.20-6.el8.x86_64",
            "langpacks-en-1.0-12.el8.noarch",
        ]
    )


def test_packages_ndb(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we can find and parse RPM NDB database files.

    Test file originates from an unmodified OpenSUSE Leap docker image (docker.io/opensuse/leap:latest).
    """

    fs_unix.map_dir("/usr/lib/sysimage/rpm", absolute_path("_data/plugins/os/unix/linux/redhat/rpm/ndb"))
    fs_unix.symlink("/usr/lib/sysimage/rpm", "/var/lib/rpm")
    target_unix.add_plugin(RpmPlugin)
    records = list(target_unix.rpm.packages())

    assert len(records) == 140

    # output compared using ``rpm -qa``
    assert sorted([r.package_name_full for r in records]) == sorted(
        [
            "libtirpc-netconfig-1.3.4-150300.3.23.1.x86_64",
            "boost-license1_66_0-1.66.0-150200.12.7.1.noarch",
            "file-magic-5.32-7.14.1.noarch",
            "system-user-root-20190513-3.3.1.noarch",
            "filesystem-15.0-11.8.1.x86_64",
            "crypto-policies-20230920.570ea89-150600.3.12.1.noarch",
            "libssh-config-0.9.8-150600.11.6.1.x86_64",
            "glibc-2.38-150600.14.40.1.x86_64",
            "libuuid1-2.39.3-150600.4.15.1.x86_64",
            "libsmartcols1-2.39.3-150600.4.15.1.x86_64",
            "libsasl2-3-2.1.28-150600.7.14.1.x86_64",
            "liblzma5-5.4.1-150600.3.3.1.x86_64",
            "libfa1-1.14.1-150600.3.3.1.x86_64",
            "libcom_err2-1.47.0-150600.4.6.2.x86_64",
            "libblkid1-2.39.3-150600.4.15.1.x86_64",
            "libfdisk1-2.39.3-150600.4.15.1.x86_64",
            "cracklib-dict-small-2.9.11-150600.1.90.x86_64",
            "libldap-data-2.4.46-150600.23.21.noarch",
            "libsemanage-conf-3.5-150600.1.48.x86_64",
            "libzstd1-1.5.5-150600.1.3.x86_64",
            "libsepol2-3.5-150600.1.49.x86_64",
            "libpcre2-8-0-10.42-150600.1.26.x86_64",
            "libnghttp2-14-1.40.0-150600.23.2.x86_64",
            "libgpg-error0-1.47-150600.1.3.x86_64",
            "kubic-locale-archive-2.38-150600.18.3.noarch",
            "libksba8-1.6.4-150600.1.2.x86_64",
            "openSUSE-release-appliance-docker-15.6-lp156.417.4.1.x86_64",
            "libbz2-1-1.0.8-150400.1.122.x86_64",
            "libeconf0-0.5.2-150400.3.6.1.x86_64",
            "libcap2-2.63-150400.3.3.1.x86_64",
            "libaudit1-3.0.6-150400.4.16.1.x86_64",
            "update-alternatives-1.19.0.4-150000.4.7.1.x86_64",
            "libsqlite3-0-3.50.2-150000.3.33.1.x86_64",
            "libpcre1-8.45-150000.20.13.1.x86_64",
            "liblua5_3-5-5.3.6-3.6.1.x86_64",
            "libkeyutils1-1.6.3-5.6.1.x86_64",
            "libjitterentropy3-3.4.1-150000.1.12.1.x86_64",
            "libgmp10-6.1.2-4.9.1.x86_64",
            "libgcc_s1-15.2.0+git10201-150000.1.6.1.x86_64",
            "libassuan0-2.5.5-150000.4.7.1.x86_64",
            "libstdc++6-15.2.0+git10201-150000.1.6.1.x86_64",
            "libncurses6-6.1-150000.5.30.1.x86_64",
            "terminfo-base-6.1-150000.5.30.1.x86_64",
            "ncurses-utils-6.1-150000.5.30.1.x86_64",
            "libz1-1.2.13-150500.4.3.1.x86_64",
            "libxml2-2-2.10.3-150500.5.35.1.x86_64",
            "libbrotlicommon1-1.0.7-150200.3.5.1.x86_64",
            "libboost_system1_66_0-1.66.0-150200.12.7.1.x86_64",
            "libbrotlidec1-1.0.7-150200.3.5.1.x86_64",
            "libboost_thread1_66_0-1.66.0-150200.12.7.1.x86_64",
            "libcap-ng0-0.7.9-4.37.x86_64",
            "libverto1-0.2.6-3.20.x86_64",
            "libpopt0-1.16-3.22.x86_64",
            "libnpth0-1.5-2.11.x86_64",
            "libattr1-2.4.47-2.19.x86_64",
            "fillup-1.42-2.18.x86_64",
            "libzio1-1.06-2.20.x86_64",
            "libunistring2-0.9.10-1.1.x86_64",
            "libcrypt1-4.4.15-150300.4.7.1.x86_64",
            "perl-base-5.26.1-150300.17.20.1.x86_64",
            "libselinux1-3.5-150600.3.3.1.x86_64",
            "libglib-2_0-0-2.78.6-150600.4.35.1.x86_64",
            "libudev1-254.27-150600.4.55.1.x86_64",
            "libgcrypt20-1.10.3-150600.3.9.1.x86_64",
            "libopenssl3-3.1.4-150600.5.42.1.x86_64",
            "libaugeas0-1.14.1-150600.3.3.1.x86_64",
            "libmount1-2.39.3-150600.4.15.1.x86_64",
            "krb5-1.20.1-150600.11.14.1.x86_64",
            "libssh4-0.9.8-150600.11.6.1.x86_64",
            "libyaml-cpp0_6-0.6.3-150400.4.3.1.x86_64",
            "libreadline7-7.0-150400.27.6.1.x86_64",
            "libelf1-0.185-150400.5.8.3.x86_64",
            "libusb-1_0-0-1.0.24-150400.3.3.1.x86_64",
            "bash-4.4-150400.27.6.1.x86_64",
            "bash-sh-4.4-150400.27.6.1.x86_64",
            "libdw1-0.185-150400.5.8.3.x86_64",
            "cpio-2.13-150400.3.6.1.x86_64",
            "libsigc-2_0-0-2.12.1-150600.1.2.x86_64",
            "libsemanage2-3.5-150600.1.48.x86_64",
            "libzck1-1.1.16-150600.9.3.x86_64",
            "libldap-2_4-2-2.4.46-150600.23.21.x86_64",
            "libcrack2-2.9.11-150600.1.90.x86_64",
            "cracklib-2.9.11-150600.1.90.x86_64",
            "libmagic1-5.32-7.14.1.x86_64",
            "libacl1-2.2.52-4.3.1.x86_64",
            "libidn2-0-2.2.0-3.6.1.x86_64",
            "libpsl5-0.20.1-150000.3.3.1.x86_64",
            "findutils-4.8.0-150300.3.3.2.x86_64",
            "libtirpc3-1.3.4-150300.3.23.1.x86_64",
            "patterns-base-fips-20200505-lp156.17.3.1.x86_64",
            "login_defs-4.8.1-150600.17.9.1.noarch",
            "libcurl4-8.14.1-150600.4.37.1.x86_64",
            "info-6.5-4.17.x86_64",
            "libnsl2-1.2.0-2.44.x86_64",
            "coreutils-8.32-150400.9.9.1.x86_64",
            "sed-4.9-150600.1.4.x86_64",
            "pinentry-1.1.0-4.3.1.x86_64",
            "grep-3.1-150000.4.6.1.x86_64",
            "gawk-4.2.1-150000.3.3.1.x86_64",
            "diffutils-3.6-4.3.1.x86_64",
            "gpg2-2.4.4-150600.3.12.1.x86_64",
            "permissions-20240826-150600.10.18.2.x86_64",
            "libgpgme11-1.23.0-150600.3.5.1.x86_64",
            "openSUSE-release-15.6-lp156.417.4.1.x86_64",
            "rpm-config-SUSE-1-150400.14.3.1.noarch",
            "rpm-ndb-4.14.3-150400.59.16.1.x86_64",
            "pam-1.3.0-150000.6.86.1.x86_64",
            "libsolv-tools-base-0.7.34-150600.8.19.2.x86_64",
            "shadow-4.8.1-150600.17.9.1.x86_64",
            "libzypp-17.37.18-150600.3.82.1.x86_64",
            "zypper-1.14.94-150600.10.52.1.x86_64",
            "sysuser-shadow-3.2-150400.3.5.3.noarch",
            "system-group-hardware-20170617-150400.24.2.1.noarch",
            "libutempter0-1.1.6-3.42.x86_64",
            "util-linux-2.39.3-150600.4.15.1.x86_64",
            "aaa_base-84.87+git20180409.04c9dae-150300.10.28.2.x86_64",
            "libffi7-3.2.1.git259-10.8.x86_64",
            "openSUSE-build-key-1.0-lp156.8.2.noarch",
            "libtasn1-6-4.13-150000.4.14.1.x86_64",
            "libtasn1-4.13-150000.4.14.1.x86_64",
            "netcfg-11.6-150000.3.6.1.noarch",
            "curl-8.14.1-150600.4.37.1.x86_64",
            "timezone-2025b-150600.91.6.2.x86_64",
            "liblz4-1-1.9.4-150600.1.4.x86_64",
            "openssl-3.1.4-150600.2.1.noarch",
            "libp11-kit0-0.23.22-150500.8.3.1.x86_64",
            "p11-kit-0.23.22-150500.8.3.1.x86_64",
            "p11-kit-tools-0.23.22-150500.8.3.1.x86_64",
            "libsystemd0-254.27-150600.4.55.1.x86_64",
            "openssl-3-3.1.4-150600.5.42.1.x86_64",
            "libprocps8-3.3.17-150000.7.42.1.x86_64",
            "procps-3.3.17-150000.7.42.1.x86_64",
            "ca-certificates-2+git20240416.98ae794-150300.4.3.3.noarch",
            "ca-certificates-mozilla-2.74-150200.41.1.noarch",
            "gpg-pubkey-25db7ae0-645bae34",
            "gpg-pubkey-29b700a4-62b07e22",
            "gpg-pubkey-39db7c82-5f68629b",
            "gpg-pubkey-3dbdc284-53674dd4",
            "gpg-pubkey-3fa1d6ce-63c9481c",
            "gpg-pubkey-65176565-61a0ee8f",
        ]
    )


def test_package_files_output(target_unix: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we can output file records for packages."""

    fs_unix.map_dir("/usr/lib/sysimage/rpm", absolute_path("_data/plugins/os/unix/linux/redhat/rpm/ndb"))
    fs_unix.symlink("/usr/lib/sysimage/rpm", "/var/lib/rpm")

    fs_unix.map_file_fh("/etc/bash.bashrc", BytesIO(b"foo"))

    target_unix.add_plugin(RpmPlugin)
    records = sorted(target_unix.rpm.packages(output_files=True), key=lambda r: r.package_name_full)

    assert records[0].ts == datetime(2026, 2, 9, 6, 52, 51, tzinfo=timezone.utc)
    assert records[0].package_name == "aaa_base"
    assert records[0].package_summary == "openSUSE Base Package"
    assert len(records[0].package_files) == 62

    assert records[1].ts == datetime(2026, 2, 9, 6, 52, 51, tzinfo=timezone.utc)
    assert records[1].package_name == "aaa_base"
    assert records[1].path == "/etc/bash.bashrc"
    assert records[1].exists == True  # noqa: E712
    assert records[1].stored_digest.sha256 == "bffe5f498f7ec8148f986030a70fcf7b17519bc5f9a61269a447f75e258fdf43"
    assert records[1].actual_digest.sha256 == "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
    assert records[1].digest_match == False  # noqa: E712
    assert records[1].stored_size == 10536
    assert records[1].source == "/usr/lib/sysimage/rpm/Packages.db"


@pytest.mark.parametrize(
    "path_part",
    ["simple"],
)
def test_blob_parsing(path_part: str) -> None:
    """Test if we can parse RPM blob entries correctly."""

    path = "_data/plugins/os/unix/linux/redhat/rpm/blob"
    blob = absolute_path(f"{path}/{path_part}.bin").read_bytes()
    expected_output = absolute_path(f"{path}/{path_part}.json").read_text()

    assert json.dumps(parse_blob(blob), default=repr, indent=4) == expected_output
