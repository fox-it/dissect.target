from __future__ import annotations

from typing import BinaryIO

import pytest

from dissect.target.helpers import magic


@pytest.mark.parametrize(
    ("func", "input", "mime_out", "expected_output"),
    [
        # Archives
        ("from_buffer", bytes.fromhex("1f9d"), True, "application/x-compress"),
        ("from_buffer", bytes.fromhex("1fa0"), True, "application/x-compress"),
        ("from_buffer", bytes.fromhex("00002D6C68302D"), True, "application/x-lha"),
        ("from_buffer", bytes.fromhex("00002D6C68352D"), True, "application/x-lha"),
        ("from_buffer", bytes.fromhex("edabeedb"), True, "application/x-rpm"),
        ("from_buffer", b"BZh", True, "application/x-bzip2"),
        ("from_buffer", b"LZIP", True, "application/x-lzip"),
        ("from_buffer", b"070701", True, "application/x-cpio"),
        ("from_buffer", b"070702", True, "application/x-cpio"),
        ("from_buffer", b"070707", True, "application/x-cpio"),
        ("from_buffer", bytes.fromhex("504b0304"), True, "application/zip"),
        ("from_buffer", bytes.fromhex("504b0506"), True, "application/zip"),
        ("from_buffer", bytes.fromhex("504b0708"), True, "application/zip"),
        ("from_buffer", bytes.fromhex("526172211a07"), True, "application/vnd.rar"),
        ("from_buffer", bytes.fromhex("526172211a070100"), True, "application/vnd.rar"),
        ("from_buffer", bytes.fromhex("0E031301"), True, "application/x-hdf"),
        ("from_buffer", bytes.fromhex("894844460D0A1A0A"), True, "application/x-hdf"),
        pytest.param("from_buffer", (b"\x00" * 0x8001) + b"CD001", True, "application/vnd.efi.iso", id="iso"),
        ("from_buffer", b"xar!", True, "application/x-xar"),
        pytest.param("from_buffer", (b"\x00" * 257) + b"ustar\x00\x30\x30", False, "Tar archive", id="tar1"),
        pytest.param("from_buffer", (b"\x00" * 257) + b"ustar\x20\x20\x00", False, "Tar archive", id="tar2"),
        ("from_buffer", b"\x37\x7a\xbc\xaf\x27\x1c", True, "application/x-7z-compressed"),
        ("from_buffer", b"\x1f\x8b", True, "application/gzip"),
        ("from_buffer", b"\xfd\x37\x7a\x58\x5a\x00", True, "application/x-xz"),
        ("from_buffer", b"\x04\x22\x4d\x18", True, "application/x-lz4"),
        ("from_buffer", b"MSCF\x00\x00\x00\x00", True, "application/vnd.ms-cab-compressed"),
        ("from_buffer", b"\x78\x01", True, "application/zlib"),
        ("from_buffer", b"\x78\x5e", True, "application/zlib"),
        ("from_buffer", b"\x78\x9c", True, "application/zlib"),
        ("from_buffer", b"\x78\xda", True, "application/zlib"),
        ("from_buffer", b"\x78\x20", True, "application/zlib"),
        ("from_buffer", b"\x78\x7d", True, "application/zlib"),
        ("from_buffer", b"\x78\xbb", True, "application/zlib"),
        ("from_buffer", b"\x78\xf9", True, "application/zlib"),
        ("from_buffer", bytes.fromhex("4f626a01"), True, "application/avro"),
        ("from_buffer", bytes.fromhex("28B52FFD"), True, "application/zstd"),
        ("from_buffer", b"IsZ!", True, "application/vnd.efi.iso+compressed"),
        ("from_buffer", b"TAPE", True, "application/vnd.ms-tape"),
        # Database formats
        ("from_buffer", b"SQLite format 3\x00FILE DATA\x4d\x3c\xb2\xa1", True, "application/vnd.sqlite3"),
        ("from_buffer", b"SQLite format 3\x00FILE DATA\x4d\x3c\xb2\xa1", None, "SQLite3 database"),
        ("from_buffer", b"DUCK", True, "application/x-duckdb"),
        # Images
        ("from_buffer", b"\x00\x00\x01\x00", True, "image/vnd.microsoft.icon"),
        ("from_buffer", b"icns", True, "image/x-icns"),
        ("from_buffer", (b"\x00" * 4) + b"ftypheic", True, "image/heif"),
        ("from_buffer", b"GIF87a", True, "image/gif"),
        ("from_buffer", b"GIF89a", True, "image/gif"),
        ("from_buffer", bytes.fromhex("49492a00"), True, "image/tiff"),
        ("from_buffer", bytes.fromhex("4d4d002a"), True, "image/tiff"),
        ("from_buffer", bytes.fromhex("49492B00"), True, "image/bigtiff"),
        ("from_buffer", bytes.fromhex("4D4D002B"), True, "image/bigtiff"),
        ("from_buffer", bytes.fromhex("49492A00100000004352"), True, "image/tiff"),
        ("from_buffer", bytes.fromhex("425047FB"), True, "image/bpg"),
        ("from_buffer", bytes.fromhex("ffd8ffdb010203"), True, "image/jpeg"),
        ("from_buffer", bytes.fromhex("ffd8ffdb010203"), False, "JPEG image"),
        ("from_buffer", bytes.fromhex("FFD8FFE000104A4649460001"), True, "image/jpeg"),
        ("from_buffer", bytes.fromhex("FFD8FFEE"), True, "image/jpeg"),
        ("from_buffer", bytes.fromhex("FFD8FFE1"), True, "image/jpeg"),
        ("from_buffer", bytes.fromhex("FFD8FFE0"), True, "image/jpeg"),
        ("from_buffer", bytes.fromhex("ffd8ffdb"), True, "image/jpeg"),
        ("from_buffer", bytes.fromhex("ffd8ffe0"), True, "image/jpeg"),
        ("from_buffer", bytes.fromhex("ffd8ffe1"), True, "image/jpeg"),
        ("from_buffer", bytes.fromhex("0000000C6A5020200D0A870A"), True, "image/jp2"),
        ("from_buffer", bytes.fromhex("FF4FFF51"), True, "image/x-jp2-codestream"),
        ("from_buffer", bytes.fromhex("89504e470d0a1a0a"), True, "image/png"),
        ("from_buffer", b"8BPS  \x00\x00\x00\x00", True, "image/vnd.adobe.photoshop"),
        # Audio and video
        ("from_buffer", b"OggS", True, "application/ogg"),
        ("from_buffer", bytes.fromhex("52494646"), True, "application/x-riff"),
        ("from_buffer", bytes.fromhex("fffb"), True, "audio/mpeg"),
        ("from_buffer", bytes.fromhex("fff3"), True, "audio/mpeg"),
        ("from_buffer", bytes.fromhex("fff2"), True, "audio/mpeg"),
        ("from_buffer", b"ID3", True, "audio/mpeg"),
        ("from_buffer", b"fLaC", True, "audio/flac"),
        ("from_buffer", b"MThd", True, "audio/midi"),
        ("from_buffer", bytes.fromhex("1A45DFA3"), True, "application/x-matroska"),
        ("from_buffer", b"\x00\x00\x00\x00ftypisom", True, "video/mp4"),
        ("from_buffer", b"\x00\x00\x00\x00ftypMSNV", True, "video/mp4"),
        ("from_buffer", b"#EXTM3U", True, "audio/x-mpegurl"),
        # Productivity
        ("from_buffer", b"\x25\x50\x44\x46-", True, "application/pdf"),
        ("from_buffer", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", True, "application/vnd.ms-excel"),
        ("from_buffer", b"Received:", True, "message/rfc822"),
        ("from_buffer", b"!BDN", True, "application/vnd.ms-outlook-pst"),
        # Executables
        ("from_buffer", b"MZ", True, "application/x-dosexec"),
        ("from_buffer", bytes.fromhex("7F454C46"), True, "application/x-executable"),
        ("from_buffer", bytes.fromhex("cafebabe"), True, "application/x-java"),
        ("from_buffer", bytes.fromhex("feedface"), True, "application/x-mach-o"),
        ("from_buffer", bytes.fromhex("feedfacf"), True, "application/x-mach-o"),
        ("from_buffer", bytes.fromhex("feedfeed"), True, "application/x-java-keystore"),
        ("from_buffer", bytes.fromhex("cefaedfe"), True, "application/x-mach-o"),
        ("from_buffer", bytes.fromhex("cffaedfe"), True, "application/x-mach-o"),
        ("from_buffer", b"%!PS", True, "application/postscript"),
        ("from_buffer", b"\x00asm", True, "application/wasm"),
        ("from_buffer", b"!<arch>\x0a", True, "application/vnd.debian.binary-package"),
        ("from_buffer", bytes.fromhex("1B4C7561"), True, "application/x-lua"),
        # Network
        ("from_buffer", bytes.fromhex("d4c3b2a1"), True, "application/vnd.tcpdump.pcap"),
        ("from_buffer", bytes.fromhex("a1b2c3d4"), True, "application/vnd.tcpdump.pcap"),
        ("from_buffer", bytes.fromhex("4d3cb2a1"), True, "application/vnd.tcpdump.pcap"),
        ("from_buffer", bytes.fromhex("a1b23c4d"), True, "application/vnd.tcpdump.pcap"),
        ("from_buffer", bytes.fromhex("0a0d0d0a"), True, "application/x-pcapng"),
        # Certificates
        ("from_buffer", b"-----BEGIN CERTIFICATE-----", True, "application/pkix-cert"),
        ("from_buffer", b"-----BEGIN CERTIFICATE REQUEST-----", True, "text/pkix-csr"),
        ("from_buffer", b"-----BEGIN PRIVATE KEY-----", True, "text/x-ssh-private-key"),
        ("from_buffer", b"-----BEGIN DSA PRIVATE KEY-----", True, "text/x-ssh-private-key"),
        ("from_buffer", b"-----BEGIN RSA PRIVATE KEY-----", True, "text/x-ssh-private-key"),
        ("from_buffer", b"PuTTY-User-Key-File-2:", True, "text/x-putty-private-key"),
        ("from_buffer", b"PuTTY-User-Key-File-3:", True, "text/x-putty-private-key"),
        ("from_buffer", b"-----BEGIN OPENSSH PRIVATE KEY-----", True, "text/x-ssh-private-key"),
        ("from_buffer", b"-----BEGIN SSH2 PUBLIC KEY-----", True, "text/x-ssh-public-key"),
        ("from_buffer", b"-----BEGIN PGP PUBLIC KEY BLOCK-----", True, "application/pgp-keys"),
        # Web
        ("from_buffer", b"wOFF", True, "font/woff"),
        ("from_buffer", b"wOF2", True, "font/woff2"),
        ("from_buffer", b"ITSF\x03\x00\x00\x00\x60\x00\x00\x00", True, "application/vnd.ms-htmlhelp"),
        # Containers and disks
        ("from_buffer", b"KDMV\x01\x00\x00\x00", True, "application/x-vmdk-disk"),
        ("from_buffer", b"AFF", True, "application/x-aff"),
        ("from_buffer", b"EVF2", True, "application/x-encase"),
        ("from_buffer", b"EVF", True, "application/x-encase"),
        ("from_buffer", b"QFI", True, "application/x-qemu-disk"),
        ("from_buffer", b"<<< Oracle VM VirtualBox Disk Image >>>", True, "application/x-oracle-virtualbox-vdi"),
        ("from_buffer", b"conectix", True, "application/x-vhd-disk"),
        ("from_buffer", b"vhdxfile", True, "application/x-vhdx-disk"),
        ("from_buffer", b"MSWIM\x00\x00\x00\xd0\x00\x00\x00\x00", True, "application/x-ms-wim"),
        # Log files
        ("from_buffer", b"LfLe", True, "application/x-win-evt"),
        ("from_buffer", b"ElfFile", True, "application/x-win-evtx"),
        ("from_buffer", b"regf", True, "application/x-win-regf"),
        ("from_buffer", b"[ZoneTransfer]", True, "application/x-win-zonetransfer"),
        ("from_buffer", b"LPKSHHRH", True, "application/x-systemd-journald-log"),
        ("from_buffer", b"\xc0\x3b\x39\x98", True, "application/x-ext-jbd-fs-journal"),
        # Other data formats
        ("from_buffer", b"bplist", True, "application/x-plist"),
        ("from_buffer", b"<?xml ", True, "application/xml"),
        # Negatives
        ("from_buffer", b"unknown_file", None, None),
        ("from_buffer", b"", None, None),
    ],
)
def test_magic_detection(func: str, input: bytes | BinaryIO | None, mime_out: bool, expected_output: str) -> None:
    """Test if we correctly identify common files.

    Relevant examples taken from referenced wikipedia page, grouped by types.

    References:
        - https://en.wikipedia.org/wiki/List_of_file_signatures
    """

    assert getattr(magic, func)(input, mime=mime_out) == expected_output


def test_magic_exception_handling() -> None:
    """Test if we throw sensible exception messages."""

    with pytest.raises(TypeError, match="Provided path is not a TargetPath or FilesystemEntry"):
        magic.from_file("not a Path")

    with pytest.raises(TypeError, match="Provided buf is not bytes or a buffer"):
        magic.from_buffer("string")

    with pytest.raises(TypeError, match="Provided fh does not have a read or seek method"):
        magic.from_descriptor(b"not a buffer")

    with pytest.raises(TypeError, match="Provided suffix is not a string"):
        magic.Magic.detect(b"foo", suffix=b"not a string", mime=False)
