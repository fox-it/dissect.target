from __future__ import annotations

from io import BytesIO
from typing import TYPE_CHECKING, BinaryIO

import pytest

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.helpers import magic
from tests._utils import absolute_path

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.filesystem import FilesystemEntry


fs = VirtualFilesystem()
fs.map_file_fh("example.png", BytesIO(b""))
entry = fs.get("example.png")


@pytest.mark.parametrize(
    ("func", "input", "mime_out", "expected_output"),
    [
        # Archives
        pytest.param("from_buffer", bytes.fromhex("1f9d"), True, "application/x-compress", id="x-compress-1"),
        pytest.param("from_buffer", bytes.fromhex("1fa0"), True, "application/x-compress", id="x-compress-2"),
        pytest.param("from_buffer", bytes.fromhex("00002D6C68302D"), True, "application/x-lha", id="x-lha-1"),
        pytest.param("from_buffer", bytes.fromhex("00002D6C68352D"), True, "application/x-lha", id="x-lha-2"),
        pytest.param("from_buffer", bytes.fromhex("edabeedb"), True, "application/x-rpm", id="rpm"),
        pytest.param("from_buffer", b"BZh", True, "application/x-bzip2", id="bzip2"),
        pytest.param("from_buffer", b"LZIP", True, "application/x-lzip", id="lzip"),
        pytest.param("from_buffer", b"070701", True, "application/x-cpio", id="cpio-1"),
        pytest.param("from_buffer", b"070702", True, "application/x-cpio", id="cpio-2"),
        pytest.param("from_buffer", b"070707", True, "application/x-cpio", id="cpio-3"),
        pytest.param("from_buffer", bytes.fromhex("504b0304"), True, "application/zip", id="zip-1"),
        pytest.param("from_buffer", bytes.fromhex("504b0506"), True, "application/zip", id="zip-2"),
        pytest.param("from_buffer", bytes.fromhex("504b0708"), True, "application/zip", id="zip-3"),
        pytest.param("from_buffer", bytes.fromhex("526172211a07"), True, "application/vnd.rar", id="rar-1"),
        pytest.param("from_buffer", bytes.fromhex("526172211a070100"), True, "application/vnd.rar", id="rar-2"),
        pytest.param("from_buffer", bytes.fromhex("0E031301"), True, "application/x-hdf", id="x-hdf-1"),
        pytest.param("from_buffer", bytes.fromhex("894844460D0A1A0A"), True, "application/x-hdf", id="x-hdf-2"),
        pytest.param("from_buffer", (b"\x00" * 0x8001) + b"CD001", True, "application/vnd.efi.iso", id="iso-1"),
        pytest.param("from_buffer", b"xar!", True, "application/x-xar", id="x-xar"),
        pytest.param("from_buffer", (b"\x00" * 257) + b"ustar\x00\x30\x30", False, "Tar archive", id="tar-1"),
        pytest.param("from_buffer", (b"\x00" * 257) + b"ustar\x20\x20\x00", False, "Tar archive", id="tar-2"),
        pytest.param("from_buffer", b"\x37\x7a\xbc\xaf\x27\x1c", True, "application/x-7z-compressed", id="7z"),
        pytest.param("from_buffer", b"\x1f\x8b", True, "application/gzip", id="gzip"),
        pytest.param("from_buffer", b"\xfd\x37\x7a\x58\x5a\x00", True, "application/x-xz", id="xz"),
        pytest.param("from_buffer", b"\x04\x22\x4d\x18", True, "application/x-lz4", id="lz4"),
        pytest.param("from_buffer", b"MSCF\x00\x00\x00\x00", True, "application/vnd.ms-cab-compressed", id="cab"),
        pytest.param("from_buffer", b"\x78\x01", True, "application/zlib", id="zlib-1"),
        pytest.param("from_buffer", b"\x78\x5e", True, "application/zlib", id="zlib-2"),
        pytest.param("from_buffer", b"\x78\x9c", True, "application/zlib", id="zlib-3"),
        pytest.param("from_buffer", b"\x78\xda", True, "application/zlib", id="zlib-4"),
        pytest.param("from_buffer", b"\x78\x20", True, "application/zlib", id="zlib-5"),
        pytest.param("from_buffer", b"\x78\x7d", True, "application/zlib", id="zlib-6"),
        pytest.param("from_buffer", b"\x78\xbb", True, "application/zlib", id="zlib-7"),
        pytest.param("from_buffer", b"\x78\xf9", True, "application/zlib", id="zlib-8"),
        pytest.param("from_buffer", bytes.fromhex("4f626a01"), True, "application/avro", id="avro"),
        pytest.param("from_buffer", bytes.fromhex("28B52FFD"), True, "application/zstd", id="zstd"),
        pytest.param("from_buffer", b"IsZ!", True, "application/vnd.efi.iso+compressed", id="iso-2"),
        pytest.param("from_buffer", b"TAPE", True, "application/vnd.ms-tape", id="tape"),
        # Database formats
        pytest.param(
            "from_buffer",
            b"SQLite format 3\x00FILE DATA\x4d\x3c\xb2\xa1",
            True,
            "application/vnd.sqlite3",
            id="sqlite-1",
        ),
        pytest.param(
            "from_buffer", b"SQLite format 3\x00FILE DATA\x4d\x3c\xb2\xa1", None, "SQLite3 database", id="sqlite-2"
        ),
        pytest.param("from_buffer", b"DUCK", True, "application/x-duckdb", id="duckdb"),
        # Images
        pytest.param("from_buffer", b"\x00\x00\x01\x00", True, "image/vnd.microsoft.icon", id="msicon"),
        pytest.param("from_buffer", b"icns", True, "image/x-icns", id="x-icns"),
        pytest.param("from_buffer", (b"\x00" * 4) + b"ftypheic", True, "image/heif", id="heif"),
        pytest.param("from_buffer", b"GIF87a", True, "image/gif", id="gif-1"),
        pytest.param("from_buffer", b"GIF89a", True, "image/gif", id="gif-2"),
        pytest.param("from_buffer", bytes.fromhex("49492a00"), True, "image/tiff", id="tiff-1"),
        pytest.param("from_buffer", bytes.fromhex("4d4d002a"), True, "image/tiff", id="tiff-2"),
        pytest.param("from_buffer", bytes.fromhex("49492B00"), True, "image/bigtiff", id="bigtiff-1"),
        pytest.param("from_buffer", bytes.fromhex("4D4D002B"), True, "image/bigtiff", id="bigtiff-2"),
        pytest.param("from_buffer", bytes.fromhex("49492A00100000004352"), True, "image/tiff", id="tiff-3"),
        pytest.param("from_buffer", bytes.fromhex("425047FB"), True, "image/bpg", id="bpg"),
        pytest.param("from_buffer", bytes.fromhex("ffd8ffdb010203"), True, "image/jpeg", id="jpeg-1"),
        pytest.param("from_buffer", bytes.fromhex("ffd8ffdb010203"), False, "JPEG image", id="jpeg-2"),
        pytest.param("from_buffer", bytes.fromhex("FFD8FFE000104A4649460001"), True, "image/jpeg", id="jpeg-3"),
        pytest.param("from_buffer", bytes.fromhex("FFD8FFEE"), True, "image/jpeg", id="jpeg-4"),
        pytest.param("from_buffer", bytes.fromhex("FFD8FFE1"), True, "image/jpeg", id="jpeg-5"),
        pytest.param("from_buffer", bytes.fromhex("FFD8FFE0"), True, "image/jpeg", id="jpeg-6"),
        pytest.param("from_buffer", bytes.fromhex("ffd8ffdb"), True, "image/jpeg", id="jpeg-7"),
        pytest.param("from_buffer", bytes.fromhex("ffd8ffe0"), True, "image/jpeg", id="jpeg-8"),
        pytest.param("from_buffer", bytes.fromhex("ffd8ffe1"), True, "image/jpeg", id="jpeg-9"),
        pytest.param("from_buffer", bytes.fromhex("0000000C6A5020200D0A870A"), True, "image/jp2", id="jp2-1"),
        pytest.param("from_buffer", bytes.fromhex("FF4FFF51"), True, "image/x-jp2-codestream", id="jp2-2"),
        pytest.param("from_buffer", bytes.fromhex("89504e470d0a1a0a"), True, "image/png", id="png-1"),
        pytest.param("from_buffer", b"8BPS  \x00\x00\x00\x00", True, "image/vnd.adobe.photoshop", id="psd"),
        # Audio and video
        pytest.param("from_buffer", b"OggS", True, "application/ogg", id="ogg"),
        pytest.param("from_buffer", bytes.fromhex("52494646"), True, "application/x-riff", id="riff"),
        pytest.param("from_buffer", bytes.fromhex("fffb"), True, "audio/mpeg", id="mpeg-1"),
        pytest.param("from_buffer", bytes.fromhex("fff3"), True, "audio/mpeg", id="mpeg-2"),
        pytest.param("from_buffer", bytes.fromhex("fff2"), True, "audio/mpeg", id="mpeg-3"),
        pytest.param("from_buffer", b"ID3", True, "audio/mpeg", id="mpeg-4"),
        pytest.param("from_buffer", b"fLaC", True, "audio/flac", id="flac"),
        pytest.param("from_buffer", b"MThd", True, "audio/midi", id="midi"),
        pytest.param("from_buffer", bytes.fromhex("1A45DFA3"), True, "application/x-matroska", id="mkv"),
        pytest.param("from_buffer", b"\x00\x00\x00\x00ftypisom", True, "video/mp4", id="mp4-1"),
        pytest.param("from_buffer", b"\x00\x00\x00\x00ftypMSNV", True, "video/mp4", id="mp4-2"),
        pytest.param("from_buffer", b"#EXTM3U", True, "audio/x-mpegurl", id="mpeg-5"),
        # Productivity
        pytest.param("from_buffer", b"\x25\x50\x44\x46-", True, "application/pdf", id="pdf"),
        pytest.param(
            "from_buffer", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", True, "application/vnd.ms-excel", id="msexcel"
        ),
        pytest.param("from_buffer", b"Received:", True, "message/rfc822", id="email"),
        pytest.param("from_buffer", b"!BDN", True, "application/vnd.ms-outlook-pst", id="pst"),
        pytest.param(
            "from_buffer",
            (b"\x00" * 2112) + b"Microsoft Word document data",
            True,
            "application/msword",
            id="msword",
        ),
        pytest.param(
            "from_buffer",
            (b"\x00" * 592) + bytes.fromhex("108d81649b4fcf1186ea00aa00b929e8"),
            True,
            "application/vnd.ms-powerpoint",
            id="mspowerpoint",
        ),
        # Executables
        pytest.param("from_buffer", b"MZ", True, "application/x-ms-dos-executable", id="mz"),
        pytest.param("from_buffer", bytes.fromhex("7F454C46"), True, "application/x-executable", id="elf"),
        pytest.param("from_buffer", bytes.fromhex("cafebabe"), True, "application/x-java", id="java"),
        pytest.param("from_buffer", bytes.fromhex("feedface"), True, "application/x-mach-o", id="macho-1"),
        pytest.param("from_buffer", bytes.fromhex("feedfacf"), True, "application/x-mach-o", id="macho-2"),
        pytest.param("from_buffer", bytes.fromhex("feedfeed"), True, "application/x-java-keystore", id="jks"),
        pytest.param("from_buffer", bytes.fromhex("cefaedfe"), True, "application/x-mach-o", id="macho-3"),
        pytest.param("from_buffer", bytes.fromhex("cffaedfe"), True, "application/x-mach-o", id="macho-4"),
        pytest.param("from_buffer", b"%!PS", True, "application/postscript", id="ps"),
        pytest.param("from_buffer", b"\x00asm", True, "application/wasm", id="wasm"),
        pytest.param("from_buffer", b"!<arch>\x0a", True, "application/vnd.debian.binary-package", id="deb"),
        pytest.param("from_buffer", bytes.fromhex("1B4C7561"), True, "application/x-lua", id="lua"),
        # Network
        pytest.param("from_buffer", bytes.fromhex("d4c3b2a1"), True, "application/vnd.tcpdump.pcap", id="pcap-1"),
        pytest.param("from_buffer", bytes.fromhex("a1b2c3d4"), True, "application/vnd.tcpdump.pcap", id="pcap-2"),
        pytest.param("from_buffer", bytes.fromhex("4d3cb2a1"), True, "application/vnd.tcpdump.pcap", id="pcap-3"),
        pytest.param("from_buffer", bytes.fromhex("a1b23c4d"), True, "application/vnd.tcpdump.pcap", id="pcap-4"),
        pytest.param("from_buffer", bytes.fromhex("0a0d0d0a"), True, "application/x-pcapng", id="pcapng"),
        # Certificates
        pytest.param("from_buffer", b"-----BEGIN CERTIFICATE-----", True, "application/pkix-cert", id="crt"),
        pytest.param("from_buffer", b"-----BEGIN CERTIFICATE REQUEST-----", True, "text/pkix-csr", id="csr"),
        pytest.param("from_buffer", b"-----BEGIN PRIVATE KEY-----", True, "text/x-ssh-private-key", id="privkey-1"),
        pytest.param("from_buffer", b"-----BEGIN DSA PRIVATE KEY-----", True, "text/x-ssh-private-key", id="privkey-2"),
        pytest.param("from_buffer", b"-----BEGIN RSA PRIVATE KEY-----", True, "text/x-ssh-private-key", id="privkey-3"),
        pytest.param("from_buffer", b"PuTTY-User-Key-File-2:", True, "text/x-putty-private-key", id="puttykey-1"),
        pytest.param("from_buffer", b"PuTTY-User-Key-File-3:", True, "text/x-putty-private-key", id="puttykey-2"),
        pytest.param(
            "from_buffer", b"-----BEGIN OPENSSH PRIVATE KEY-----", True, "text/x-ssh-private-key", id="privkey-4"
        ),
        pytest.param("from_buffer", b"-----BEGIN SSH2 PUBLIC KEY-----", True, "text/x-ssh-public-key", id="pubkey-1"),
        pytest.param(
            "from_buffer", b"-----BEGIN PGP PUBLIC KEY BLOCK-----", True, "application/pgp-keys", id="pubkey-2"
        ),
        # Web
        pytest.param("from_buffer", b"wOFF", True, "font/woff", id="woff"),
        pytest.param("from_buffer", b"wOF2", True, "font/woff2", id="woff2"),
        pytest.param(
            "from_buffer", b"ITSF\x03\x00\x00\x00\x60\x00\x00\x00", True, "application/vnd.ms-htmlhelp", id="mshelp"
        ),
        # Containers and disks
        pytest.param("from_buffer", b"KDMV\x01\x00\x00\x00", True, "application/x-vmdk-disk", id="vmdk"),
        pytest.param("from_buffer", b"AFF", True, "application/x-aff", id="x-aff"),
        pytest.param("from_buffer", b"EVF2", True, "application/x-encase", id="evf2"),
        pytest.param("from_buffer", b"EVF", True, "application/x-encase", id="evf"),
        pytest.param("from_buffer", b"QFI\xfb", True, "application/x-qemu-disk", id="qfi"),
        pytest.param(
            "from_buffer",
            b"<<< Oracle VM VirtualBox Disk Image >>>",
            True,
            "application/x-oracle-virtualbox-vdi",
            id="vdi",
        ),
        pytest.param("from_buffer", b"conectix", True, "application/x-vhd-disk", id="vhd"),
        pytest.param("from_buffer", b"vhdxfile", True, "application/x-vhdx-disk", id="vhdx"),
        pytest.param("from_buffer", b"MSWIM\x00\x00\x00\xd0\x00\x00\x00\x00", True, "application/x-ms-wim", id="mswim"),
        # Log files
        pytest.param("from_buffer", b"LfLe", True, "application/x-win-evt", id="evt"),
        pytest.param("from_buffer", b"ElfFile", True, "application/x-win-evtx", id="evtx"),
        pytest.param("from_buffer", b"regf", True, "application/x-win-regf", id="regf"),
        pytest.param("from_buffer", b"[ZoneTransfer]", True, "application/x-win-zonetransfer", id="zonetransfer"),
        pytest.param("from_buffer", b"LPKSHHRH", True, "application/x-systemd-journald-log", id="journal-1"),
        pytest.param("from_buffer", b"\xc0\x3b\x39\x98", True, "application/x-ext-jbd-fs-journal", id="journal-2"),
        # Other data formats
        pytest.param("from_buffer", b"bplist", True, "application/x-plist", id="bplist"),
        pytest.param("from_buffer", b"<?xml ", True, "application/xml", id="xml"),
        # Negatives
        pytest.param("from_buffer", b"unknown_file", None, None),
        pytest.param("from_buffer", b"", None, None),
        # Other methods
        pytest.param(
            "from_file",
            absolute_path("_data/filesystems/cpio/initrd.img-6.1.0-15-amd64"),
            True,
            "application/zstd",
            id="zstd",
        ),
        pytest.param("from_entry", entry, True, "image/png", id="png-2"),
        pytest.param("from_descriptor", BytesIO(b"ElfFile"), True, "application/x-win-evtx", id="evtx-2"),
        pytest.param("from_fh", BytesIO(b"regf"), True, "application/x-win-regf", id="regf-2"),
    ],
)
def test_magic_detection(
    func: str, input: bytes | BinaryIO | Path | FilesystemEntry | None, mime_out: bool, expected_output: str
) -> None:
    """Test if we correctly identify common files.

    Relevant examples taken from referenced wikipedia page, grouped by types.

    References:
        - https://en.wikipedia.org/wiki/List_of_file_signatures
    """
    assert getattr(magic, func)(input, mime=mime_out) == expected_output


def test_magic_exception_handling() -> None:
    """Test if we throw sensible exception messages."""
    with pytest.raises(TypeError, match="Provided path is not a Path instance"):
        magic.from_file("not a Path")

    with pytest.raises(TypeError, match="Provided buf is not bytes"):
        magic.from_buffer("string")

    with pytest.raises(TypeError, match="Provided fh does not have a read or seek method"):
        magic.from_descriptor(b"not a buffer")

    with pytest.raises(TypeError, match="Provided suffix is not a string"):
        magic.Magic.detect(b"foo", suffix=b"not a string", mime=False)
