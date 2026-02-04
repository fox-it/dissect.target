from __future__ import annotations

# Manual overrides for types freedesktop does not (yet) support.
TYPES = [
    {
        "type": "application/x-compress",
        "name": "UNIX-compressed file (LZH)",
        "pattern": ["*.Z", "*.z", "*.tar.z"],
        "magic": [{"offset": 0, "value": b"\x1f\xa0"}],
    },
    {
        "type": "application/x-plist",
        "name": "Apple binary property list file",
        "pattern": ["*.plist"],
        "magic": [{"offset": 0, "value": b"bplist"}],
    },
    {
        "type": "image/bigtiff",
        "name": "BigTIFF image",
        "pattern": ["*.tif", "*.tiff"],
        "magic": [
            {"offset": 0, "value": b"MM\x00+"},
            {"offset": 0, "value": b"II+\x00"},
        ],
    },
    {
        "type": "image/bpg",
        "name": "Better Portable Graphics image",
        "pattern": ["*.bpg"],
        "magic": [
            {"offset": 0, "value": b"\x42\x50\x47\xfb"},
        ],
    },
    {
        "type": "image/jp2",
        "name": "JPEG-2000 JP2 image",
        "pattern": ["*.jp2", "*.jpg2"],
        "magic": [{"offset": 0, "value": b"\x00\x00\x00\x0cjP  \r\n\x87\n"}],
    },
    {
        "type": "application/x-cpio",
        "name": "CPIO archive",
        "pattern": ["*.cpio"],
        "magic": [
            {"offset": 0, "value": b"070707"},
            {"offset": 0, "value": b"070701"},
            {"offset": 0, "value": b"070702"},
        ],
    },
    {
        "type": "application/zip",
        "name": "Zip archive",
        "pattern": ["*.zip", "*.zipx"],
        "magic": [
            {"offset": 0, "value": b"PK\x03\x04"},
            {"offset": 0, "value": b"PK\x05\x06"},
            {"offset": 0, "value": b"PK\x07\x08"},
        ],
    },
    {
        "type": "application/x-executable",
        "name": "Executable",
        "pattern": [],
        "magic": [
            {"offset": 0, "value": b"\x7fELF"},
            {"offset": 0, "value": b"R\x1c"},
            {"offset": 0, "value": b"\x04 "},
            {"offset": 0, "value": b"\x04!"},
            {"offset": 0, "value": b"\x06\x03"},
        ],
    },
    {
        "type": "application/x-mach-o",
        "name": "Mach-O executable",
        "pattern": [],
        "magic": [
            {"offset": 0, "value": b"\xfe\xed\xfa\xce"},
            {"offset": 0, "value": b"\xfe\xed\xfa\xcf"},
            {"offset": 0, "value": b"\xce\xfa\xed\xfe"},
            {"offset": 0, "value": b"\xcf\xfa\xed\xfe"},
        ],
    },
    {
        "type": "application/vnd.tcpdump.pcap",
        "name": "Network packet capture",
        "pattern": [
            "*.pcap",
        ],
        "magic": [
            {"offset": 0, "value": b"\xa1\xb2\xc3\xd4"},
            {"offset": 0, "value": b"\xd4\xc3\xb2\xa1"},
            {"offset": 0, "value": b"\xa1\xb2\x3c\x4d"},
            {"offset": 0, "value": b"\x4d\x3c\xb2\x4d"},
            {"offset": 0, "value": b"\xd4\xc3\xb2\xa1"},
            {"offset": 0, "value": b"\x4d\x3c\xb2\xa1"},
        ],
    },
    {
        "type": "application/vnd.ms-htmlhelp",
        "name": "CHM document",
        "pattern": ["*.chm"],
        "magic": [
            {"offset": 0, "value": b"\x49\x54\x53\x46\x03\x00\x00\x00\x60\x00\x00\x00"},
        ],
    },
    {
        "type": "application/vnd.efi.iso",
        "name": "Raw CD image",
        "pattern": ["*.iso", "*.iso9660"],
        "magic": [
            {"offset": 0x8001, "value": b"CD001"},
        ],
    },
    {
        "type": "application/vnd.efi.iso+compressed",
        "name": "Compressed ISO image",
        "pattern": ["*.isz"],
        "magic": [
            {"offset": 0, "value": b"IsZ!"},
        ],
    },
    {
        "type": "application/zstd",
        "name": "Zstandard archive",
        "pattern": ["*.zst"],
        "magic": [
            {"offset": 0, "value": b"\xfd/\xb5("},
            {"offset": 0, "value": b"\x28\xb5\x2f\xfd"},
        ],
    },
    {
        "type": "application/x-lz4",
        "name": "LZ4 archive",
        "pattern": ["*.lz4"],
        "magic": [
            {"offset": 0, "value": b'\x18M"\x04'},
            {"offset": 0, "value": b"\x18L!\x02"},
            {"offset": 0, "value": b"\x04\x22\x4d\x18"},
        ],
    },
    {
        "type": "application/zlib",
        "name": "Zlib archive",
        "pattern": ["*.zz"],
        "magic": [
            {"offset": 0, "value": b"\x78\x01"},
            {"offset": 0, "value": b"\x78\x5e"},
            {"offset": 0, "value": b"\x78\x9c"},
            {"offset": 0, "value": b"\x78\xda"},
            {"offset": 0, "value": b"\x78\x20"},
            {"offset": 0, "value": b"\x78\x7d"},
            {"offset": 0, "value": b"\x78\xbb"},
            {"offset": 0, "value": b"\x78\xf9"},
        ],
    },
    {
        "type": "application/avro",
        "name": "Apache Avro Object Container File",
        "pattern": ["*.avro"],
        "magic": [
            {"offset": 0, "value": b"Obj\x01"},
        ],
    },
    {
        "type": "application/vnd.ms-tape",
        "name": "Microsoft Tape Format (MTF)",
        "pattern": [],
        "magic": [
            {"offset": 0, "value": b"TAPE"},
        ],
    },
    {
        "type": "application/x-duckdb",
        "name": "DuckDB database file",
        "pattern": [],
        "magic": [
            {"offset": 0, "value": b"DUCK"},
        ],
    },
    {
        "type": "application/vnd.ms-outlook-pst",
        "name": "Microsoft Outlook Personal Storage Table file",
        "pattern": [],
        "magic": [
            {"offset": 0, "value": b"!BDN"},
        ],
    },
    {
        "type": "application/x-lua",
        "name": "Lua bytecode",
        "pattern": ["*.luac"],
        "magic": [
            {"offset": 0, "value": b"\x1bLua"},
        ],
    },
    {
        "type": "application/x-aff",
        "name": "Advanced Forensics Format",
        "pattern": ["*.aff"],
        "magic": [
            {"offset": 0, "value": b"AFF"},
        ],
    },
    {
        "type": "application/x-encase",
        "name": "EnCase EWF version 2 format",
        "pattern": ["*.e01", "*.E01"],
        "magic": [
            {"offset": 0, "value": b"EVF2"},
        ],
    },
    {
        "type": "application/x-encase",
        "name": "EnCase EWF version 1 format",
        "pattern": ["*.e01", "*.E01"],
        "magic": [
            {"offset": 0, "value": b"EVF"},
        ],
    },
    {
        "type": "application/x-oracle-virtualbox-vdi",
        "name": "Oracle VirtualBox Virtual Hard Disk file format",
        "pattern": ["*.vdi"],
        "magic": [
            {"offset": 0, "value": b"<<< Oracle VM VirtualBox Disk Image >>>"},
        ],
    },
    {
        "type": "application/x-win-evt",
        "name": "Windows Event Viewer file format",
        "pattern": ["*.evt"],
        "magic": [
            {"offset": 0, "value": b"LfLe"},
        ],
    },
    {
        "type": "application/x-win-evtx",
        "name": "Windows Event Viewer XML file format",
        "pattern": ["*.evtx"],
        "magic": [
            {"offset": 0, "value": b"ElfFile"},
        ],
    },
    {
        "type": "application/x-win-regf",
        "name": "Windows Registry file",
        "pattern": [],
        "magic": [
            {"offset": 0, "value": b"regf"},
        ],
    },
    {
        "type": "application/x-win-zonetransfer",
        "name": "Microsoft Zone Identifier for URL Security Zones",
        "pattern": ["*.Identifier"],
        "magic": [
            {"offset": 0, "value": b"[ZoneTransfer]"},
        ],
    },
    {
        "type": "application/x-systemd-journald-log",
        "name": "Systemd Journald log file",
        "pattern": ["*.journal"],
        "magic": [
            {"offset": 0, "value": b"LPKSHHRH"},
        ],
    },
    {
        "type": "application/x-ext-jbd-fs-journal",
        "name": "Linux EXT3/EXT4 jbd2 filesystem journal",
        "pattern": [],
        "magic": [
            {"offset": 0, "value": b"\xc0\x3b\x39\x98"},
        ],
    },
    {
        "type": "text/pkix-csr",
        "name": "X.509 certificate signing request",
        "pattern": ["*.csr"],
        "magic": [
            {"offset": 0, "value": b"-----BEGIN CERTIFICATE REQUEST-----"},
        ],
    },
    {
        "type": "text/x-ssh-private-key",
        "name": "OpenSSH private key",
        "pattern": [],
        "magic": [
            {"offset": 0, "value": b"-----BEGIN OPENSSH PRIVATE KEY-----"},
            {"offset": 0, "value": b"-----BEGIN PRIVATE KEY-----"},
            {"offset": 0, "value": b"-----BEGIN DSA PRIVATE KEY-----"},
            {"offset": 0, "value": b"-----BEGIN RSA PRIVATE KEY-----"},
        ],
    },
    {
        "type": "text/x-ssh-public-key",
        "name": "OpenSSH public key",
        "pattern": ["*.pub"],
        "magic": [
            {"offset": 0, "value": b"ssh-ed25519 "},
            {"offset": 0, "value": b"sk-ssh-ed25519@openssh.com "},
            {"offset": 0, "value": b"ecdsa-sha2-nistp521 "},
            {"offset": 0, "value": b"ecdsa-sha2-nistp384 "},
            {"offset": 0, "value": b"ecdsa-sha2-nistp256 "},
            {"offset": 0, "value": b"sk-ecdsa-sha2-nistp256@openssh.com "},
            {"offset": 0, "value": b"ssh-rsa "},
            {"offset": 0, "value": b"ssh-dss "},
            {"offset": 0, "value": b"-----BEGIN SSH2 PUBLIC KEY-----"},
        ],
    },
    {
        "type": "text/x-putty-private-key",
        "name": "PuTTY private key",
        "pattern": [],
        "magic": [
            {"offset": 0, "value": b"PuTTY-User-Key-File-2:"},
            {"offset": 0, "value": b"PuTTY-User-Key-File-3:"},
        ],
    },
]
