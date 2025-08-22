from __future__ import annotations

import random
from unittest.mock import Mock, patch

from dissect.target.filesystems.nc import NetcatListenerFilesystem


def test_nc_filesystem() -> None:
    with patch("socket.socket") as mock_socket:
        mock_client = Mock()

        mock_socket.return_value = mock_socket
        mock_socket.accept.return_value = (mock_client, ("10.69.69.10", 420))

        queue = []

        random.seed(69)

        def mock_sendall(data: bytes) -> None:
            assert queue, "No data in queue"
            assert data == queue[-1][0], f"Sent command does not match expected. Sent: {data}, Expected: {queue[-1][0]}"

        mock_client.sendall = mock_sendall
        mock_client.recv = lambda _: queue.pop(0)[1] if queue else b""

        fs = NetcatListenerFilesystem("hostname", dialect="linux")

        queue.append(
            (
                b"\necho -n 7ccb8c0925cb8818$((700)); (stat '/') 2> >(sed 's/^/4ea81111ab65e99a/;s/$/4ea81111ab65e99a/'); echo -n 7c0328cdc8edba2a$((700))\n",  # noqa: E501
                b"7ccb8c0925cb8818700  File: /\n  Size: 254       \tBlocks: 0          IO Block: 4096   directory\nDevice: 0,38\tInode: 901167      Links: 1\nAccess: (0755/drwxr-xr-x)  Uid: (    0/    root)   Gid: (    0/    root)\nAccess: 2025-05-16 22:42:18.000000000 +0200\nModify: 2025-08-22 11:43:56.903048665 +0200\nChange: 2025-08-22 11:43:56.903048665 +0200\n Birth: 2025-05-19 13:58:46.909076358 +0200\n7c0328cdc8edba2a700",  # noqa: E501
            )
        )
        entry = fs.get("/")

        assert entry.is_dir()
        assert entry.stat().st_mode & 0o777 == 0o755
        assert entry.stat().st_ino == 901167
        assert entry.stat().st_dev == 0x26
        assert entry.stat().st_nlink == 1
        assert entry.stat().st_uid == 0
        assert entry.stat().st_gid == 0
        assert entry.stat().st_size == 254
        assert entry.stat().st_atime == 1747428138.0
        assert entry.stat().st_mtime == 1755855836.903048
        assert entry.stat().st_ctime == 1755855836.903048
        assert entry.stat().st_birthtime == 1747655926.909076
