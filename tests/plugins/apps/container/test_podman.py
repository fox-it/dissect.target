from __future__ import annotations

import textwrap
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import pytest

from dissect.target.plugins.apps.container.podman import PodmanPlugin
from tests._utils import absolute_path

if TYPE_CHECKING:
    from dissect.target.filesystem import VirtualFilesystem
    from dissect.target.target import Target


@pytest.fixture
def target_unix_podman(target_unix_users: Target, fs_unix: VirtualFilesystem) -> Target:
    for id, file in [
        ("ae30bde8949f4d4e5b90ad839bbbaffa03db7d9eccbcad7163c34665084d1b70", "httpd"),
        ("4e82f2c6d0ba1a41eacaa5622fcbb9c4e22c9531e6345291a68f6a2219ac9d1a", "nginx"),
        ("bb44c71b8e6c00ba0d4bd483ede69ec32930ca8a30abee4a7f2aadb39cee4988", "debian"),
    ]:
        fs_unix.map_file(
            f"/home/user/.local/share/containers/storage/overlay-containers/{id}/userdata/config.json",
            absolute_path(f"_data/plugins/apps/container/podman/config.json-{file}"),
        )

    fs_unix.map_file(
        "/home/user/.local/share/containers/storage/db.sql",
        absolute_path("_data/plugins/apps/container/podman/db.sql"),
    )

    fs_unix.map_file(
        "/home/user/.local/share/containers/storage/overlay-images/images.json",
        absolute_path("_data/plugins/apps/container/podman/images.json"),
    )

    return target_unix_users


def test_podman_images(target_unix_podman: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we can detect Podman images on a target based on an ``images.json`` file.

    Structure of a Podman OCI image on disk::

        $PODMAN/storage/overlay-images/
                                      /images.json
                                      /images.lock
                                      /<HASH>/
                                             /=<BASE64>
                                             /manifest
    """

    target_unix_podman.add_plugin(PodmanPlugin)
    records = list(target_unix_podman.container.images())

    assert sorted([f"{r.name}:{r.tag}" for r in records]) == [
        "docker.io/library/alpine:latest",
        "docker.io/library/debian:latest",
        "docker.io/library/nginx:latest",
        "docker.io/library/ubuntu:latest",
    ]

    assert records[0].name == "docker.io/library/nginx"
    assert records[0].tag == "latest"
    assert records[0].image_id == "4cad75abc83d"
    assert records[0].hash == "4cad75abc83d5ca6ee22053d85850676eaef657ee9d723d7bef61179e1e1e485"
    assert records[0].created == datetime(2025, 2, 5, 21, 27, 16, tzinfo=timezone.utc)
    assert records[0].source == "/home/user/.local/share/containers/storage/overlay-images/images.json"


def test_podman_containers(target_unix_podman: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we can detect Podman containers on a target based on a SQLite3 database."""

    target_unix_podman.add_plugin(PodmanPlugin)
    records = list(target_unix_podman.container.containers())

    assert sorted([r.names for r in records]) == [
        "boring_mirzakhani",
        "fervent_proskuriakova",
        "hardcore_khayyam",
        "zen_taussig",
    ]

    assert records[0].container_id == "bb44c71b8e6c00ba0d4bd483ede69ec32930ca8a30abee4a7f2aadb39cee4988"
    assert records[0].image == "docker.io/library/debian:latest"
    assert records[0].image_id == "1fd9a3236e02e50084b18aff689d466641759f4e9e5fee930e194a605081be65"
    assert records[0].command == "bash"
    assert records[0].created == datetime(2025, 4, 9, 11, 37, 41, 694673, tzinfo=timezone.utc)
    assert records[0].running
    assert records[0].pid == 58526
    assert records[0].started == datetime(2025, 4, 9, 11, 37, 42, 68128, tzinfo=timezone.utc)
    assert records[0].finished == datetime(1, 1, 1, tzinfo=timezone.utc)
    assert records[0].ports == []
    assert records[0].names == "hardcore_khayyam"
    assert records[0].volumes == ["/tmp/host-folder:/data"]
    assert records[0].environment == [
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "container=podman",
        "TERM=xterm",
    ]
    assert (
        records[0].mount_path
        == "/home/user/.local/share/containers/storage/overlay/f351129587e2bb1da9ba4f03dcd22e1c838cd4f20dcc70e6da72381d2905b913"  # noqa: E501
    )
    assert (
        records[0].config_path
        == "/home/user/.local/share/containers/storage/overlay-containers/bb44c71b8e6c00ba0d4bd483ede69ec32930ca8a30abee4a7f2aadb39cee4988/userdata/config.json"  # noqa: E501
    )
    assert (
        records[0].image_path
        == "/home/user/.local/share/containers/storage/overlay-images/1fd9a3236e02e50084b18aff689d466641759f4e9e5fee930e194a605081be65"  # noqa: E501
    )
    assert records[0].source == "/home/user/.local/share/containers/storage/db.sql"

    assert records[-1].image == "docker.io/library/nginx:latest"
    assert records[-1].command == "nginx -g daemon off;"
    assert records[-1].volumes == ["/tmp/host-folder/host-file.txt:/data/container-file.txt"]
    assert records[-1].ports == ["0.0.0.0:8080->80/tcp"]


def test_podman_logs(target_unix_podman: Target, fs_unix: VirtualFilesystem) -> None:
    """Test if we can parse non-default Podman json-file log driver entries."""

    fs_unix.map_file(
        "/home/user/.local/share/containers/storage/overlay-containers/350f9f5489aebd1d33aa9ed17450270f5a5502d8548df8085d88eccccf2182f1/userdata/ctr.log",
        absolute_path("_data/plugins/apps/container/podman/ctr.log"),
    )

    target_unix_podman.add_plugin(PodmanPlugin)
    records = list(target_unix_podman.container.logs())

    assert len(records) == 51

    assert records[0].ts == datetime(2025, 7, 17, 13, 59, 55, 516060, tzinfo=timezone.utc)
    assert records[0].container == "350f9f5489aebd1d33aa9ed17450270f5a5502d8548df8085d88eccccf2182f1"
    assert records[0].stream == "stdout"
    assert records[0].message == "\x1b[?2004h\x1b]0;root@350f9f5489ae: /\x07root@350f9f5489ae:/# id"
    assert (
        records[0].source
        == "/home/user/.local/share/containers/storage/overlay-containers/350f9f5489aebd1d33aa9ed17450270f5a5502d8548df8085d88eccccf2182f1/userdata/ctr.log"  # noqa: E501
    )

    assert "\n".join([r.message for r in records]) == textwrap.dedent("""\
    \x1b[?2004h\x1b]0;root@350f9f5489ae: /\x07root@350f9f5489ae:/# id
    uid=0(root) gid=0(root) groups=0(root)
    \x1b[?2004l\x1b[?2004h\x1b]0;root@350f9f5489ae: /\x07root@350f9f5489ae:/# whoami
    root
    \x1b[?2004l\x1b[?2004h\x1b]0;root@350f9f5489ae: /\x07root@350f9f5489ae:/# ls -lah .
    total 56K
    dr-xr-xr-x   1 root   root    4.0K Jul 17 13:59 \x1b[0m\x1b[01;34m.\x1b[0m
    dr-xr-xr-x   1 root   root    4.0K Jul 17 13:59 \x1b[01;34m..\x1b[0m
    lrwxrwxrwx   1 root   root       7 Apr 22  2024 \x1b[01;36mbin\x1b[0m -> \x1b[01;34musr/bin\x1b[0m
    drwxr-xr-x   2 root   root    4.0K Apr 22  2024 \x1b[01;34mboot\x1b[0m
    drwxr-xr-x   5 root   root     360 Jul 17 13:59 \x1b[01;34mdev\x1b[0m
    drwxr-xr-x   1 root   root    4.0K Jul 17 13:59 \x1b[01;34metc\x1b[0m
    drwxr-xr-x   3 root   root    4.0K Jul 14 14:14 \x1b[01;34mhome\x1b[0m
    lrwxrwxrwx   1 root   root       7 Apr 22  2024 \x1b[01;36mlib\x1b[0m -> \x1b[01;34musr/lib\x1b[0m
    lrwxrwxrwx   1 root   root       9 Apr 22  2024 \x1b[01;36mlib64\x1b[0m -> \x1b[01;34musr/lib64\x1b[0m
    drwxr-xr-x   2 root   root    4.0K Jul 14 14:08 \x1b[01;34mmedia\x1b[0m
    drwxr-xr-x   2 root   root    4.0K Jul 14 14:08 \x1b[01;34mmnt\x1b[0m
    drwxr-xr-x   2 root   root    4.0K Jul 14 14:08 \x1b[01;34mopt\x1b[0m
    dr-xr-xr-x 278 nobody nogroup    0 Jul 17 13:59 \x1b[01;34mproc\x1b[0m
    drwx------   2 root   root    4.0K Jul 14 14:14 \x1b[01;34mroot\x1b[0m
    drwxr-xr-x   1 root   root    4.0K Jul 17 13:59 \x1b[01;34mrun\x1b[0m
    lrwxrwxrwx   1 root   root       8 Apr 22  2024 \x1b[01;36msbin\x1b[0m -> \x1b[01;34musr/sbin\x1b[0m
    drwxr-xr-x   2 root   root    4.0K Jul 14 14:08 \x1b[01;34msrv\x1b[0m
    dr-xr-xr-x  13 nobody nogroup    0 Jul 17 13:59 \x1b[01;34msys\x1b[0m
    drwxrwxrwt   2 root   root    4.0K Jul 14 14:14 \x1b[30;42mtmp\x1b[0m
    drwxr-xr-x  12 root   root    4.0K Jul 14 14:08 \x1b[01;34musr\x1b[0m
    drwxr-xr-x  11 root   root    4.0K Jul 14 14:14 \x1b[01;34mvar\x1b[0m
    \x1b[?2004l\x1b[?2004h\x1b]0;root@350f9f5489ae: /\x07root@350f9f5489ae:/# cat /etc/passwd
    root:x:0:0:root:/root:/bin/bash
    daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
    bin:x:2:2:bin:/bin:/usr/sbin/nologin
    sys:x:3:3:sys:/dev:/usr/sbin/nologin
    sync:x:4:65534:sync:/bin:/bin/sync
    games:x:5:60:games:/usr/games:/usr/sbin/nologin
    man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
    lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
    mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
    news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
    uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
    proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
    www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
    backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
    list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
    irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
    _apt:x:42:65534::/nonexistent:/usr/sbin/nologin
    nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
    ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash
    \x1b[?2004l\x1b[?2004h\x1b]0;root@350f9f5489ae: /\x07root@350f9f5489ae:/# echo "hidden\x08 \x08\x08 \x08\x08 \x08\x08 \x08\x08 \x08\x08 \x08hello!"
    \x1b[?2004l
    \x1b[?2004l
    exit""")  # noqa: E501
