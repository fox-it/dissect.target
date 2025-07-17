from __future__ import annotations

from dissect.target.plugin import NamespacePlugin

COMMON_IMAGE_FIELDS = [
    ("string", "name"),
    ("string", "tag"),
    ("string", "image_id"),
    ("string", "hash"),
    ("datetime", "created"),
    ("path", "source"),
]

COMMON_CONTAINER_FIELDS = [
    ("string", "container_id"),
    ("string", "image"),
    ("string", "image_id"),
    ("string", "command"),
    ("datetime", "created"),
    ("boolean", "running"),
    ("varint", "pid"),
    ("datetime", "started"),
    ("datetime", "finished"),
    ("string[]", "ports"),
    ("string", "names"),
    ("string[]", "volumes"),
    ("string[]", "environment"),
    ("path", "mount_path"),
    ("path", "config_path"),
    ("path", "image_path"),
    ("path", "source"),
]

COMMON_LOG_FIELDS = [
    ("datetime", "ts"),
    ("string", "container"),
    ("string", "stream"),
    ("string", "message"),
    ("path", "source"),
]


class ContainerPlugin(NamespacePlugin):
    __namespace__ = "container"
