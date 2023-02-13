from __future__ import annotations

import gzip
import os
import socket
from typing import BinaryIO, Iterator, Optional

from dissect.target.filesystem import Filesystem
from dissect.target.helpers.record import UnixUserRecord
from dissect.target.plugin import OperatingSystem, export
from dissect.target.plugins.os.unix.linux._os import LinuxPlugin
from dissect.target.target import Target


def netmask_to_bits(netmask):
    socket.inet_aton(netmask)


def parselines(fp):
    parts = []
    string = None

    for line in fp:
        line = line.strip()

        for parsed_line in line.split(" "):
            if parsed_line.startswith('"'):
                if parsed_line.endswith('"'):
                    parts.append(parsed_line[1:-1])
                else:
                    string = [parsed_line[1:]]
            elif parsed_line.endswith('"') and parsed_line[-2] != "\\":
                string.append(parsed_line[:-1])
                parts.append(" ".join(string))
                string = None
            elif string:
                string.append(parsed_line)
            else:
                parts.append(parsed_line)

        if string:
            string.append("\n")

        if parts and not string:
            yield parts
            parts = []


class ConfigNode:
    children = None

    def __init__(self):
        self.children = {}

    def set(self, path, value):
        n = self

        for part in path[:-1]:
            if part not in n.children:
                n.children[part] = ConfigNode()
            n = n.children[part]

        n.children[path[-1]] = value

    def __contains__(self, attr):
        return attr in self.children

    def __getattr__(self, attr):
        return self.children[attr]

    def __getitem__(self, index):
        return self.children[index]

    def items(self):
        return self.children.items()


class FortigateConfig:
    def __init__(self, fp):
        self.config = ConfigNode()

        stack = []

        for p in parselines(fp):
            # print stack
            cmd = p[0]
            # print p

            if cmd == "config":
                if p[1] == "vdom" and stack == [["vdom"]]:
                    continue

                stack.append(p[1:])

            elif cmd == "edit":
                stack.append(p[1:])

            elif cmd == "end":
                stack.pop()

            elif cmd == "next":
                stack.pop()

            elif cmd == "set":
                path = []
                for part in stack:
                    path += part

                path.append(p[1])
                self.config.set(path, p[2:])


class FortigatePlugin(LinuxPlugin):
    def __init__(self, target: Target):
        super().__init__(target)
        self.target = target

        fp = self.open_config()
        self.config = FortigateConfig(fp)
        fp.close()

    @export(record=UnixUserRecord)
    def users(self) -> Iterator[UnixUserRecord]:
        raise NotImplementedError()

    @export(property=True)
    def os(self) -> str:
        return OperatingSystem.FORTIGATE.value

    def open_config(self) -> BinaryIO:
        fs = self.target.filesystems[0]
        if fs.exists("system.conf"):
            fp = fs.open("system.conf")
        elif fs.exists("config/sys_global.conf.gz"):
            entry = fs.get("config/sys_global.conf.gz")
            if entry.is_symlink():
                entry = fs.get("config/" + os.path.basename(entry.readlink()))

            fp = entry.open()
            fp = gzip.GzipFile(fileobj=fp)

        return fp

    @classmethod
    def detect(cls, target: Target) -> Optional[Filesystem]:
        for fs in target.filesystems:
            if fs.exists("/config") and fs.exists("/rootfs.gz"):
                return fs

        return None

    @classmethod
    def create(cls, target: Target, sysvol: Filesystem) -> FortigatePlugin:
        target.fs.mount("/", sysvol)
        return cls(target)

    @export(property=True)
    def hostname(self) -> str:
        return self.config.config.system["global"].hostname[0]

    @export(property=True)
    def ips(self) -> list[str]:
        r = []
        for _, conf in self.config.config.system.interface.children.items():
            if "ip" in conf:
                r.append(conf.ip[0])
        return r

    @export(property=True)
    def version(self) -> str:
        fp = self.open_config()
        r = fp.readline().split("=")[1].rsplit("-", 1)[0]
        fp.close()

        return "Fortigate " + r
