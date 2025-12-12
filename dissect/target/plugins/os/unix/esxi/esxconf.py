from __future__ import annotations

import json as jsonlib
from typing import TYPE_CHECKING, TextIO, TypeAlias

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import Plugin, arg, export, internal

if TYPE_CHECKING:
    from dissect.target.target import Target

_EsxConf: TypeAlias = dict[str, "str | int | bool | _EsxConf"]


class EsxConfPlugin(Plugin):
    """Plugin to interact with ``esxconf`` configuration."""

    __namespace__ = "esxconf"

    def __init__(self, target: Target):
        super().__init__(target)
        self._config = None

        if (path := target.fs.path("/etc/vmware/esx.conf")).exists():
            with path.open("rt") as fh:
                self._config = parse_esx_conf(fh)

    def check_compatible(self) -> None:
        if self.target.os != "esxi":
            raise UnsupportedPluginError("ESXi specific plugin loaded on non-ESXi target")

        if not self._config:
            raise UnsupportedPluginError("esx.conf not found on target")

    def _cfg(self, path: str) -> str | int | bool | _EsxConf | None:
        if not self._config:
            self.target.log.warning("No ESXi config!")
            return None

        value_name = path.strip("/").split("/")[-1]
        obj = _traverse(path, self._config)

        if not value_name and obj:
            return obj

        return obj.get(value_name) if obj else None

    @internal
    def get(self, path: str) -> str | int | bool | _EsxConf | None:
        """Get esxconf value at the specified path."""
        return self._cfg(path)

    @export(output="none")
    @arg("path", help="config path")
    @arg("-j", "--json", action="store_true", help="output in JSON format")
    def __call__(self, path: str, json: bool) -> None:
        """Dump esxconf value at the specified path."""
        obj = self._cfg(path)

        if json:
            print(jsonlib.dumps(obj, indent=4, sort_keys=True))
        else:
            print(obj)


def parse_esx_conf(fh: TextIO) -> _EsxConf:
    config = {}
    for line in fh:
        if not (line := line.strip()):
            continue

        key, _, value = line.partition("=")
        key = key.strip().strip("/")
        value = value.strip().strip('"')

        if value == "true":
            value = True
        elif value == "false":
            value = False
        elif value.isnumeric():
            value = int(value)

        value_name = key.split("/")[-1]
        obj = _traverse(key, config, create=True)
        obj[value_name] = value

    return config


def _traverse(path: str, obj: _EsxConf, create: bool = False) -> _EsxConf | None:
    parts = path.strip("/").split("/")
    path_parts = parts[:-1]
    for part in path_parts:
        array_idx = None
        if part.endswith("]"):
            part, _, rest = part.partition("[")
            array_idx = rest.strip("]")

        if part not in obj:
            if create:
                obj[part] = {}
            else:
                return None

        obj = obj[part]
        if array_idx:
            if array_idx not in obj:
                if create:
                    obj[array_idx] = {}
                else:
                    return None
            obj = obj[array_idx]

    return obj
