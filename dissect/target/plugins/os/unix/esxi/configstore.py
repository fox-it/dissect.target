from __future__ import annotations

import json as jsonlib
from typing import TYPE_CHECKING, Any

from dissect.database.sqlite3 import SQLite3

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import Plugin, internal

if TYPE_CHECKING:
    from pathlib import Path

    from dissect.target.target import Target


class ConfigstorePlugin(Plugin):
    """Plugin to interact with the ESXi configstore."""

    __namespace__ = "configstore"

    def __init__(self, target: Target):
        super().__init__(target)
        self._configstore = None

        # ESXi 7 introduced the configstore
        # It's made available at /etc/vmware/configstore/current-store-1 during boot, but stored at
        # the path used below in local.tgz
        if (path := target.fs.path("/var/lib/vmware/configstore/backup/current-store-1")).exists():
            self._configstore = parse_config_store(path)

    def check_compatible(self) -> None:
        if self.target.os != "esxi":
            raise UnsupportedPluginError("ESXi specific plugin loaded on non-ESXi target")

        if not self._configstore:
            raise UnsupportedPluginError("ESXi configstore not found on target")

    @internal
    def get(self, key: str, default: Any = None) -> dict[str, Any]:
        """Get configstore value for the specified key."""
        return self._configstore.get(key, default)


def parse_config_store(path: Path) -> dict[str, Any]:
    with SQLite3(path) as db:
        store = {}

        if table := db.table("Config"):
            for row in table.rows():
                component_name = row.Component
                config_group_name = row.ConfigGroup
                value_group_name = row.Name
                identifier_name = row.Identifier

                if component_name not in store:
                    store[component_name] = {}
                component = store[component_name]

                if config_group_name not in component:
                    component[config_group_name] = {}
                config_group = component[config_group_name]

                if value_group_name not in config_group:
                    config_group[value_group_name] = {}
                value_group = config_group[value_group_name]

                if identifier_name not in value_group:
                    value_group[identifier_name] = {}
                identifier = value_group[identifier_name]

                identifier["modified_time"] = row.ModifiedTime
                identifier["creation_time"] = row.CreationTime
                identifier["version"] = row.Version
                identifier["success"] = row.Success
                identifier["auto_conf_value"] = jsonlib.loads(row.AutoConfValue) if row.AutoConfValue else None
                identifier["user_value"] = jsonlib.loads(row.UserValue) if row.UserValue else None
                identifier["vital_value"] = jsonlib.loads(row.VitalValue) if row.VitalValue else None
                identifier["cached_value"] = jsonlib.loads(row.CachedValue) if row.CachedValue else None
                identifier["desired_value"] = jsonlib.loads(row.DesiredValue) if row.DesiredValue else None
                identifier["revision"] = row.Revision

        return store
