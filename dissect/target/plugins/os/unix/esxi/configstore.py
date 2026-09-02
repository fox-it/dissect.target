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
        self._configstore = {}
        path = None
        # ESXi 7 introduced the configstore
        # It's made available at /etc/vmware/configstore/current-store-1 during boot, but stored at
        # /var/lib/vmware/configstore/backup/current-store-1 in local.tgz
        # On live collection (uac, vm-support), this file is located at the /etc path
        for path in ("/etc/vmware/configstore/current-store-1", "/var/lib/vmware/configstore/backup/current-store-1"):
            if (p := self.target.fs.path(path)).exists():
                self.path = p
                self._configstore = parse_config_store(p)

    def check_compatible(self) -> None:
        # NOTE: Unable to use OS specific functions here, as this method can be called in ESXiPlugin.create
        if not self._configstore:
            raise UnsupportedPluginError("ESXi configstore not found on target")

    @internal
    def get(
        self,
        component: str,
        config_group: str | None = None,
        value_group: str | None = None,
        identifier: str | None = None,
        default: Any = None,
    ) -> dict[str, Any] | Any:
        """Get configstore value for the specified key.
        Subkey order is component -> config_group -> value_group -> identifier.

        Sub subkey are used only previous subkey are defined. E.g. is value_group is None, identifier will be ignored.
        """
        step_value = self._configstore
        for step_name in [component, config_group, value_group, identifier]:
            if step_name is None:
                return step_value
            if step_name not in step_value:
                return default
            step_value = step_value.get(step_name)
        return step_value


def parse_config_store(path: Path) -> dict[str, Any]:
    """Parse ESXi configstore and create a tree-like dictionary with values.


    Note: Configstore is a SQlite3 Db with the following schema

        .. code-block:: sql

            CREATE TABLE Config(Component TEXT
                ConfigGroup TEXT
                Name TEXT
                Identifier TEXT NOT NULL DEFAULT ''
                ModifiedTime DATETIME DEFAULT (datetime(CURRENT_TIMESTAMP))
                CreationTime DATETIME
                Version TEXT DEFAULT ''
                Success BOOLEAN DEFAULT 1
                AutoConfValue TEXT
                 UserValue TEXT
                 VitalValue TEXT
                 CachedValue TEXT
                 DesiredValue TEXT
                 Revision INTEGER DEFAULT 0
                 PRIMARY KEY(Component
                     ConfigGroup
                     Name
                     Identifier)
            );
    """
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
