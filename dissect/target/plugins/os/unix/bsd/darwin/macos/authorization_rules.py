from __future__ import annotations

from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.plugins.os.unix.bsd.darwin.macos.helpers.build_records import build_sqlite_records

if TYPE_CHECKING:
    from collections.abc import Iterator

    from dissect.target import Target

AuthorizationRulesRecord = TargetRecordDescriptor(
    "macos/authorization_rules",
    [
        ("string[]", "tables"),
        ("varint", "rules_id"),
        ("string", "rules_name"),
        ("varint", "rules_type"),
        ("varint", "rules_class"),
        ("string", "rules_group"),
        ("varint", "rules_kofn"),
        ("varint", "rules_timeout"),
        ("varint", "rules_flags"),
        ("string", "rules_tries"),
        ("varint", "rules_version"),
        ("datetime", "rules_created"),
        ("datetime", "rules_modified"),
        ("string", "rules_hash"),
        ("string", "rules_identifier"),
        ("string", "rules_requirement"),
        ("string", "rules_comment"),
        ("string[]", "rules_delegates_map"),
        ("datetime", "rules_history_timestamp"),
        ("string", "rules_history_source"),
        ("varint", "rules_history_operation"),
        ("varint", "mechanisms_map_m_id"),
        ("varint", "mechanisms_map_ord"),
        ("string", "mechanisms_plugin"),
        ("string", "mechanisms_param"),
        ("varint", "mechanisms_privileged"),
        ("path", "source"),
    ],
)

ConfigTableRecord = TargetRecordDescriptor(
    "macos/authorization_rules/config",
    [
        ("string", "table"),
        ("string", "key"),
        ("string", "value"),
        ("path", "source"),
    ],
)

SQLiteSequenceTableRecord = TargetRecordDescriptor(
    "macos/authorization_rules/sqlite_sequence",
    [
        ("string", "table"),
        ("string", "name"),
        ("varint", "seq"),
        ("path", "source"),
    ],
)

AuthorizationRulesRecords = (
    AuthorizationRulesRecord,
    ConfigTableRecord,
    SQLiteSequenceTableRecord,
)

joins = (
    {"table1": "rules", "key1": "name", "table2": "rules_history", "key2": "rule", "join": "iterate"},
    {"table1": "rules", "key1": "version", "table2": "rules_history", "key2": "version", "join": "ignore"},
    {"table1": "rules", "key1": "id", "table2": "mechanisms_map", "key2": "r_id", "join": "iterate"},
    {"table1": "mechanisms_map", "key1": "m_id", "table2": "mechanisms", "key2": "id", "join": "iterate"},
    {"table1": "rules", "key1": "id", "table2": "delegates_map", "key2": "r_id", "join": "nested"},
)


class AuthorizationRulesPlugin(Plugin):
    """macOS authorization rules plugin."""

    PATH = "/var/db/auth.db"

    def __init__(self, target: Target):
        super().__init__(target)
        self.file = None
        self._resolve_file()

    def _resolve_file(self) -> None:
        path = self.target.fs.path(self.PATH)
        if path.exists():
            self.file = path

    def check_compatible(self) -> None:
        if not self.file:
            raise UnsupportedPluginError("No auth.db file found")

    @export(record=AuthorizationRulesRecords)
    def authorization_rules(self) -> Iterator[AuthorizationRulesRecords]:
        """Yield authorization rules information."""
        yield from build_sqlite_records(self, (self.file,), AuthorizationRulesRecords, joins)

        # Still missing prompts & buttons tables
