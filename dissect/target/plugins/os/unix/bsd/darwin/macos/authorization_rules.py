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
        ("bytes", "rules_requirement"),
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

CONVERT_TIMESTAMPS = {
    "rules_created": "2001",
    "rules_modified": "2001",
}


class AuthorizationRulesPlugin(Plugin):
    """macOS authorization rules plugin.

    The database located in /var/db/auth.db is used to store permissions to perform sensitive operations.

    References:
        - https://angelica.gitbook.io/hacktricks/macos-hardening/macos-security-and-privilege-escalation/macos-security-protections/macos-authorizations-db-and-authd
    """

    PATH = "/var/db/auth.db"

    def __init__(self, target: Target):
        super().__init__(target)
        self.file = self.target.fs.path(self.PATH) if self.target.fs.path(self.PATH).exists() else None

    def check_compatible(self) -> None:
        if not self.file:
            raise UnsupportedPluginError("No auth.db file found")

    @export(record=AuthorizationRulesRecords)
    def authorization_rules(self) -> Iterator[AuthorizationRulesRecords]:
        """Return macOS authorization rules from the auth.db database.

        The /var/db/auth.db database stores authorization rules used by macOS
        to determine whether a client is allowed to perform privileged operations.

        Yields the following record types:

        .. code-block:: text

            AuthorizationRulesRecord:
                tables (string[]): Names of source tables contributing to the record.
                rules_id (varint): Unique identifier for the rule.
                rules_name (string): Unique name used to identify the authorization rule.
                rules_type (varint): Rule type value.
                rules_class (varint): Rule class defining how the rule is evaluated.
                rules_group (string): User group associated with the rule.
                rules_kofn (varint): "k-of-n" parameter indicating how many subrules must be satisfied.
                rules_timeout (varint): Duration in seconds before the authorization expires.
                rules_flags (varint): Flags modifying rule behavior.
                rules_tries (string): Maximum number of allowed authorization attempts.
                rules_version (varint): Version of the rule.
                rules_created (datetime): Timestamp when the rule was created.
                rules_modified (datetime): Timestamp of the last modification.
                rules_hash (string): Hash value used to verify rule integrity.
                rules_identifier (string): Identifier string used for external reference.
                rules_requirement (bytes): Serialized data defining rule requirements and mechanisms.
                rules_comment (string): Human-readable description of the rule.
                rules_delegates_map (string[]): Delegate mappings for the rule.
                rules_history_timestamp (datetime): Timestamp from the rules_history table.
                rules_history_source (string): Source of the history entry (e.g. authd).
                rules_history_operation (varint): Operation type recorded in rules_history.
                mechanisms_map_m_id (varint): Mechanism identifier from mechanisms_map.
                mechanisms_map_ord (varint): Order of the mechanism within the rule.
                mechanisms_plugin (string): Mechanism plugin name.
                mechanisms_param (string): Mechanism parameter value.
                mechanisms_privileged (varint): Indicates whether the mechanism runs with privileges.
                source (path): Path to the auth.db database file.

            ConfigTableRecord:
                table (string): Name of the source table (config).
                key (string): Configuration key.
                value (string): Stored value associated with the key.
                source (path): Path to the auth.db database file.

            SQLiteSequenceTableRecord:
                table (string): Name of the source table (sqlite_sequence).
                name (string): Name of the table for which the sequence applies.
                seq (varint): Current autoincrement value for the table.
                source (path): Path to the auth.db database file.

        Records are constructed by joining data from the rules,
        rules_history, mechanisms_map, mechanisms, and
        delegates_map tables.

        Multiple records may be produced for a single rule when multiple
        mechanisms or delegate mappings exist.
        """
        yield from build_sqlite_records(
            self, (self.file,), AuthorizationRulesRecords, joins, convert_timestamps=CONVERT_TIMESTAMPS
        )

        # TODO: Add prompts & buttons tables
