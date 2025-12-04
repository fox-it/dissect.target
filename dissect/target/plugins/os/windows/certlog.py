from __future__ import annotations

from typing import TYPE_CHECKING, Union

from dissect.database.ese.tools import certlog
from dissect.database.exception import Error

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path
    from dissect.target.target import Target

CertificateExtensionsRecord = TargetRecordDescriptor(
    "filesystem/windows/certlog/certificate_extension",
    [
        ("datetime", "ts_submittedWhen"),
        ("string", "database")
    ],
)

CertificatesRecord = TargetRecordDescriptor(
    "filesystem/windows/certlog/certificates",
    [
        ("datetime", "ts"),
        ("path", "app"),
        ("string", "user"),
        ("varint", "interface_luid"),
        ("varint", "l2_profile_id"),
        ("varint", "connected_time"),
        ("datetime", "connect_start_time"),
        ("varint", "l2_profile_flags"),
    ],
)

CRLsRecord = TargetRecordDescriptor(
    "filesystem/windows/sru/energy_estimator",
    [
        ("datetime", "ts"),
        ("path", "app"),
        ("string", "user"),
        ("bytes", "binary_data"),
    ],
)

RequestAttributesRecord = TargetRecordDescriptor(
    "filesystem/windows/sru/energy_usage",
    [
        ("datetime", "ts"),
        ("path", "app"),
        ("string", "user"),
        ("varint", "event_timestamp"),
        ("varint", "state_transition"),
        ("varint", "designed_capacity"),
        ("varint", "full_charged_capacity"),
        ("varint", "charge_level"),
        ("varint", "cycle_count"),
        ("varint", "configuration_hash"),
        ("varint", "battery_count"),
        ("varint", "battery_charge_limited"),
    ],
)

RequestsRecord = TargetRecordDescriptor(
    "filesystem/windows/sru/energy_usage_lt",
    [
        ("datetime", "ts"),
        ("path", "app"),
        ("string", "user"),
        ("varint", "active_ac_time"),
        ("varint", "cs_ac_time"),
        ("varint", "active_dc_time"),
        ("varint", "cs_dc_time"),
        ("varint", "active_discharge_time"),
        ("varint", "cs_discharge_time"),
        ("varint", "active_energy"),
        ("varint", "cs_energy"),
        ("varint", "designed_capacity"),
        ("varint", "full_charged_capacity"),
        ("varint", "cycle_count"),
        ("varint", "configuration_hash"),
    ],
)

CertLogRecord = Union[  # noqa: UP007
    RequestsRecord,
    RequestAttributesRecord,
    CRLsRecord,
    CertificatesRecord,
    CertificateExtensionsRecord
]

TRANSFORMS = {}

FIELD_MAPPINGS = {}

class CertLogPlugin(Plugin):
    """Return all available SRUM data stored in the SRUDB.dat.

    The System Resource Usage Monitor (SRUM) stores its information in a SRUDB.dat file. As the names suggests, it
    contains data about resource usage, such as network and memory usage by applications.

    References:
        - https://docs.microsoft.com/en-us/sql/relational-databases/performance-monitor/monitor-resource-usage-system-monitor?view=sql-server-ver15
        - https://blog.1234n6.com/2019/01/
    """

    __namespace__ = "certlog"

    def __init__(self, target: Target):
        super().__init__(target)
        print(f"Is direct {self.target.is_direct}")
        self._certlog_db = []
        for path in self.get_paths():
            try:
                self._certlog_db.append(certlog.CertLog(path.open()))
            except Error as e:
                self.target.log.warning("Error opening Certlog database")
                self.target.log.debug("", exc_info=e)
        print("HERE")

    def _get_paths(self) -> Iterator[Path]:
        """Return all artifact files of interest to the plugin.

        To be implemented by the plugin subclass.
        """
        certlog_dir = self.target.resolve("%windir%/System32/CertLog")
        if certlog_dir.exists():
            yield from certlog_dir.glob('*.edb')

    def check_compatible(self) -> None:
        if not self._certlog_db:
            raise UnsupportedPluginError("No Certlog Database found")

    def read_records(self, table_name: str, record_type: CertLogRecord) -> Iterator[CertLogRecord]:
        for db in self.db:
            table = self._sru.get_table(table_name=table_name)
            if not table:
                self.target.log.warning("Table not found: %s", table_name)
                return iter(())

            columns = [c.name for c in table.columns]
            if columns[:4] != ["AutoIncId", "TimeStamp", "AppId", "UserId"]:
                raise ValueError(f"Unexpected table layout in SRU iteration: {table} ({columns[:4]})")
            columns = columns[1:]

            for entry in self._sru.get_table_entries(table=table):
                values = (entry[name] for name in columns)
                column_values = zip(columns, values, strict=False)

                record_values = {}
                for column, value in column_values:
                    new_value = value
                    if new_value and (transform := TRANSFORMS.get(column)):
                        if isinstance((transformed_value := transform(new_value)), str):
                            new_value = self.target.fs.path(transformed_value)
                        else:
                            new_value = transformed_value
                    new_column = FIELD_MAPPINGS.get(column, column)
                    record_values[new_column] = new_value

                yield record_type(
                    _target=self.target,
                    **record_values,
                )

    @export(record=RequestsRecord)
    def requests(self) -> Iterator[RequestsRecord]:
        """Return the contents of Windows Network Data Usage Monitor table from the SRUDB.dat file.

        Gives insight into the network usage of the system.
        """
        yield from self.read_records("network_data", RequestsRecord)
