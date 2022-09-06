from dissect.esedb.exceptions import Error
from dissect.esedb.tools import sru
from flow.record.fieldtypes import uri

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export


NetworkDataRecord = TargetRecordDescriptor(
    "filesystem/windows/sru/network_data",
    [
        ("datetime", "ts"),
        ("uri", "app"),
        ("string", "user"),
        ("varint", "interface_luid"),
        ("varint", "l2_profile_id"),
        ("varint", "l2_profile_flags"),
        ("varint", "bytes_sent"),
        ("varint", "bytes_recvd"),
    ],
)

NetworkConnectivityRecord = TargetRecordDescriptor(
    "filesystem/windows/sru/network_connectivity",
    [
        ("datetime", "ts"),
        ("uri", "app"),
        ("string", "user"),
        ("varint", "interface_luid"),
        ("varint", "l2_profile_id"),
        ("varint", "connected_time"),
        ("datetime", "connect_start_time"),
        ("varint", "l2_profile_flags"),
    ],
)

EnergyEstimatorRecord = TargetRecordDescriptor(
    "filesystem/windows/sru/energy_estimator",
    [
        ("datetime", "ts"),
        ("uri", "app"),
        ("string", "user"),
        ("bytes", "binary_data"),
    ],
)

EnergyUsageRecord = TargetRecordDescriptor(
    "filesystem/windows/sru/energy_usage",
    [
        ("datetime", "ts"),
        ("uri", "app"),
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

EnergyUsageLTRecord = TargetRecordDescriptor(
    "filesystem/windows/sru/energy_usage_lt",
    [
        ("datetime", "ts"),
        ("uri", "app"),
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

ApplicationRecord = TargetRecordDescriptor(
    "filesystem/windows/sru/application",
    [
        ("datetime", "ts"),
        ("uri", "app"),
        ("string", "user"),
        ("varint", "foreground_cycle_time"),
        ("varint", "background_cycle_time"),
        ("varint", "face_time"),
        ("varint", "foreground_context_switches"),
        ("varint", "background_context_switches"),
        ("varint", "foreground_bytes_read"),
        ("varint", "foreground_bytes_written"),
        ("varint", "foreground_num_read_operations"),
        ("varint", "foreground_num_write_operations"),
        ("varint", "foreground_number_of_flushes"),
        ("varint", "background_bytes_read"),
        ("varint", "background_bytes_written"),
        ("varint", "background_num_read_operations"),
        ("varint", "background_num_write_operations"),
        ("varint", "background_number_of_flushes"),
    ],
)

PushNotificationRecord = TargetRecordDescriptor(
    "filesystem/windows/sru/push_notification",
    [
        ("datetime", "ts"),
        ("uri", "app"),
        ("string", "user"),
        ("varint", "notification_type"),
        ("varint", "payload_size"),
        ("varint", "network_type"),
    ],
)

ApplicationTimelineRecord = TargetRecordDescriptor(
    "filesystem/windows/sru/application_timeline",
    [
        ("datetime", "ts"),
        ("uri", "app"),
        ("string", "user"),
        ("varint", "flags"),
        ("datetime", "end_time"),
        ("varint", "duration_ms"),
        ("varint", "span_ms"),
        ("varint", "timeline_end"),
        ("varint", "in_focus_timeline"),
        ("varint", "user_input_timeline"),
        ("varint", "comp_rendered_timeline"),
        ("varint", "comp_dirtied_timeline"),
        ("varint", "comp_propagated_timeline"),
        ("varint", "audio_in_timeline"),
        ("varint", "audio_out_timeline"),
        ("varint", "cpu_timeline"),
        ("varint", "disk_timeline"),
        ("varint", "network_timeline"),
        ("varint", "mbb_timeline"),
        ("varint", "in_focus_s"),
        ("varint", "psm_foreground_s"),
        ("varint", "user_input_s"),
        ("varint", "comp_rendered_s"),
        ("varint", "comp_dirtied_s"),
        ("varint", "comp_propagated_s"),
        ("varint", "audio_in_s"),
        ("varint", "audio_out_s"),
        ("varint", "cycles"),
        ("varint", "cycles_breakdown"),
        ("varint", "cycles_attr"),
        ("varint", "cycles_attr_breakdown"),
        ("varint", "cycles_wob"),
        ("varint", "cycles_wob_breakdown"),
        ("varint", "disk_raw"),
        ("varint", "network_tail_raw"),
        ("varint", "network_bytes_raw"),
        ("varint", "mbb_tail_raw"),
        ("varint", "mbb_bytes_raw"),
        ("varint", "display_required_s"),
        ("varint", "display_required_timeline"),
        ("varint", "keyboard_input_timeline"),
        ("varint", "keyboard_input_s"),
        ("varint", "mouse_input_s"),
    ],
)

VfuRecord = TargetRecordDescriptor(
    "filesystem/windows/sru/vfu",
    [
        ("datetime", "ts"),
        ("uri", "app"),
        ("string", "user"),
        ("varint", "flags"),
        ("varint", "start_time"),
        ("varint", "end_time"),
        ("bytes", "usage"),
    ],
)

SdpVolumeProviderRecord = TargetRecordDescriptor(
    "filesystem/windows/sru/sdp_volume_provider",
    [
        ("datetime", "ts"),
        ("uri", "app"),
        ("string", "user"),
        ("varint", "total"),
        ("varint", "used"),
    ],
)

SdpPhysicalDiskProviderRecord = TargetRecordDescriptor(
    "filesystem/windows/sru/sdp_physical_disk_provider",
    [
        ("datetime", "ts"),
        ("uri", "app"),
        ("string", "user"),
        ("varint", "size_in_bytes"),
    ],
)

SdpCpuProviderRecord = TargetRecordDescriptor(
    "filesystem/windows/sru/sdp_cpu_provider",
    [
        ("datetime", "ts"),
        ("uri", "app"),
        ("string", "user"),
        ("varint", "processor_time"),
    ],
)

SdpNetworkProviderRecord = TargetRecordDescriptor(
    "filesystem/windows/sru/sdp_network_provider",
    [
        ("datetime", "ts"),
        ("uri", "app"),
        ("string", "user"),
        ("varint", "bytes_inbound"),
        ("varint", "bytes_outbound"),
        ("varint", "bytes_total"),
    ],
)

FIELD_MAPPINGS = {
    "ActiveAcTime": "active_ac_time",
    "ActiveDcTime": "active_dc_time",
    "ActiveDischargeTime": "active_discharge_time",
    "ActiveEnergy": "active_energy",
    "AppId": "app",
    "AudioInS": "audio_in_s",
    "AudioInTimeline": "audio_in_timeline",
    "AudioOutS": "audio_out_s",
    "AudioOutTimeline": "audio_out_timeline",
    "BackgroundBytesRead": "background_bytes_read",
    "BackgroundBytesWritten": "background_bytes_written",
    "BackgroundContextSwitches": "background_context_switches",
    "BackgroundCycleTime": "background_cycle_time",
    "BackgroundNumReadOperations": "background_num_read_operations",
    "BackgroundNumWriteOperations": "background_num_write_operations",
    "BackgroundNumberOfFlushes": "background_number_of_flushes",
    "BatteryChargeLimited": "battery_charge_limited",
    "BatteryCount": "battery_count",
    "BinaryData": "binary_data",
    "BytesInBound": "bytes_inbound",
    "BytesOutBound": "bytes_outbound",
    "BytesRecvd": "bytes_recvd",
    "BytesSent": "bytes_sent",
    "BytesTotal": "bytes_total",
    "ChargeLevel": "charge_level",
    "CompDirtiedS": "comp_dirtied_s",
    "CompDirtiedTimeline": "comp_dirtied_timeline",
    "CompPropagatedS": "comp_propagated_s",
    "CompPropagatedTimeline": "comp_propagated_timeline",
    "CompRenderedS": "comp_rendered_s",
    "CompRenderedTimeline": "comp_rendered_timeline",
    "ConfigurationHash": "configuration_hash",
    "ConnectStartTime": "connect_start_time",
    "ConnectedTime": "connected_time",
    "CpuTimeline": "cpu_timeline",
    "CsAcTime": "cs_ac_time",
    "CsDcTime": "cs_dc_time",
    "CsDischargeTime": "cs_discharge_time",
    "CsEnergy": "cs_energy",
    "CycleCount": "cycle_count",
    "Cycles": "cycles",
    "CyclesAttr": "cycles_attr",
    "CyclesAttrBreakdown": "cycles_attr_breakdown",
    "CyclesBreakdown": "cycles_breakdown",
    "CyclesWOB": "cycles_wob",
    "CyclesWOBBreakdown": "cycles_wob_breakdown",
    "DesignedCapacity": "designed_capacity",
    "DiskRaw": "disk_raw",
    "DiskTimeline": "disk_timeline",
    "DisplayRequiredS": "display_required_s",
    "DisplayRequiredTimeline": "display_required_timeline",
    "DurationMS": "duration_ms",
    "EndTime": "end_time",
    "EventTimestamp": "event_timestamp",
    "FaceTime": "face_time",
    "Flags": "flags",
    "ForegroundBytesRead": "foreground_bytes_read",
    "ForegroundBytesWritten": "foreground_bytes_written",
    "ForegroundContextSwitches": "foreground_context_switches",
    "ForegroundCycleTime": "foreground_cycle_time",
    "ForegroundNumReadOperations": "foreground_num_read_operations",
    "ForegroundNumWriteOperations": "foreground_num_write_operations",
    "ForegroundNumberOfFlushes": "foreground_number_of_flushes",
    "FullChargedCapacity": "full_charged_capacity",
    "InFocusS": "in_focus_s",
    "InFocusTimeline": "in_focus_timeline",
    "InterfaceLuid": "interface_luid",
    "KeyboardInputS": "keyboard_input_s",
    "KeyboardInputTimeline": "keyboard_input_timeline",
    "L2ProfileFlags": "l2_profile_flags",
    "L2ProfileId": "l2_profile_id",
    "MBBBytesRaw": "mbb_bytes_raw",
    "MBBTailRaw": "mbb_tail_raw",
    "MBBTimeline": "mbb_timeline",
    "MouseInputS": "mouse_input_s",
    "NetworkBytesRaw": "network_bytes_raw",
    "NetworkTailRaw": "network_tail_raw",
    "NetworkTimeline": "network_timeline",
    "NetworkType": "network_type",
    "NotificationType": "notification_type",
    "PSMForegroundS": "psm_foreground_s",
    "PayloadSize": "payload_size",
    "ProcessorTime": "processor_time",
    "SizeInBytes": "size_in_bytes",
    "SpanMS": "span_ms",
    "StartTime": "start_time",
    "StateTransition": "state_transition",
    "TimeStamp": "ts",
    "TimelineEnd": "timeline_end",
    "Total": "total",
    "Usage": "usage",
    "Used": "used",
    "UserId": "user",
    "UserInputS": "user_input_s",
    "UserInputTimeline": "user_input_timeline",
}


def transform_app_id(value):
    if value is not None:
        if isinstance(value, bytes):
            value = value.decode()
        else:
            value = str(value)
        value = uri.from_windows(value)
    return value


TRANSFORMS = {
    "AppId": transform_app_id,
}


class SRUPlugin(Plugin):
    """Return all available SRUM data stored in the SRUDB.dat.

    The System Resource Usage Monitor (SRUM) stores its information in a SRUDB.dat file. As the names suggests, it
    contains data about resource usage, such as network and memory usage by applications.

    Sources:
        - https://docs.microsoft.com/en-us/sql/relational-databases/performance-monitor/monitor-resource-usage-system-monitor?view=sql-server-ver15
        - https://blog.1234n6.com/2019/01/
        - http://dfir.pro/index.php?link_id=92259
    """  # noqa: E501

    __namespace__ = "sru"

    def __init__(self, target):
        super().__init__(target)
        self._sru = None

        srupath = self.target.fs.path("sysvol/Windows/System32/sru/SRUDB.dat")
        if srupath.exists():
            try:
                self._sru = sru.SRU(srupath.open())
            except Error as e:
                self.target.log.warning("Error opening SRU database", exc_info=e)

    def check_compatible(self):
        if not self._sru:
            raise UnsupportedPluginError("No SRUDB found")

    def read_records(self, table_name, record_type):
        table = self._sru.get_table(table_name=table_name)
        if not table:
            raise ValueError(f"Table not found: {table_name}")

        columns = [c.name for c in table.columns]
        if columns[:4] != ["AutoIncId", "TimeStamp", "AppId", "UserId"]:
            raise ValueError(f"Unexpected table layout in SRU iteration: {table} ({columns[:4]})")
        columns = columns[1:]

        for entry in self._sru.get_table_entries(table=table):
            values = (entry[name] for name in columns)
            column_values = zip(columns, values)

            record_values = {}
            for column, value in column_values:
                new_value = TRANSFORMS[column](value) if column in TRANSFORMS else value
                new_column = FIELD_MAPPINGS.get(column, column)
                record_values[new_column] = new_value

            yield record_type(
                _target=self.target,
                **record_values,
            )

    @export(record=NetworkDataRecord)
    def network_data(self):
        """
        Return the contents of Windows Network Data Usage Monitor table from the SRUDB.dat file.

        Gives insight into the network usage of the system.
        """
        yield from self.read_records("network_data", NetworkDataRecord)

    @export(record=NetworkConnectivityRecord)
    def network_connectivity(self):
        """
        Return the contents of Windows Network Connectivity Usage Monitor table from the SRUDB.dat file.

        Gives insight into the network connectivity usage of the system.
        """
        yield from self.read_records("network_connectivity", NetworkConnectivityRecord)

    @export(record=EnergyEstimatorRecord)
    def energy_estimator(self):
        """Return the contents of Energy Estimator table from the SRUDB.dat file."""
        yield from self.read_records("energy_estimator", EnergyEstimatorRecord)

    @export(record=EnergyUsageRecord)
    def energy_usage(self):
        """
        Return the contents of Energy Usage Provider table from the SRUDB.dat file.

        Gives insight into the energy usage of the system.
        """
        yield from self.read_records("energy_usage", EnergyUsageRecord)

    @export(record=EnergyUsageLTRecord)
    def energy_usage_lt(self):
        """
        Return the contents of Energy Usage Provider Long Term table from the SRUDB.dat file.

        Gives insight into the energy usage of the system looking over the long term.
        """
        yield from self.read_records("energy_usage_lt", EnergyUsageLTRecord)

    @export(record=ApplicationRecord)
    def application(self):
        """
        Return the contents of Application Resource Usage table from the SRUDB.dat file.

        Gives insights into the resource usage of applications on the system.
        """
        yield from self.read_records("application", ApplicationRecord)

    @export(record=PushNotificationRecord)
    def push_notification(self):
        """
        Return the contents of Windows Push Notification Data table from the SRUDB.dat file.

        Gives insight into the notification usage of the system.
        """
        yield from self.read_records("push_notifications", PushNotificationRecord)

    @export(record=ApplicationTimelineRecord)
    def application_timeline(self):
        """Return the contents of App Timeline Provider table from the SRUDB.dat file."""
        yield from self.read_records("application_timeline", ApplicationTimelineRecord)

    @export(record=VfuRecord)
    def vfu(self):
        """Return the contents of vfuprov table from the SRUDB.dat file."""
        yield from self.read_records("vfu", VfuRecord)

    @export(record=SdpVolumeProviderRecord)
    def sdp_volume_provider(self):
        """Return the contents of SDP Volume Provider table from the SRUDB.dat file."""
        yield from self.read_records("sdp_volume_provider", SdpVolumeProviderRecord)

    @export(record=SdpPhysicalDiskProviderRecord)
    def sdp_physical_disk_provider(self):
        """Return the contents of SDP Physical Disk Provider table from the SRUDB.dat file."""
        yield from self.read_records("sdp_physical_disk_provider", SdpPhysicalDiskProviderRecord)

    @export(record=SdpCpuProviderRecord)
    def sdp_cpu_provider(self):
        """Return the contents of SDP CPU Provider table from the SRUDB.dat file."""
        yield from self.read_records("sdp_cpu_provider", SdpCpuProviderRecord)

    @export(record=SdpNetworkProviderRecord)
    def sdp_network_provider(self):
        """Return the contents of SDP Network Provider table from the SRUDB.dat file."""
        yield from self.read_records("sdp_network_provider", SdpNetworkProviderRecord)
