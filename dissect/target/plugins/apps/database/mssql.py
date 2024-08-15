import re
from datetime import datetime
from typing import Iterator
from dissect.target.helpers.record import (
    TargetRecordDescriptor,
    create_extended_descriptor,
)
from dissect.target.plugin import Plugin, arg, export, internal
from dissect.target.exceptions import RegistryError

MssqlErrorlogRecord = TargetRecordDescriptor(
    "microsoft/sql/errorlog",
    [
        ("string", "instance"),
        ("datetime", "ts"),
        ("string", "process"),
        ("string", "message"),
        ("path", "filename"),
    ],
)

class MssqlPlugin(Plugin):
    __namespace__ = "mssql"

    REGISTRY_KEY = "HKLM\\SOFTWARE\\Microsoft\\Microsoft SQL Server"
    FILE_GLOB = "ERRORLOG*"
    VERSIONS = {
        90: "Microsoft SQL Server 2005",
        100: "Microsoft SQL Server 2008",
        110: "Microsoft SQL Server 2012",
        120: "Microsoft SQL Server 2014",
        130: "Microsoft SQL Server 2016",
        140: "Microsoft SQL Server 2017",
        150: "Microsoft SQL Server 2019",
        160: "Microsoft SQL Server 2022",
    }

    def check_compatible(self) -> None:
        try:
            self.target.registry.key(self.REGISTRY_KEY)
        except:
            raise UnsupportedPluginError("System does not seem to be running SQL Server")

    def build_record(self, linebuffer, instance_name, errorlog) -> MssqlErrorlogRecord:
        # the lines seem to contain fixed-width fields, so let's try this
        date = linebuffer[:23].strip().split(".")[0]
        dt = datetime.strptime(date, "%Y-%m-%d %H:%M:%S")
        process_name = linebuffer[23:35].strip()
        message = linebuffer[35:].strip()

        return MssqlErrorlogRecord(
            instance=instance_name,
            ts=self.target.datetime.to_utc(dt),
            process=process_name,
            message=message,
            filename=errorlog,
            _target=self.target,
        )

    def find_instances(self) -> Iterator[str]:
        instances = []

        for reg_key in self.target.registry.keys(self.REGISTRY_KEY):
            for subkey in reg_key.subkeys():
                if subkey.name[:5] == "MSSQL" and "." in subkey.name and subkey.name not in instances:
                    instances.append(subkey.name)

        for instance_name in instances:
            yield instance_name

    def get_log_path_from_registry(self, instance_name) -> str:
        key_path = self.REGISTRY_KEY + "\\" + instance_name

        for reg_key in self.target.registry.keys(key_path):
            for subkey in reg_key.subkeys():
                if subkey.name == "SQLServerAgent":
                    try:
                        return "\\".join(subkey.value("ErrorLogFile").value.split("\\")[:-1])
                    except RegistryError:
                        pass

        return None

    def get_data_path_from_registry(self, instance_name) -> str:
        key_path = self.REGISTRY_KEY + "\\" + instance_name

        for reg_key in self.target.registry.keys(key_path):
            for subkey in reg_key.subkeys():
                if subkey.name == "MSSQLServer":
                    try:
                        return subkey.value("DefaultData").value
                    except RegistryError:
                        pass

        return None

    @export(output="none")
    def info(self) -> None:
        """Return informational output about Microsoft SQL Server
        """
        version = 0
        for reg_key in self.target.registry.keys(self.REGISTRY_KEY):
            for subkey in reg_key.subkeys():
                if subkey.name.isnumeric():
                    version = max(version, int(subkey.name))

        if version in self.VERSIONS.keys():
            version_string = self.VERSIONS[version]
            print(f"Version: {version_string}")
        else:
            print(f"Version: Unknown Microsoft SQL Server version: {version}")

        for instance_name in self.find_instances():
            print(f"Instance: {instance_name}")
            data_pathname = self.get_data_path_from_registry(instance_name)
            print(f" - Data path: {data_pathname}")
            errorlog_pathname = self.get_log_path_from_registry(instance_name)
            print(f" - Log path: {errorlog_pathname}")

    @export(output="yield")
    def instances(self) -> Iterator[str]:
        """Return the Microsoft SQL Server instance names
        """
        return self.find_instances()

    @export(record=MssqlErrorlogRecord)
    def errorlog(self) -> Iterator[MssqlErrorlogRecord]:
        """Return the Microsoft SQL Server ERRORLOG messages.

        These log files contain information such as:
         - Logon failures
         - Enabling/disabling of features, such as xp_cmdshell

        References:
            - https://learn.microsoft.com/en-us/sql/relational-databases/logs/view-offline-log-files
        """

        timestamp_matcher = re.compile(r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.\d{2}")

        for instance_name in self.find_instances():
            errorlog_pathname = self.get_log_path_from_registry(instance_name)

            if errorlog_pathname:
                errorlog_path = self.target.fs.path(errorlog_pathname)
                if errorlog_path.exists():
                    for errorlog in errorlog_path.glob(self.FILE_GLOB):
                        errorlog_file = errorlog.open(mode="rt", encoding="utf-16-le")

                        # entries can be multiline, so we need a line buffer
                        linebuffer = ""

                        # normally the file seems to have a byte-order mark at the start
                        c = errorlog_file.read(1)
                        if c != "\ufeff":
                            # if it does not have a byte-order mark, we must not ignore the first character
                            linebuffer += c

                        for line in errorlog_file:
                            # if the line starts with a timestamp, it must be a new entry,
                            # so we must flush and reset the line buffer
                            if (timestamp_matcher.search(line) is not None):
                                if len(linebuffer) > 0:
                                    yield self.build_record(linebuffer.strip(), instance_name, errorlog)
                                linebuffer = line
                            # otherwise the line should be added to the existing line buffer
                            else:
                                linebuffer += line

                        # also output the last entry that might still be in the line buffer
                        if len(linebuffer) > 0:
                            yield self.build_record(linebuffer.strip(), instance_name, errorlog)
