import re
from typing import Iterator

from defusedxml import ElementTree
from dissect.util.ts import wintimestamp

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.fsutil import Path
from dissect.target.helpers.record import DynamicDescriptor, TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.target import Target

camel_case_patterns = [re.compile(r"(\S)([A-Z][a-z]+)"), re.compile(r"([a-z0-9])([A-Z])"), re.compile(r"(\w)[.\s](\w)")]


def _collect_wer_data(wer_file: Path) -> tuple[list[tuple[str, str]], dict[str, str]]:
    """Parse data from a .wer file."""
    record_values = {}
    record_fields = []
    key = None
    for line in wer_file.read_text("utf-16").splitlines():
        if len(line_split := line.rstrip().split("=", 1)) == 2:
            name, value = line_split
            record_type = "string"

            # dynamic entry with key and value on separate lines
            if "].Name" in name and not key:
                key = value
                # set key and continue to get value on the next line
                continue

            # dynamic entry with key and value on the same line
            elif "]." in name and not key:
                category, name = name.split(".", 1)
                key = f"{category.split('[')[0]}{name}"

            if "EventTime" in name:
                value = wintimestamp(int(value))
                record_type = "datetime"
                key = "ts"

            key = _key_to_snake_case(key if key else name)

            record_values[key] = value
            record_fields.append((record_type, key)) if key != "ts" else record_fields.insert(0, (record_type, key))
            # reset key necessary for dynamic entries and ts
            key = None

    return record_fields, record_values


def _collect_wer_metadata(metadata_xml_file: Path) -> tuple[list[tuple[str, str]], dict[str, str]]:
    """Parse data from a metadata .xml file linked to a .wer file."""
    record_fields = []
    record_values = {}
    file = metadata_xml_file.read_text("utf-16")

    tree = ElementTree.fromstring(file)
    for metadata in tree.iter("WERReportMetadata"):
        for category in metadata:
            for value in category:
                if record_value := value.text.strip("\t\n"):
                    key = _key_to_snake_case(f"{category.tag}{value.tag}")
                    record_fields.append(("string", key))
                    record_values[key] = record_value

    return record_fields, record_values


def _create_record_descriptor(record_name: str, record_fields: list[tuple[str, str]]) -> TargetRecordDescriptor:
    record_fields.extend(
        [
            ("path", "wer_file_path"),
            ("path", "metadata_file_path"),
        ]
    )
    return TargetRecordDescriptor(record_name, record_fields)


def _key_to_snake_case(key: str) -> str:
    for pattern in camel_case_patterns:
        key = pattern.sub(r"\1_\2", key)
    return key.lower()


class WindowsErrorReportingPlugin(Plugin):
    """Plugin for parsing Windows Error Reporting files."""

    WER_LOG_DIRS = [
        "sysvol/ProgramData/Microsoft/Windows/WER/ReportArchive",
        "sysvol/ProgramData/Microsoft/Windows/WER/ReportQueue",
        "%userprofile%/AppData/Local/Microsoft/Windows/WER/ReportArchive",
        "%userprofile%/AppData/Local/Microsoft/Windows/WER/ReportQueue",
    ]

    def __init__(self, target: Target):
        super().__init__(target)
        self.wer_files = [
            res.iterdir()
            for wer_dir in self.WER_LOG_DIRS
            for res in self.target.fs.path(wer_dir).rglob("*")
            if res.is_dir()
        ]

    def check_compatible(self) -> None:
        if self.wer_files:
            return
        raise UnsupportedPluginError("No Windows Error Reporting directories found.")

    @export(record=DynamicDescriptor(["path", "string", "datetime"]))
    def wer(self) -> Iterator[DynamicDescriptor]:
        """Return information from Windows Error Reporting (WER) files.

        Windows Error Reporting (WER) is used by Microsoft to create a report when an application crashes. These reports
        can be sent to Microsoft, on which basis Microsoft can provide the user with troubleshooting information. Since
        malware usually crashes more often than legitimate software, the presence of these WER files and/or the
        information within may be useful for analysis. For example, it may contain the file hash of the crashed
        application within the target_app_id field.

        Sources:
            - https://learn.microsoft.com/en-us/windows/win32/wer/windows-error-reporting
            - https://medium.com/dfir-dudes/amcache-is-not-alone-using-wer-files-to-hunt-evil-86bdfdb216d7

        Yields dynamically created records based on the fields in the files. A record at least contains the following
        fields:
            ts (datetime): The moment in time when the error event took place.
            version (string): WER file version.
            event_type (string): WER file event type.
            consent (string): WER file consent to be sent to Microsoft.
            report_identifier (string): WER file report identifier
            app_session_guid (string): GUID for the app session causing/reporting the error.
            target_app_id (string): WER file target app ID which may contain the application hash.
            target_app_ver (string): WER file target app version.
            boot_id (string): WER file boot ID.
            response_type (string): WER file response type.
            friendly_event_name (string): Human readable event name.
            app_name (string): WER file application name.
            app_path (string): Path to application that caused/reported the error.
            report_description (string): WER file report description.
            application_identity (string): WER file application identity.
            metadata_hash (string): WER file metadata hash.
            wer_file_path (path): File path to the WER report on the target.
            metadata_file_path (path): File path to the metadata XML file on the target (if present).
        """
        for files in self.wer_files:
            record_fields = []
            record_values = {"_target": self.target}

            for file in files:
                if file.suffix == ".wer":
                    record_values["wer_file_path"] = file
                    wer_report_fields, wer_report_values = _collect_wer_data(file)
                    # make sure wer_report_fields are the first entries in the list
                    record_fields = wer_report_fields + record_fields
                    record_values = record_values | wer_report_values
                elif ".WERInternalMetadata" in file.suffixes:
                    record_values["metadata_file_path"] = file
                    metadata_fields, metadata_values = _collect_wer_metadata(file)
                    record_fields.extend(metadata_fields)
                    record_values = metadata_values | record_values

            record = _create_record_descriptor("filesystem/windows/wer/report", record_fields)
            yield record(**record_values)
