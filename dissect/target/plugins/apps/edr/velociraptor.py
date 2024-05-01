import json
import re
import urllib
from functools import lru_cache
from typing import Iterator

from flow.record import RecordDescriptor

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import DynamicDescriptor, TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.target import Target

VELOCIRAPTOR_RESULTS = "/$velociraptor_results$"
ISO_8601_PATTERN = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?"


class VelociraptorRecordBuilder:
    def __init__(self, os_type: str, artifact_name: str):
        self._create_event_descriptor = lru_cache(4096)(self._create_event_descriptor)
        self.RECORD_NAME = f"velociraptor/{os_type}/{artifact_name}"

    def read_record(self, object: dict, target: Target):
        """Builds a Velociraptor record"""
        record_values = {}
        record_fields = []

        record_values["_target"] = target

        for key, value in object.items():
            # Reserved by flow.record
            if key.startswith("_"):
                continue

            key = key.lower()

            if re.match(ISO_8601_PATTERN, str(value)):
                record_type = "datetime"
            elif isinstance(value, list):
                record_type = "string[]"
            elif isinstance(value, int):
                record_type = "varint"
            elif key == "hash":
                record_type = "digest"
                value = (value["md5"] or None, value["sha1"] or None, value["sha256"] or None)
            elif isinstance(value, str):
                record_type = "string"
            # FIXME: Why is there no record type dict?
            elif isinstance(value, dict):
                record_type = "string"
            else:
                record_type = "dynamic"

            record_fields.append((record_type, key))
            record_values[key] = value

        # tuple conversion here is needed for lru_cache
        desc = self._create_event_descriptor(tuple(record_fields))
        return desc(**record_values)

    def _create_event_descriptor(self, record_fields: tuple) -> TargetRecordDescriptor:
        return TargetRecordDescriptor(self.RECORD_NAME, record_fields)


class VelociraptorPlugin(Plugin):
    def __init__(self, target: Target):
        super().__init__(target)
        self.results = target.fs.path(VELOCIRAPTOR_RESULTS)

    def check_compatible(self) -> None:
        if not self.results.exists():
            raise UnsupportedPluginError("No Velociraptor artifacts found")

    @export(record=DynamicDescriptor(["datetime"]))
    def velociraptor(self) -> Iterator[RecordDescriptor]:
        """Return Rapid7 Velociraptor artifacts.

        References:
            - https://docs.velociraptor.app/docs/vql/artifacts/
        """
        for artifact in self.results.glob("*.json"):
            with self.target.fs.path(artifact).open("rt") as fh:
                # "Windows.KapeFiles.Targets%2FAll\ File\ Metadata.json" becomes "windows_kapefiles_targets"
                artifact_name = (
                    urllib.parse.unquote(artifact.name.rstrip(".json")).split("/")[0].lower().replace(".", "_")
                )
                velociraptor_record_builder = VelociraptorRecordBuilder(self.target.os, artifact_name)

                for line in fh:
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        object = json.loads(line)
                        yield velociraptor_record_builder.read_record(object, self.target)
                    except json.decoder.JSONDecodeError:
                        self.target.log.warning("Could not decode Velociraptor JSON log line: %s (%s)", line, artifact)
                        continue
