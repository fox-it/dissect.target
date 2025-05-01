from __future__ import annotations

import json
import re
import urllib.parse
from functools import lru_cache
from typing import TYPE_CHECKING

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import DynamicDescriptor, TargetRecordDescriptor
from dissect.target.plugin import Plugin, export

if TYPE_CHECKING:
    from collections.abc import Iterator

    from flow.record import Record

    from dissect.target.target import Target

VELOCIRAPTOR_RESULTS = "/$velociraptor_results$"
ISO_8601_PATTERN = r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?"


class VelociraptorRecordBuilder:
    def __init__(self, artifact_name: str):
        self._create_event_descriptor = lru_cache(4096)(self._create_event_descriptor)
        self.record_name = f"velociraptor/{artifact_name}"

    def build(self, object: dict, target: Target) -> TargetRecordDescriptor:
        """Builds a Velociraptor record."""
        record_values = {}
        record_fields = []

        record_values["_target"] = target

        for key, value in object.items():
            # Reserved by flow.record
            if key.startswith("_"):
                continue

            key = key.lower().replace("(", "_").replace(")", "_")

            if re.match(ISO_8601_PATTERN, str(value)):
                record_type = "datetime"
            elif isinstance(value, list):
                record_type = "string[]"
            elif isinstance(value, int):
                record_type = "varint"
            elif key == "hash":
                record_type = "digest"
                value = (value.get("MD5"), value.get("SHA1"), value.get("SHA256"))
            elif isinstance(value, str):
                record_type = "string"
            elif isinstance(value, dict):
                record_type = "record"
                value = self.build(value, target)
            else:
                record_type = "dynamic"

            record_fields.append((record_type, key))
            record_values[key] = value

        # tuple conversion here is needed for lru_cache
        desc = self._create_event_descriptor(tuple(record_fields))
        return desc(**record_values)

    def _create_event_descriptor(self, record_fields: list[tuple[str, str]]) -> TargetRecordDescriptor:
        return TargetRecordDescriptor(self.record_name, record_fields)


class VelociraptorPlugin(Plugin):
    """Returns records from Velociraptor artifacts."""

    __namespace__ = "velociraptor"

    def __init__(self, target: Target):
        super().__init__(target)
        self.results_dir = target.fs.path(VELOCIRAPTOR_RESULTS)

    def check_compatible(self) -> None:
        if not self.results_dir.exists():
            raise UnsupportedPluginError("No Velociraptor artifacts found")

    @export(record=DynamicDescriptor(["datetime"]))
    def results(self) -> Iterator[Record]:
        """Return Rapid7 Velociraptor artifacts.

        References:
            - https://docs.velociraptor.app/docs/vql/artifacts/
        """
        for artifact in self.results_dir.glob("*.json"):
            # "Windows.KapeFiles.Targets%2FAll\ File\ Metadata.json" becomes "windows_kapefiles_targets"
            artifact_name = (
                urllib.parse.unquote(artifact.name.removesuffix(".json")).split("/")[0].lower().replace(".", "_")
            )
            record_builder = VelociraptorRecordBuilder(artifact_name)

            for line in artifact.open("rt"):
                if not (line := line.strip()):
                    continue

                try:
                    object = json.loads(line)
                    yield record_builder.build(object, self.target)
                except json.decoder.JSONDecodeError:
                    self.target.log.warning(
                        "Could not decode Velociraptor JSON log line in file %s: %s",
                        artifact,
                        line,
                    )
                    continue
