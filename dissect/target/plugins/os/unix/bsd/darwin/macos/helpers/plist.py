from __future__ import annotations

import plistlib
import re
import uuid
from datetime import datetime
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.util.plist import NSDictionary, NSKeyedArchiver

from dissect.target.helpers.record import TargetRecordDescriptor

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from flow.record.base import Record

    from dissect.target.plugin import Plugin

re_non_identifier = re.compile(r"[^A-Za-z0-9_]")


def build_records(
    plugin: Plugin,
    record_name: str,
    files: set[str],
    record_descriptors: tuple | None = None,
    collapse_paths: set[tuple[str, bool]] | None = None,
) -> Iterator[Record]:
    for file in files:
        file = plugin.target.fs.path(file)
        try:
            fh = file.open(mode="rb")
        except FileNotFoundError:
            plugin.target.log.exception("File not found: %s", file)
            continue

        try:
            if b"$archiver" in fh.peek(64):
                fh.seek(0)
                data = load_plist_data(fh)
            else:
                data = plistlib.load(fh)

            yield from emit_dict_records(
                plugin,
                record_name,
                data,
                file,
                record_descriptors=record_descriptors,
                collapse_paths=collapse_paths,
            )

        except Exception:
            plugin.target.log.exception("Failed to parse %s", file)


def dynamic_build_record(plugin: Plugin, record_name: str, rdict: dict, source: Path | None) -> Record:
    record_fields = sorted(rdict.items())

    record_values = {
        "_target": plugin.target,
        "source": source,
    }
    record_fields = []

    for k, v in rdict.items():
        k = format_key(k)

        if isinstance(v, bool):
            record_fields.append(("boolean", k))
        elif isinstance(v, int):
            record_fields.append(("varint", k))
        else:
            record_fields.append(("string", k))

        record_values[k] = v

    record_fields.append(("path", "source"))

    desc = create_event_descriptor(record_name, tuple(record_fields))

    return desc(**record_values)


def select_descriptor(
    record_descriptors: tuple,
    rdict: dict,
) -> TargetRecordDescriptor | None:
    rdict_keys = {format_key(k) for k in rdict}

    for record in record_descriptors:
        record_keys = set(record.fields.keys())
        if rdict_keys.issubset(record_keys):
            return record

    return None


def build_record(
    plugin: Plugin,
    rdict: dict,
    source: Path | None,
    record_descriptors: tuple | None = None,
) -> Record:
    desc = select_descriptor(record_descriptors, rdict)

    if desc is None:
        plugin.target.log.exception(
            "No matching record descriptor for %s with fields %s",
            source,
            sorted(map(format_key, rdict)),
        )
        return None

    record_values = {
        "_target": plugin.target,
        "source": source,
    }

    for k, v in rdict.items():
        record_values[format_key(k)] = v

    return desc(**record_values)


def create_event_descriptor(record_name: str, record_fields: list[tuple[str, str]]) -> TargetRecordDescriptor:
    return TargetRecordDescriptor(record_name, record_fields)


def format_key(key: str) -> str:
    key = re_non_identifier.sub("_", key)

    key = re.sub(r"_+", "_", key)

    key = key.lstrip("_")

    if not key or key[0].isdigit():
        key = f"k_{key}"

    return key


UUID_RE = re.compile(
    r"^[0-9A-Fa-f]{8}-"
    r"[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{4}-"
    r"[0-9A-Fa-f]{12}$"
)


def is_collapsed_path(child_path: str, collapse_paths: set[tuple[str, bool]]) -> bool:
    for collapse_path, exact in collapse_paths:
        if child_path == collapse_path:
            return True
        if not exact and collapse_path and child_path.startswith(f"{collapse_path}/"):
            return True
    return False


def emit_dict_records(
    plugin: Plugin,
    record_name: str,
    node: dict,
    source: Path | None,
    *,
    section: str | None = None,
    path: str | None = None,
    record_descriptors: tuple | None = None,
    collapse_paths: set[tuple[str, bool]] | None = None,
) -> Iterator[Record]:
    if path and path.endswith("$class"):
        return

    attributes = {}
    child_dicts = {}

    for k, v in node.items():
        child_path = f"{path}/{k}" if path else k

        if collapse_paths and isinstance(v, dict) and is_collapsed_path(child_path, collapse_paths):
            attributes[k] = list(v.items())
            continue

        if isinstance(v, dict):
            child_dicts[k] = v
        else:
            attributes[k] = v

    if node and all(isinstance(k, str) and UUID_RE.fullmatch(k) for k in node):
        attributes = {}

    if attributes:
        record_data = dict(attributes)

        if section is not None:
            record_data["section"] = section
        if path is not None:
            record_data["plist_path"] = path

        if record_descriptors is None:
            yield dynamic_build_record(plugin, record_name, record_data, source)
        else:
            yield build_record(plugin, record_data, source, record_descriptors)

    for k, child in child_dicts.items():
        child_path = f"{path}/{k}" if path else k
        yield from emit_dict_records(
            plugin,
            record_name,
            child,
            source,
            section=section,
            path=child_path,
            record_descriptors=record_descriptors,
            collapse_paths=collapse_paths,
        )


def normalize_nsobj(obj: Any) -> Any:
    """Convert NSKeyedArchiver output to plain Python types."""
    if isinstance(obj, NSDictionary):
        return {k: normalize_nsobj(v) for k, v in obj.items()}

    if isinstance(obj, dict):
        return {k: normalize_nsobj(v) for k, v in obj.items()}

    if isinstance(obj, list):
        return [normalize_nsobj(v) for v in obj]

    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj

    if isinstance(obj, datetime):
        return obj

    if isinstance(obj, uuid.UUID):
        return str(obj)

    if hasattr(obj, "keys"):
        return {k: normalize_nsobj(obj.get(k)) for k in obj.keys()}  # noqa: SIM118

    return obj


def load_plist_data(fh: BinaryIO) -> Any:
    ns = NSKeyedArchiver(fh)
    root = ns.get("store")
    return normalize_nsobj(root)
