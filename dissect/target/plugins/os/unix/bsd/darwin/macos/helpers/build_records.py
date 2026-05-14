from __future__ import annotations

import io
import plistlib
import re
import uuid
from collections import defaultdict
from datetime import datetime
from io import BytesIO
from itertools import product
from typing import TYPE_CHECKING, Any, BinaryIO

from dissect.database.sqlite3 import SQLite3
from dissect.util.plist import NSDictionary, NSKeyedArchiver

from dissect.target.helpers.record import TargetRecordDescriptor

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from flow.record.base import Record

    from dissect.target.plugin import Plugin

re_non_identifier = re.compile(r"[^A-Za-z0-9_]")


def build_sqlite_records(
    plugin: Plugin,
    files: set[str],
    record_descriptors: tuple | None = None,
    joins: tuple = (),
    field_mappings: dict | None = None,
) -> Iterator[TargetRecordDescriptor]:
    for file in files:
        with SQLite3(file) as database:
            for table in database.tables():
                for row in table.rows():
                    row_dict = {k: v for k, v in row}  # noqa C416

                    for key, value in list(row_dict.items()):
                        if isinstance(value, (bytes, bytearray)) and value.startswith(b"bplist00"):
                            if is_nskeyedarchive_blob(value):
                                try:
                                    archiver = NSKeyedArchiver(BytesIO(value))
                                    decoded_value = archiver.top.get("root")
                                    row_dict[key] = decoded_value
                                except Exception:
                                    plugin.target.log.exception(
                                        "Failed to decode %s value for key %s",
                                        table.name,
                                        key,
                                    )
                            else:
                                yield from build_record_from_data(
                                    plugin, file, value, record_descriptors, field_mappings
                                )
                                row_dict.pop(key)

                    if table.name in {j["table2"] for j in joins}:
                        for j2 in joins:
                            if j2["table2"] != table.name:
                                continue

                            if row_dict.get(j2["key2"]) is None:
                                row_dict["table"] = table.name
                                yield build_record(plugin, row_dict, file, record_descriptors, field_mappings)
                                break
                            else:
                                match = False
                                for row1 in database.table(j2["table1"]).rows():
                                    row1_dict = {k: v for k, v in row1}  # noqa C416
                                    if row1_dict.get(j2["key1"]) == row_dict.get(j2["key2"]):
                                        match = True
                                        break

                                if not match:
                                    row_dict["table"] = table.name
                                    yield build_record(plugin, row_dict, file, record_descriptors, field_mappings)
                                    break

                    elif table.name in {j["table1"] for j in joins}:
                        tables = set()
                        iterate_rows = defaultdict(list)
                        tables.add(table.name)

                        for j in joins:
                            if j["table1"] != table.name:
                                continue

                            ignore_joins = [
                                ij
                                for ij in joins
                                if ij["table1"] == j["table1"]
                                and ij["table2"] == j["table2"]
                                and ij["join"] == "ignore"
                            ]

                            if j["join"] == "iterate":
                                for expanded in handle_iterate_join(database, row_dict, j, joins, tables):
                                    iterate_rows[j["table2"]].append(expanded)

                            elif j["join"] == "nested":
                                handle_nested_join(database, row_dict, j, ignore_joins, tables)

                        if len(iterate_rows) > 0:
                            row_dict = prefix_row(row_dict, table.name)
                            keys = list(iterate_rows.keys())
                            values = list(iterate_rows.values())
                            for key in keys:
                                tables.add(key)
                            row_dict["tables"] = tables

                            for combination in product(*values):
                                combined_row = dict(row_dict)
                                for joined_row in combination:
                                    combined_row.update(joined_row)

                                yield build_record(
                                    plugin,
                                    combined_row,
                                    file,
                                    record_descriptors,
                                )
                        else:
                            yield build_record(plugin, row_dict, file, record_descriptors, field_mappings)

                    else:
                        row_dict["table"] = table.name
                        yield build_record(plugin, row_dict, file, record_descriptors, field_mappings)


def prefix_row(row_dict: dict, table: str) -> dict:
    return {f"{table}_{k}": v for k, v in row_dict.items()}


def handle_iterate_join(
    database: SQLite3,
    parent_dict: dict,
    current_join: dict,
    joins: tuple,
    tables: set[str],
) -> list[dict]:
    results: list[dict] = []

    ignore_joins = [
        ij
        for ij in joins
        if ij["table1"] == current_join["table1"] and ij["table2"] == current_join["table2"] and ij["join"] == "ignore"
    ]

    for child_row in database.table(current_join["table2"]).rows():
        if child_row.get(current_join["key2"]) != parent_dict.get(current_join["key1"]):
            continue

        tables.add(current_join["table2"])

        child_dict = {k: v for k, v in child_row}  # noqa C416
        child_dict.pop(current_join["key2"], None)

        for ij in ignore_joins:
            if parent_dict.get(ij["key1"]) == child_dict.get(ij["key2"]):
                child_dict.pop(ij["key2"], None)

        downstream_iterate_rows = defaultdict(list)
        for dj in joins:
            if dj["table1"] != current_join["table2"]:
                continue

            downstream_ignore = [
                ij
                for ij in joins
                if ij["table1"] == dj["table1"] and ij["table2"] == dj["table2"] and ij["join"] == "ignore"
            ]

            if dj["join"] == "iterate":
                for expanded in handle_iterate_join(database, child_dict, dj, joins, tables):
                    downstream_iterate_rows[dj["table2"]].append(expanded)

            elif dj["join"] == "nested":
                tables.add(dj["table2"])
                handle_nested_join(database, child_dict, dj, downstream_ignore)

        if len(downstream_iterate_rows) > 0:
            base_prefixed = prefix_row(child_dict, current_join["table2"])
            values = list(downstream_iterate_rows.values())

            for combination in product(*values):
                combined_row = dict(base_prefixed)
                for joined_row in combination:
                    combined_row.update(joined_row)
                results.append(combined_row)
        else:
            results.append(prefix_row(child_dict, current_join["table2"]))

    return results


def handle_nested_join(
    database: SQLite3,
    row_dict: dict,
    current_join: dict,
    ignore_joins: list[dict],
    tables: set[str],
) -> None:
    n_rows = []
    for n_row in database.table(current_join["table2"]).rows():
        if n_row[current_join["key2"]] == row_dict[current_join["key1"]]:
            tables.add(current_join["table2"])
            n_dict = {k: v for k, v in n_row}  # noqa C416
            n_dict.pop(current_join["key2"])
            for ij in ignore_joins:
                if row_dict.get(ij["key1"]) == n_dict.get(ij["key2"]):
                    n_dict.pop(ij["key2"])
            n_rows.append(n_dict)
    row_dict[current_join["table2"]] = n_rows


def is_nskeyedarchive_blob(value: (bytes, bytearray)) -> bool:
    try:
        plist_obj = plistlib.loads(value)
    except Exception:
        return False

    return (
        isinstance(plist_obj, dict)
        and plist_obj.get("$archiver") == "NSKeyedArchiver"
        and "$objects" in plist_obj
        and "$top" in plist_obj
    )


def build_plist_records(
    plugin: Plugin,
    files: set[str],
    record_descriptors: tuple | None = None,
    collapse_paths: set[tuple[str, bool]] | None = None,
    field_mappings: dict | None = None,
    function_name: str | None = None,
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
                data,
                file,
                record_descriptors=record_descriptors,
                collapse_paths=collapse_paths,
                field_mappings=field_mappings,
                function_name=function_name,
            )

        except Exception:
            plugin.target.log.exception("Failed to parse %s", file)


def build_record_from_data(
    plugin: Plugin,
    file: str,
    raw_data: bytes,
    record_descriptors: tuple | None = None,
    field_mappings: dict | None = None,
    function_name: str | None = None,
) -> Iterator[Record]:
    try:
        if not raw_data:
            return

        if raw_data.startswith(b"bplist00"):
            data = load_plist_data(raw_data) if b"$archiver" in raw_data[:128] else plistlib.loads(raw_data)

        else:
            data = plistlib.load(io.BytesIO(raw_data))

        yield from emit_dict_records(
            plugin,
            data,
            file,
            record_descriptors=record_descriptors,
            field_mappings=field_mappings,
            function_name=function_name,
        )

    except Exception:
        plugin.target.log.exception("Failed to parse %s", file)


def dynamic_build_record(plugin: Plugin, function_name: str, rdict: dict, source: Path | None) -> Record:
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

    desc = create_event_descriptor(function_name, tuple(record_fields))

    return desc(**record_values)


def select_descriptor(
    record_descriptors: tuple,
    rdict: dict,
    plugin: Plugin,
    source: Path | None,
) -> TargetRecordDescriptor | None:
    rdict_keys = {format_key(k) for k in rdict}

    selected_record = None
    best_match_count = 0

    for record in record_descriptors:
        record_keys = set(record.fields.keys())

        matched_keys = rdict_keys & record_keys
        match_count = len(matched_keys)

        if match_count > best_match_count:
            best_match_count = match_count
            selected_record = record

    if best_match_count == 0:
        return None

    missing_fields = rdict_keys - set(selected_record.fields.keys())
    if missing_fields:
        plugin.target.log.warning(
            "Source %s contains fields not defined in the selected record descriptor: %s",
            source,
            sorted(missing_fields),
        )

    return selected_record


def build_record(
    plugin: Plugin,
    rdict: dict,
    source: Path | None,
    record_descriptors: tuple | None = None,
    field_mappings: dict | None = None,
) -> Record:
    if field_mappings:
        for key in list(rdict):
            for src, dst in field_mappings.items():
                if format_key(key) == src:
                    rdict[dst] = rdict.pop(key)

    desc = select_descriptor(record_descriptors, rdict, plugin, source)

    if desc is None:
        plugin.target.log.exception(
            "No matching record descriptor for %s with fields %s",
            source,
            sorted(map(format_key, rdict)),
        )
        return None

    allowed_keys = set(desc.fields.keys())
    filtered_rdict = {k: v for k, v in rdict.items() if format_key(k) in allowed_keys}

    record_values = {
        "_target": plugin.target,
        "source": source,
    }

    for k, v in filtered_rdict.items():
        record_values[format_key(k)] = v

    return desc(**record_values)


def create_event_descriptor(function_name: str, record_fields: list[tuple[str, str]]) -> TargetRecordDescriptor:
    return TargetRecordDescriptor(function_name, record_fields)


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
    node: dict,
    source: Path | None,
    *,
    section: str | None = None,
    path: str | None = None,
    record_descriptors: tuple | None = None,
    collapse_paths: set[tuple[str, bool]] | None = None,
    field_mappings: dict | None = None,
    function_name: str | None = None,
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
            yield dynamic_build_record(plugin, function_name, record_data, source)
        else:
            yield build_record(plugin, record_data, source, record_descriptors, field_mappings)

    for k, child in child_dicts.items():
        child_path = f"{path}/{k}" if path else k
        yield from emit_dict_records(
            plugin,
            child,
            source,
            section=section,
            path=child_path,
            record_descriptors=record_descriptors,
            collapse_paths=collapse_paths,
            field_mappings=field_mappings,
            function_name=function_name,
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
