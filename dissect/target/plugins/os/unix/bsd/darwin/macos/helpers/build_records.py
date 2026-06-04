from __future__ import annotations

import io
import plistlib
import re
import uuid
from collections import defaultdict
from datetime import datetime, timedelta, timezone
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
    convert_timestamps: dict | None = None,
) -> Iterator[TargetRecordDescriptor]:
    """Extract and normalize records from SQLite databases.

    Iterates over provided SQLite files, reads all tables and rows, and converts
    them into dictionaries. Supports decoding of binary plist values and
    NSKeyedArchiver blobs. The optional joins arg can be used to combine and
    filter rows across related tables.

    Join behavior is controlled via the `joins` configuration:
        - iterate: iterates over rows of table2 and merges them with
            matching table1 entries. Table2 rows that do not match with any table1
            will be yielded separately.
        - nested: adds a field to table1 rows containing all of the matching table2 rows.
    - ignore: removes specific fields when values match, used to avoid duplicate fields on joins.

    Args:
        plugin (Plugin): Plugin instance providing logging and target access.
        files (set[str]): Paths to SQLite database files.
        record_descriptors (tuple | None): Optional descriptors for record construction.
        joins (tuple): Join configuration dictionary defining relationships between tables.
        field_mappings (dict | None): Optional field name mappings.
        convert_timestamps (dict | None): Optional timestamp conversion rules.

    Yields:
        TargetRecordDescriptor: Normalized records constructed from database rows.
    """
    joins_by_table1 = defaultdict(list)
    joins_by_table2 = defaultdict(list)
    ignore_joins_map = defaultdict(list)

    for j in joins:
        joins_by_table1[j["table1"]].append(j)
        joins_by_table2[j["table2"]].append(j)

        if j["join"] == "ignore":
            key = (j["table1"], j["table2"])
            ignore_joins_map[key].append(j)

    for file in files:
        try:
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
                                        plugin, file, value, record_descriptors, field_mappings, convert_timestamps
                                    )
                                    row_dict.pop(key)

                        if table.name in joins_by_table2:
                            for j2 in joins_by_table2[table.name]:
                                if row_dict.get(j2["key2"]) is None:
                                    row_dict["table"] = table.name
                                    yield build_record(
                                        plugin, row_dict, file, record_descriptors, field_mappings, convert_timestamps
                                    )
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
                                        yield build_record(
                                            plugin,
                                            row_dict,
                                            file,
                                            record_descriptors,
                                            field_mappings,
                                            convert_timestamps,
                                        )
                                        break

                        elif table.name in joins_by_table1:
                            tables = set()
                            iterate_rows = defaultdict(list)
                            tables.add(table.name)

                            for j in joins_by_table1[table.name]:
                                ignore_joins = ignore_joins_map[(j["table1"], j["table2"])]

                                if j["join"] == "iterate":
                                    for expanded in handle_iterate_join(
                                        database, row_dict, j, joins_by_table1, ignore_joins_map, tables
                                    ):
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
                                        convert_timestamps=convert_timestamps,
                                    )
                            else:
                                yield build_record(
                                    plugin, row_dict, file, record_descriptors, field_mappings, convert_timestamps
                                )

                        else:
                            row_dict["table"] = table.name
                            yield build_record(
                                plugin, row_dict, file, record_descriptors, field_mappings, convert_timestamps
                            )
        except Exception:
            plugin.target.log.exception("Failed to process SQLite file: %s", file)


def prefix_row(row_dict: dict, table: str) -> dict:
    """Prefix all keys in a row dictionary with the table name.

    Args:
        row_dict (dict): Row data as key-value pairs.
        table (str): Table name to prepend to each key.

    Returns:
        dict: A new dictionary with prefixed keys.
    """
    return {f"{table}_{k}": v for k, v in row_dict.items()}


def handle_iterate_join(
    database: SQLite3,
    parent_dict: dict,
    current_join: dict,
    joins_by_table1: defaultdict(list),
    ignore_joins_map: defaultdict(list),
    tables: set[str],
) -> list[dict]:
    """Process iterative joins between tables.

    Matches child rows to a parent row based on join keys and expands them
    into separate result dictionaries. Recursively processes downstream joins,
    allowing chained relationships across multiple tables.

    Applies "ignore" rules to remove matching fields where configured.

    Args:
        database (SQLite3): Open SQLite database instance.
        parent_dict (dict): Current parent row data.
        current_join (dict): Join configuration describing the relationship.
        joins_by_table1 (defaultdict): Joins indexed by source table.
        ignore_joins_map (defaultdict): Mapping of ignore join rules.
        tables (set[str]): Set of involved table names.

    Returns:
        list[dict]: Expanded and prefixed row dictionaries.
    """
    results: list[dict] = []

    ignore_joins = ignore_joins_map[(current_join["table1"], current_join["table2"])]

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
        for j in joins_by_table1[current_join["table2"]]:
            downstream_ignore = ignore_joins_map[(j["table1"], j["table2"])]

            if j["join"] == "iterate":
                for expanded in handle_iterate_join(database, child_dict, j, joins_by_table1, ignore_joins_map, tables):
                    downstream_iterate_rows[j["table2"]].append(expanded)

            elif j["join"] == "nested":
                tables.add(j["table2"])
                handle_nested_join(database, child_dict, j, downstream_ignore)

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
    """Process nested joins between tables.

    Finds related rows in a secondary table and embeds them as a list of
    dictionaries under a key named after the joined table.

    Applies ignore rules to remove matching fields where configured.

    Args:
        database (SQLite3): Open SQLite database instance.
        row_dict (dict): Current row being enriched.
        current_join (dict): Join configuration describing the relationship.
        ignore_joins (list[dict]): Ignore rules for this join.
        tables (set[str]): Set of involved table names.

    Returns:
        None: Modifies `row_dict` in place.
    """
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
    """Determine whether a binary blob is an NSKeyedArchiver-encoded plist.

    Attempts to parse the blob as a plist and checks for the structural
    markers used by NSKeyedArchiver.

    Args:
        value (bytes | bytearray): Binary data to inspect.

    Returns:
        bool: True if the blob appears to be an NSKeyedArchiver archive.
    """
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
    convert_timestamps: dict | None = None,
    function_name: str | None = None,
) -> Iterator[Record]:
    """Extract and normalize records from plist files.

    Iterates over provided file paths, parses each file as a plist, and emits
    records from the resulting data structures. Supports both standard plist
    formats and NSKeyedArchiver-encoded plists.

    Parsed data is passed to emit_dict_records for recursive traversal
    and record construction.

    Args:
        plugin (Plugin): Plugin instance providing logging and target access.
        files (set[str]): Paths to plist files.
        record_descriptors (tuple | None): Optional descriptors for record construction.
        collapse_paths (set[tuple[str, bool]] | None): Plist paths to collapse during recursive traversal.
        field_mappings (dict | None): Optional field name mappings.
        convert_timestamps (dict | None): Optional timestamp conversion rules.
        function_name (str | None): Optional name used for dynamic record creation.

    Yields:
        Record: Normalized records constructed from plist contents.
    """
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
                convert_timestamps=convert_timestamps,
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
    convert_timestamps: dict | None = None,
    function_name: str | None = None,
) -> Iterator[Record]:
    """Extract and normalize records from raw binary data containing plist content.

    Detects whether the input data is a binary plist and whether it contains
    NSKeyedArchiver-encoded content. Parses the data accordingly, then passes
    the resulting structure to emit_dict_records for recursive traversal
    and record construction.

    Args:
        plugin (Plugin): Plugin instance providing logging and target access.
        file (str): File from which the raw_data was extracted.
        raw_data (bytes): Raw binary data to parse.
        record_descriptors (tuple | None): Optional descriptors for record construction.
        field_mappings (dict | None): Optional field name mappings.
        convert_timestamps (dict | None): Optional timestamp conversion rules.
        function_name (str | None): Optional name used for dynamic record creation.

    Yields:
        Record: Normalized records constructed from plist contents.
    """
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
            convert_timestamps=convert_timestamps,
            function_name=function_name,
        )

    except Exception:
        plugin.target.log.exception("Failed to parse %s", file)


def dynamic_build_record(plugin: Plugin, function_name: str, rdict: dict, source: Path) -> Record:
    """Dynamically construct a record descriptor and corresponding record from a dictionary.

    Infers field types based on Python value types and builds a descriptor
    accordingly. Supports lists, and includes the source
    path as a field.

    Args:
        plugin (Plugin): Plugin instance providing target context.
        function_name (str): Name used for the generated record descriptor.
        rdict (dict): Dictionary containing record data.
        source (Path): Source path associated with the record.

    Returns:
        Record: A record instance created from the dynamically generated descriptor.
    """
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
        elif isinstance(v, list):
            record_fields.append(("string[]", k))
        else:
            record_fields.append(("string", k))

        record_values[k] = v

    record_fields.append(("path", "source"))

    desc = TargetRecordDescriptor(function_name, record_fields)

    return desc(**record_values)


def select_descriptor(
    record_descriptors: tuple,
    rdict: dict,
    plugin: Plugin,
    source: Path,
) -> TargetRecordDescriptor | None:
    """Select the most appropriate record descriptor for a given data dictionary.

    Compares the keys in the dictionary against available record descriptors
    and selects the one with the highest number of matching fields. In case of a tie,
    the descriptor with fewer total fields is preferred.

    Logs a warning if the input contains fields not defined in the selected descriptor.

    Args:
        record_descriptors (tuple): Available record descriptors.
        rdict (dict): Dictionary containing record data.
        plugin (Plugin): Plugin instance for logging.
        source (Path): Source path associated with the record.

    Returns:
        TargetRecordDescriptor | None: The selected descriptor, or None if no match is found.
    """
    formatted_rdict = {format_key(k): type(v).__name__ for k, v in rdict.items()}

    selected_record = None
    best_match_count = 0
    best_match_length = 0

    for record in record_descriptors:
        record_keys = set(record.fields.keys())

        matched_keys = set(formatted_rdict.keys()) & record_keys
        match_count = len(matched_keys)

        if match_count > best_match_count:
            best_match_count = match_count
            best_match_length = len(record_keys)
            selected_record = record

        elif match_count == best_match_count and len(record_keys) < best_match_length:
            best_match_length = len(record_keys)
            selected_record = record

    if best_match_count == 0:
        return None

    missing_fields = {key: type_name for key, type_name in formatted_rdict.items() if key not in selected_record.fields}

    if missing_fields:
        formatted = ", ".join(f"{k} ({v})" for k, v in sorted(missing_fields.items()))
        plugin.target.log.warning(
            "Source %s contains fields not defined in the selected record descriptor: %s",
            source,
            formatted,
        )

    return selected_record


def build_record(
    plugin: Plugin,
    rdict: dict,
    source: Path,
    record_descriptors: tuple,
    field_mappings: dict | None = None,
    convert_timestamps: dict | None = None,
) -> Record:
    """Construct a record from a dictionary using a matching record descriptor.

    Applies provided field mappings, selects an appropriate descriptor based on
    the fields in the dictionary, filters unsupported fields, and performs provided
    timestamp conversions before instantiating the record.

    If no matching descriptor is found, logs an error and returns None.

    Args:
        plugin (Plugin): Plugin instance providing logging and target context.
        rdict (dict): Dictionary containing record data.
        source (Path): Source path associated with the record.
        record_descriptors (tuple): Available record descriptors.
        field_mappings (dict | None): Optional field name mappings.
        convert_timestamps (dict | None): Optional timestamp conversion rules.

    Returns:
        Record | None: Constructed record, or None if no descriptor matched.
    """
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
        key = format_key(k)
        if convert_timestamps and key in convert_timestamps:
            v = convert_timestamp(v, convert_timestamps[key])
        record_values[key] = v

    return desc(**record_values)


def convert_timestamp(value: Any, mode: str) -> datetime | Any:
    """Convert a value to a datetime based on the specified timestamp format.

    Supports conversion from Apple's epoch (seconds since 2001-01-01 UTC).
    If the value is None, it is returned unchanged.
    Unsupported modes return the original value.

    Args:
        value (Any): Input value to convert.
        mode (str): Conversion mode (e.g., "2001" for Apple epoch).

    Returns:
        datetime | Any: Converted datetime, or original value if no conversion applied.
    """
    if value is None:
        return value

    if mode == "2001":
        return datetime(2001, 1, 1, tzinfo=timezone.utc) + timedelta(seconds=float(value))

    return value


def format_key(key: str) -> str:
    """Normalize a key name (string) to a valid format.

    Replaces unsupported characters with underscores, collapses
    repeated underscores, removes leading underscores, and ensures
    the key does not start with a digit.

    Args:
        key (str): The key name to be formatted.

    Returns:
        str: Normalized key name suitable for use as an identifier.
    """
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
    """Determine whether a path should be collapsed during traversal.

    A path is considered collapsed if it matches a configured path exactly,
    or if it is a descendant of a configured path when non-exact matching is allowed.

    Args:
        child_path (str): Current traversal path.
        collapse_paths (set[tuple[str, bool]]): Set of (path, exact) rules.

    Returns:
        bool: True if the path should be collapsed, False otherwise.
    """
    for collapse_path, exact in collapse_paths:
        if child_path == collapse_path:
            return True
        if not exact and collapse_path and child_path.startswith(f"{collapse_path}/"):
            return True
    return False


def emit_dict_records(
    plugin: Plugin,
    node: dict,
    source: Path,
    *,
    section: str | None = None,
    path: str | None = None,
    record_descriptors: tuple | None = None,
    collapse_paths: set[tuple[str, bool]] | None = None,
    field_mappings: dict | None = None,
    convert_timestamps: dict | None = None,
    function_name: str | None = None,
) -> Iterator[Record]:
    """Recursively traverse a dictionary and emit records from its contents.

    Splits dictionary entries into attribute values and nested child dictionaries.

    Handles lists by separating scalar elements from nested dictionaries:
        scalar values are retained as attributes
        dictionary elements are treated as child nodes and processed recursively.

    Collapses specified paths into attribute values instead of recursing.

    Generates records for nodes containing attribute data, using either dynamic
    descriptor construction or predefined record descriptors. Recursively processes
    nested child dictionaries to emit additional records.

    Args:
        plugin (Plugin): Plugin instance providing logging and target context.
        node (dict): Dictionary node to process.
        source (Path): Source path associated with the data.
        section (str | None): Optional section label for records.
        path (str | None): Current traversal path within the structure.
        record_descriptors (tuple | None): Optional descriptors for record construction.
        collapse_paths (set[tuple[str, bool]] | None): Paths to collapse instead of recurse.
        field_mappings (dict | None): Optional field name mappings.
        convert_timestamps (dict | None): Optional timestamp conversion rules.
        function_name (str | None): Optional name for dynamic record creation.

    Yields:
        Record: Records generated from dictionary contents.
    """
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

        elif isinstance(v, list):
            cleaned_list = []
            contains_dict = False
            for i, item in enumerate(v):
                if isinstance(item, dict):
                    contains_dict = True
                    child_dicts[f"{k}[{i}]"] = item
                else:
                    cleaned_list.append(item)

            if cleaned_list or not contains_dict:
                attributes[k] = cleaned_list
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
            yield build_record(plugin, record_data, source, record_descriptors, field_mappings, convert_timestamps)

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
            convert_timestamps=convert_timestamps,
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
    """Load and normalize data from an NSKeyedArchiver-encoded plist."""
    ns = NSKeyedArchiver(fh)
    root = ns.get("store")
    return normalize_nsobj(root)
