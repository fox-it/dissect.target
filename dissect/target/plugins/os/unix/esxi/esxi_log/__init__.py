from __future__ import annotations

import re
import typing
from datetime import datetime

from dissect.target.helpers.fsutil import open_decompress
from dissect.target.helpers.record import TargetRecordDescriptor

if typing.TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path
    from re import Pattern

    from dissect.target import Target

ESXiLogRecord = TargetRecordDescriptor(
    "esxi/log",
    [
        ("datetime", "ts"),
        ("string", "type"),
        ("string", "log_level"),
        ("string", "application"),
        ("varint", "pid"),
        ("string", "op_id"),
        ("string", "user"),
        ("string", "event_metadata"),
        ("string", "message"),
        ("path", "source"),
    ],
)

RE_TIMESTAMP = (
    r"((?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{3})?Z)\s)"  # ts, mostly including milliseconds, but not always
)
RE_LOG_LEVEL = (
    r"((?P<log_level>[\w()]+)\s)"  # info, warning, of In(166), Wa(164), Er(163), Db(15) in esxi8+, sometime missing
)
RE_APPLICATION = r"((?P<application>([-\w]+))\[(?P<pid>(\d+))\]|-):?"  # hostd[pid] < esxi8, Hostd[pid]: esxi8+

RE_NEW_LINE = (
    r"(?P<newline_delimiter>--> ?)"  # in Exi8+, newline marker is positioned after the ts loglevel application part
)
# but for some log this marker is missing...
RE_LOG_FORMAT: Pattern = re.compile(
    rf"""
    {RE_TIMESTAMP}?
    (
        {RE_LOG_LEVEL}?
        {RE_APPLICATION}\s
    )?
   {RE_NEW_LINE}?
   (\[(?P<metadata>(.*?))\]\s)?
   (?P<message>.*?)""",
    re.VERBOSE,
)


def get_esxi_log_path(target: Target, logname: str) -> Iterator[Path]:
    """Get log location, looking in most usual location, as well as in the osdata partition.

    References:
        - https://knowledge.broadcom.com/external/article/306962/location-of-esxi-log-files.html
    """
    # Esxi/loaders should ensure that logs are symlinked to /var/run/log, as on a live ESXi hosts.
    if (var_run_log := target.fs.path("/var/run/log")).exists():
        for path in var_run_log.glob(f"{logname}.*"):
            try:
                yield path.resolve(strict=True)
            except FilesystemError as e:  # noqa PERF203
                target.info.warning("Fail to resolve path to %s : %s", path, str(e))
    return


def yield_log_records_from_file(
    target: Target, path: Path, re_log_format: re.Pattern, logname: str
) -> Iterator[ESXiLogRecord]:
    """Yield parsed log entries, for a single file."""
    current_record = None
    for line in open_decompress(path, "rt"):
        if not line:
            continue
        line = line.strip("\n")
        if (match := re_log_format.fullmatch(line)) is None:
            target.log.warning("log file contains unrecognized format in %s", path)
            target.log.debug("log file contains unrecognized format in %s : %s", path, line)
            continue

        log = match.groupdict()
        user = None
        op_id = None
        # For multiline event, line start with --> Before Esxi8
        # For Esxi8+, --> is after the Date loglevel application[pid] block
        # but sometime --> is missing but it's still previous line continuation
        if log.get("newline_delimiter") == "-->" or log.get("ts") is None:
            if current_record:
                current_record.message = current_record.message + "\n" + log.get("message")
            else:
                target.log.warning("log file contains unrecognized format in %s", path)
                target.log.debug("log file contains unrecognized format in %s : %s", path, line)
        else:
            if current_record:
                yield current_record
            current_record = None
            if metadata := log.get("metadata"):
                user_match = re.search(r"user=(\S+)", metadata)
                op_id_match = re.search(r"opID=(\S+)", metadata)
                if user_match:
                    user = user_match.groups()[0]
                if op_id_match:
                    op_id = op_id_match.groups()[0]

            if "." in log["ts"]:
                ts = datetime.strptime(log["ts"], "%Y-%m-%dT%H:%M:%S.%f%z")
            else:
                ts = datetime.strptime(log["ts"], "%Y-%m-%dT%H:%M:%S%z")
            current_record = ESXiLogRecord(
                _target=target,
                type=logname,
                message=log.get("message", ""),
                log_level=log.get("log_level", None),
                application=log.get("application", None),
                pid=log.get("pid", None),
                user=user,
                op_id=op_id,
                event_metadata=log.get("metadata", ""),
                ts=ts,
                source=path,
            )

    if current_record:
        yield current_record


def yield_log_records(
    target: Target, log_paths: list[Path], re_log_format: re.Pattern, logname: str
) -> Iterator[ESXiLogRecord]:
    """Yield parsed log entries, iterate on identified log files."""
    for path in log_paths:
        try:
            yield from yield_log_records_from_file(target, path, re_log_format, logname)
        except Exception as e:  # noqa: PERF203
            target.log.warning("An error occurred parsing %s log file %s: %s", logname, path, str(e))
            target.log.debug("", exc_info=e)
