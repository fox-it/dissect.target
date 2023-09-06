from io import BytesIO

from dissect import cstruct
from dissect.util import lzxpress_huffman
from dissect.util.ts import wintimestamp
from flow.record.fieldtypes import path

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, arg, export

PrefetchRecord = TargetRecordDescriptor(
    "filesystem/ntfs/prefetch",
    [
        ("datetime", "ts"),
        ("path", "filename"),
        ("path", "prefetch"),
        ("path", "linkedfile"),
        ("uint32", "runcount"),
    ],
)


GroupedPrefetchRecord = TargetRecordDescriptor(
    "filesystem/ntfs/prefetch",
    [
        ("datetime", "ts"),
        ("path", "filename"),
        ("path", "prefetch"),
        ("path[]", "linkedfiles"),
        ("uint32", "runcount"),
        ("datetime[]", "previousruns"),
    ],
)


c_prefetch = """
    struct PREFETCH_HEADER_DETECT {
        char signature[4];
        uint32 size;
    };

    struct PREFETCH_HEADER {
        uint32 version;
        char signature[4];
        uint32 unknown;
        uint32 size;
        char name[60];
        uint32 hash;
        uint32 flag;
    };

    struct FILE_INFORMATION_26 {
        uint32 metrics_array_offset;
        uint32 number_of_file_metrics_entries;
        uint32 trace_chain_array_offset;
        uint32 number_of_trace_chain_array_entries;
        uint32 filename_strings_offset;
        uint32 filename_strings_size;
        uint32 volumes_information_offset;
        uint32 number_of_volumes;
        uint32 volumes_information_size;
        uint32 unknown[2];
        uint64 last_run_time;
        uint64 last_run_remains[7];
        uint64 unknown[2];
        uint32 run_count;
        uint32 unknown;
        uint32 unknown;
        char unknown[88];
    };

    struct FILE_INFORMATION_17 {
        uint32 metrics_array_offset;
        uint32 number_of_file_metrics_entries;
        uint32 trace_chain_array_offset;
        uint32 number_of_trace_chain_array_entries;
        uint32 filename_strings_offset;
        uint32 filename_strings_size;
        uint32 volumes_information_offset;
        uint32 number_of_volumes;
        uint32 volumes_information_size;
        uint32 last_run_time;
        uint32 unknown;
        uint32 run_count;
        uint32 unknown;
    };

    struct FILE_INFORMATION_23 {
        uint32 metrics_array_offset;
        uint32 number_of_file_metrics_entries;
        uint32 trace_chain_array_offset;
        uint32 number_of_trace_chain_array_entries;
        uint32 filename_strings_offset;
        uint32 filename_strings_size;
        uint32 volumes_information_offset;
        uint32 number_of_volumes;
        uint32 volumes_information_size;
        uint32 unknown[2];
        uint64 last_run_time;
        uint64 last_run_remains[2];
        uint32 run_count;
        uint32 unknown;
        uint32 unknown;
        char unknown[80];
    };

    struct VOLUME_INFORMATION_17 {
        uint32 device_path_offset;
        uint32 device_path_number_of_characters;
        uint64 creation_time;
        uint32 serial_number;
        uint32 file_reference_offset;
        uint32 file_reference_size;
        uint32 directory_strings_array_offset;
        uint32 number_of_directory_strings;
        uint32 unknown;
    };

    struct VOLUME_INFORMATION_30 {
        uint32 device_path_offset;
        uint32 device_path_number_of_characters;
        uint64 creation_time;
        uint32 serial_number;
        uint32 file_reference_offset;
        uint32 file_reference_size;
        uint32 directory_strings_array_offset;
        uint32 number_of_directory_strings;
        char unknown[4];
        char unknown[24];
        char unknown[4];
        char unknown[24];
        char unknown[4];
    };

    struct TRACE_CHAIN_ARRAY_ENTRY_17 {
        uint32 next_array_entry_index;
        uint32 total_block_load_count;
        uint32 unknown;
        uint32 unknown;
        uint32 unknown;
    };

    struct FILE_METRICS_ARRAY_ENTRY_17 {
        uint32 start_time;
        uint32 duration;
        uint32 filename_string_offset;
        uint32 filename_string_number_of_characters;
        uint32 flags;
    };

    struct FILE_METRICS_ARRAY_ENTRY_23 {
        uint32 start_time;
        uint32 duration;
        uint32 average_duration;
        uint32 filename_string_offset;
        uint32 filename_string_number_of_characters;
        uint32 flags;
        uint64 ntfs_reference;
    };
    """
prefetch = cstruct.cstruct()
prefetch.load(c_prefetch)

prefetch_version_structs = {
    17: (prefetch.FILE_INFORMATION_17, prefetch.FILE_METRICS_ARRAY_ENTRY_17),
    23: (prefetch.FILE_INFORMATION_23, prefetch.FILE_METRICS_ARRAY_ENTRY_23),
    30: (prefetch.FILE_INFORMATION_26, prefetch.FILE_METRICS_ARRAY_ENTRY_23),
}


class Prefetch:
    def __init__(self, fh):
        header_detect = prefetch.PREFETCH_HEADER_DETECT(fh.read(8))
        if header_detect.signature == b"MAM\x04":
            fh = BytesIO(lzxpress_huffman.decompress(fh))

        self.fh = fh
        self.fh.seek(0)
        self.header = prefetch.PREFETCH_HEADER(self.fh)
        self.version = self.identify()
        self.volumes = None
        self.metrics = None
        self.fn = None

        self.parse()

    def identify(self):
        self.fh.seek(0)
        version = self.header.version

        if version in prefetch_version_structs.keys():
            return version

        raise NotImplementedError()

    def parse(self):
        try:
            file_info_header, file_metrics_header = prefetch_version_structs.get(self.version)
            self.fh.seek(84)
            self.fn = file_info_header(self.fh)
            self.metrics = self.parse_metrics(metric_array_struct=file_metrics_header)
        except KeyError:
            raise NotImplementedError()

    def parse_metrics(self, metric_array_struct):
        metrics = []
        self.fh.seek(self.fn.metrics_array_offset)
        for _ in range(self.fn.number_of_file_metrics_entries):
            entry = metric_array_struct(self.fh)
            filename = self.read_filename(
                self.fn.filename_strings_offset + entry.filename_string_offset,
                entry.filename_string_number_of_characters,
            )
            metrics.append(path.from_windows(filename.decode("utf-16-le")))
        return metrics

    def read_filename(self, off, size):
        offset = self.fh.tell()
        self.fh.seek(off)
        data = self.fh.read(size * 2)
        self.fh.seek(offset)  # reset pointer
        return data

    @property
    def latest_timestamp(self):
        """Get the latest execution timestamp inside the prefetch file."""
        return wintimestamp(self.fn.last_run_time)

    @property
    def previous_timestamps(self):
        """Get the previous timestamps from the prefetch file."""
        try:
            # We check if timestamp actually has a value
            return [wintimestamp(timestamp) for timestamp in self.fn.last_run_remains if timestamp != 0]
        except AttributeError:
            # Header version 17 doesn't contain last_run_remains
            return []


class PrefetchPlugin(Plugin):
    def __init__(self, target):
        super().__init__(target)
        self.prefetchdir = self.target.fs.path("sysvol/windows/prefetch")

    def check_compatible(self) -> None:
        if len(list(self.prefetchdir.iterdir())) == 0:
            raise UnsupportedPluginError("No prefetch files found")

    @export(record=[PrefetchRecord, GroupedPrefetchRecord])
    @arg("--grouped", action="store_true", help="Group the prefetch record")
    def prefetch(self, grouped=False):
        """Return the content of all prefetch files.

        Prefetch is a memory management feature in Windows. It contains information (for example run count and
        timestamp) about executable applications that have been executed recently or are frequently executed.

        References:
            - https://www.geeksforgeeks.org/prefetch-files-in-windows/

        Yields PrefetchRecords with fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): Run timestamp.
            filename (path): The filename.
            prefetch (path): The prefetch entry.
            linkedfile (path): The linked file entry.
            runcount (int): The run count.

        with --grouped:

        Yields PrefetchRecords with fields:
            hostname (string): The target hostname.
            domain (string): The target domain.
            ts (datetime): Run timestamp.
            filename (path): The filename.
            prefetch (path): The prefetch entry.
            linkedfiles (path[]): A list of linked files
            runcount (int): The run count.
            previousruns (datetime[]): Previous run non zero timestamps

        """
        for entry in self.prefetchdir.iterdir():
            if not entry.name.lower().endswith(".pf"):
                continue

            try:
                scca = Prefetch(entry.open())
            except Exception as e:
                self.target.log.warning("Failed to parse prefetch file: %s", entry, exc_info=e)
                continue

            filename = path.from_windows(scca.header.name.decode("utf-16-le", errors="ignore").split("\x00")[0])
            entry_name = path.from_windows(entry.name)

            if grouped:
                yield GroupedPrefetchRecord(
                    ts=scca.latest_timestamp,
                    filename=filename,
                    prefetch=entry_name,
                    linkedfiles=list(map(path.from_windows, scca.metrics)),
                    runcount=scca.fn.run_count,
                    previousruns=scca.previous_timestamps,
                    _target=self.target,
                )
            else:
                run_dates = [scca.latest_timestamp] + scca.previous_timestamps
                for linked_file in scca.metrics:
                    for date in run_dates:
                        yield PrefetchRecord(
                            ts=date,
                            filename=filename,
                            prefetch=entry_name,
                            linkedfile=path.from_windows(linked_file),
                            runcount=scca.fn.run_count,
                            _target=self.target,
                        )
