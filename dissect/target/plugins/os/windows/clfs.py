from collections import namedtuple
from io import BytesIO
import ntpath

from dissect.clfs import blf, blf_container
from dissect.clfs.exceptions import InvalidBLFError, InvalidRecordBlockError
from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.plugin import Plugin, export
from dissect.target.helpers.record import TargetRecordDescriptor


BLF_PATH = "sysvol/windows/system32/config/"  # Unsure at time of writing if this is the only location
BLF = namedtuple("BLF", ["blf_file", "blf"])


ClfsRecord = TargetRecordDescriptor(
    "filesystem/windows/clfs",
    [
        ("string", "stream_name"),
        ("uint32", "stream_id"),
        ("string", "type"),
        ("string", "file_attributes"),
        ("uint32", "offset"),
        ("string", "container_name"),
        ("uint32", "container_id"),
        ("uint32", "container_size"),
        ("uint32", "record_offset"),
        ("string", "record_data"),
        ("string", "block_data"),
    ],
)


class ClfsPlugin(Plugin):
    """CLFS Plugin

    Dissect plugin for parsing the Base Log Files of a Microsoft Windows system.

    Most of these records are actually parsed in-memory, this is the first iteration
    to parse the files present on disk. This should be improved in the near future when
    the memory implementation for dissect is working.
    """

    __namespace__ = "clfs"

    def __init__(self, target):
        super(ClfsPlugin, self).__init__(target)
        self._blfs = []

        blfdir = self.target.fs.path(BLF_PATH)

        if blfdir.exists():
            blf_files = blfdir.glob("*.blf")

            for blf_file in blf_files:

                blf_contents = blf_file.open().read()

                # Parse the base log file
                with BytesIO(blf_contents) as blf_fh:
                    blf_data = blf.BLF(blf_fh=blf_fh)

                    try:
                        blf_data.control_record()
                    except InvalidRecordBlockError as e:
                        self.target.log.warning(f"Invalid record block: {blf_file}", exc_info=e)

                    try:
                        blf_data.validate()
                    except InvalidBLFError as e:
                        self.target.log.warning(f"Could not validate BLF: {blf_file}", exc_info=e)

                    # Store the BLF so we can parse the associated containers
                    blf_data.parse_metablocks()
                    self._blfs.append(BLF(blf_file=blf_file, blf=blf_data))

    def check_compatible(self):
        if not self._blfs:
            raise UnsupportedPluginError("No BLF's found")

    @export(record=ClfsRecord)
    def clfs(self):

        for blf_data in self._blfs:
            # Parse the BLF record streams
            for stream in blf_data.blf.streams:

                # Stream container ID for physical container
                s_container_id = stream.lsn_base.offset.container_id

                for container in blf_data.blf.containers:
                    # Check if the stream ID is matching the container ID
                    if container.id != s_container_id:
                        continue

                    # We can encounter the same container ID for the shadow blocks
                    if container.type != stream.type:
                        continue

                    # Invalid LSN (-1)
                    if stream.lsn_base.physical_offset <= 0:
                        continue

                    # Strip the prepended directory to accomodate for dissect FS
                    container_name = ntpath.basename(container.name)
                    container_file = self.target.fs.path(BLF_PATH + container_name)

                    # Open each container and yield the results for each record found within that container
                    container_contents = container_file.open().read()
                    with BytesIO(container_contents) as container_fh:
                        trans = blf_container.Container(container_fh=container_fh, block_offset=stream.offset)

                        for record_offset, record_data, block_data in trans.parse_container():
                            yield ClfsRecord(
                                stream_name=stream.name,
                                stream_id=stream.id,
                                type=stream.type,
                                file_attributes=stream.file_attributes,
                                offset=stream.offset,
                                container_name=container_name,
                                container_id=s_container_id,
                                container_size=container.size,
                                record_offset=record_offset,
                                record_data=record_data,
                                block_data=block_data,
                            )
