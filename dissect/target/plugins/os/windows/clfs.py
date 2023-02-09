from typing import Iterator

from dissect.clfs import blf, container
from dissect.clfs.exceptions import InvalidBLFError, InvalidRecordBlockError

from dissect.target.exceptions import UnsupportedPluginError
from dissect.target.helpers import fsutil
from dissect.target.helpers.record import TargetRecordDescriptor
from dissect.target.plugin import Plugin, export
from dissect.target.target import Target

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
        ("bytes", "record_data"),
        ("bytes", "block_data"),
    ],
)


class ClfsPlugin(Plugin):
    """CLFS Plugin.

    Dissect plugin for parsing the Base Log Files of a Microsoft Windows system.

    Most of these records are actually parsed in-memory, this is the first iteration
    to parse the files present on disk. This should be improved in the near future when
    the memory implementation for dissect is working.
    """

    BLF_PATH = "sysvol/windows/system32/config/"  # Unsure at time of writing if this is the only location

    def __init__(self, target: Target):
        super().__init__(target)
        self._blfs = []

        blfdir = self.target.fs.path(self.BLF_PATH)

        if blfdir.exists() and blfdir.is_dir():
            blf_files = blfdir.glob("*.blf")

            for blf_path in blf_files:
                fh = blf_path.open()

                try:
                    blf_instance = blf.BLF(fh)
                    self._blfs.append((blf_path, blf_instance))
                except InvalidRecordBlockError as e:
                    self.target.log.warning(f"Invalid record block: {blf_path}", exc_info=e)
                except InvalidBLFError as e:
                    self.target.log.warning(f"Could not validate BLF: {blf_path}", exc_info=e)

    def check_compatible(self) -> bool:
        if not self._blfs:
            raise UnsupportedPluginError("No BLF files found")

    @export(record=ClfsRecord)
    def clfs(self) -> Iterator[ClfsRecord]:
        """Parse the containers associated with a valid BLF file.

        Containers are used to store the transactional logs in the form of records.

        Sources:
            - https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-the-common-log-file-system
        """  # noqa: E501

        for blf_path, blf_instance in self._blfs:
            # We only parse the base record client/container contexts for now
            for base_record in blf_instance.base_records():
                for stream in base_record.streams:
                    for blf_container in base_record.containers:
                        # Check if the stream ID is matching the container ID
                        if blf_container.id != stream.lsn_base.Offset.ContainerId:
                            continue

                        # We can encounter the same container ID for the shadow blocks
                        if blf_container.type != stream.type:
                            continue

                        # Invalid LSN (-1)
                        if stream.lsn_base.PhysicalOffset <= 0:
                            continue

                        container_path = blf_container.name.replace("%BLF%", str(blf_path.parent))
                        container_path = fsutil.normalize(container_path, alt_separator=blf_path._flavour.altsep)
                        container_file = self.target.fs.path(container_path)

                        fh = container_file.open()
                        trans = container.Container(fh, offset=stream.offset)

                        # Open each container and yield the results for each record found within that container
                        for record_offset, record_data, block_data in trans.records():
                            yield ClfsRecord(
                                stream_name=stream.name,
                                stream_id=stream.id,
                                type=stream.type,
                                file_attributes=stream.file_attributes,
                                offset=stream.offset,
                                container_name=container_file.name,
                                container_id=stream.lsn_base.Offset.ContainerId,
                                container_size=blf_container.size,
                                record_offset=record_offset,
                                record_data=record_data,
                                block_data=block_data,
                                _target=self.target,
                            )
