from dissect.hypervisor import hyperv

from dissect.target import container
from dissect.target.helpers import fsutil
from dissect.target.loader import Loader

DRIVE_CONTROLLER_GUIDS = [
    # Microsoft Emulated IDE Controller
    "83f8638b-8dca-4152-9eda-2ca8b33039b4",
    # Synthetic SCSI Controller
    "d422512d-2bf2-4752-809d-7b82b5fcb1b4",
]


class VmcxLoader(Loader):
    """Hyper-V VMCX loader

    Maps all virtual disks to the target. In VMCX files, all paths are absolute,
    so we first attempt to locate a file with the same name in the same path as
    the VMCX file. This is the most common method if we get a copy of a Hyper-V VM.
    If that fails, we fall back to the absolute path, which is required when we're
    targetting a Hyper-V host and loading child VMs.
    """

    def __init__(self, path, **kwargs):
        path = path.resolve()

        super().__init__(path)
        self.vmcx = hyperv.HyperVFile(path.open("rb"))
        self.base_dir = path.parent

    @staticmethod
    def detect(path):
        return path.suffix.lower() == ".vmcx"

    def map(self, target):
        obj = self.vmcx.as_dict()
        configuration = obj["configuration"]

        instance_guids = []
        for value in configuration["manifest"].values():
            # Iterate all vdevXXX entries
            if not isinstance(value, dict) or "device" not in value:
                continue

            if value["device"].lower() in DRIVE_CONTROLLER_GUIDS:
                instance_guids.append(value["instance"])

        if not instance_guids:
            raise ValueError("Unable to find drive controllers")

        for guid in instance_guids:
            device = configuration.get(f"_{guid}_", {})

            for key, value in device.items():
                if not key.startswith("controller"):
                    continue

                for drive in value.values():
                    if drive["type"] != "VHD":
                        continue

                    if not drive["pathname"]:
                        continue

                    filepath = drive["pathname"]
                    filename = fsutil.basename(filepath, alt_separator="\\")
                    relative_path = self.base_dir.joinpath(filename)
                    if relative_path.exists():
                        disk_path = relative_path
                    else:
                        disk_path = self.base_dir.joinpath("/").joinpath(filepath)

                    try:
                        target.disks.add(container.open(disk_path))
                    except Exception:
                        target.log.exception("Failed to load VHD: %s", drive)
