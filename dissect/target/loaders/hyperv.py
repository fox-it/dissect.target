from __future__ import annotations

import base64
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Optional
from xml.etree.ElementTree import Element

from defusedxml import ElementTree
from dissect.hypervisor import hyperv

from dissect.target import container
from dissect.target.helpers import fsutil
from dissect.target.loader import Loader

if TYPE_CHECKING:
    from dissect.target.target import Target

log = logging.getLogger(__name__)

DRIVE_CONTROLLER_GUIDS = [
    # Microsoft Emulated IDE Controller
    "83f8638b-8dca-4152-9eda-2ca8b33039b4",
    # Synthetic SCSI Controller
    "d422512d-2bf2-4752-809d-7b82b5fcb1b4",
]


def is_hyperv_xml(path: Path) -> bool:
    """Return if an XML file is a valid Hyper-V configuration.

    Args:
        path: Path to the file to check.
    """
    if path.suffix != ".xml":
        return False

    try:
        et = ElementTree.fromstring(path.read_bytes())
        element_names = [el.tag for el in et]
        return et.tag == "configuration" and "manifest" in element_names
    except Exception:
        return False


def xml_as_dict(element: Element, root: Optional[dict] = None) -> dict:
    """Convert a Hyper-V XML file into a dictionary.

    Recursively converts all XML elements into a correctly typed dictionary.

    Args:
        element: The current element to convert.
        root: The dictionary object to use as current root.
    """
    root = {} if root is None else root

    ftype = element.get("type")
    if ftype is None:
        obj = root.setdefault(element.tag, {})
        for el in element:
            xml_as_dict(el, obj)
    elif ftype == "string":
        root[element.tag] = element.text
    elif ftype == "integer":
        root[element.tag] = int(element.text)
    elif ftype == "bytes":
        root[element.tag] = base64.b64decode(element.text)
    elif ftype in ("bool", "boolean"):
        root[element.tag] = True if element.text.lower() == "true" else False
    else:
        # We don't necessarily want to error out, so add as string instead
        log.warning("Unknown Hyper-V XML value type, adding as string instead: %s (%s)", ftype, element.tag)
        root[element.tag] = element.text

    return root


class HyperVLoader(Loader):
    """Hyper-V loader.

    Maps all virtual disks to the target. All paths are absolute in Hyper-V configuration files, so we first attempt
    to locate a file with the same name in the same path as the configuration file. This is the most common method if
    we get a copy of a Hyper-V VM. If that fails, we fall back to the absolute path, which is required when we're
    targetting a Hyper-V host and loading child VMs.
    """

    def __init__(self, path: Path, **kwargs):
        self.vmcx = None
        self.xml = None

        if path.suffix == ".vmcx":
            self.vmcx = hyperv.HyperVFile(path.open("rb"))
        elif path.suffix == ".xml":
            self.xml = ElementTree.fromstring(path.read_bytes())
        else:
            raise ValueError(f"HyperVLoader initialized with unsupported file: {path}")

        path = path.resolve()
        self.base_dir = path.parent
        super().__init__(path)

    @staticmethod
    def detect(path: Path) -> bool:
        return path.suffix.lower() == ".vmcx" or is_hyperv_xml(path)

    def map(self, target: Target) -> None:
        if self.vmcx:
            obj = self.vmcx.as_dict()
        else:
            obj = xml_as_dict(self.xml)

        configuration = obj["configuration"]

        # Naive approach first
        instance_guids = {key for key in configuration.keys() if key[1:-1].lower() in DRIVE_CONTROLLER_GUIDS}

        # Add properly discovered instances next
        for value in configuration["manifest"].values():
            # Iterate all vdevXXX entries
            if not isinstance(value, dict) or "device" not in value:
                continue

            if value["device"].lower() in DRIVE_CONTROLLER_GUIDS:
                instance_guids.add(f"_{value['instance']}_")

        if not instance_guids:
            raise ValueError("Unable to find drive controllers")

        for guid in instance_guids:
            # The GUID can be stored in lower or upper case
            device = configuration.get(guid, configuration.get(guid.lower(), {}))

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

                    # First attempt path relative to .vmcx/.xml file
                    disk_path = self.base_dir.joinpath(filename)

                    # Next attempt "Virtual Hard Disks" directory relative from .vmcx/.xml file
                    if not disk_path.exists():
                        disk_path = self.base_dir.joinpath("Virtual Hard Disks").joinpath(filename)

                    # Next attempt "Virtual Hard Disks" directory one up from .vmcx/.xml file
                    if not disk_path.exists():
                        disk_path = self.base_dir.parent.joinpath("Virtual Hard Disks").joinpath(filename)

                    # Finally attempt absolute path
                    if not disk_path.exists():
                        disk_path = self.base_dir.joinpath("/").joinpath(filepath).resolve()

                    try:
                        target.disks.add(container.open(disk_path))
                    except Exception:
                        target.log.exception("Failed to load VHD: %s", drive)
