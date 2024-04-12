from __future__ import annotations
from pathlib import Path
import re

from dissect.target.loader import Loader



class ProxmoxLoader(Loader):
    """Load Proxmox disk data onto target disks.
    
    The method proxmox uses to store disk data varies on multiple factors such as 
    filesystem used, available storage space and other factors. This information is 
    stored within a config file in the filesystem.

    This loader attains the necessary information to find the disk data on the 
    filesystem and appends it to the target filesystem's disks.
    """

    def __init__(self, path, **kwargs):
        path = path.resolve()
        super().__init__(path)        

    @staticmethod
    def detect(path) -> bool:
        return path.suffix.lower() == ".conf"

    def map(self, target):
        parsed_config = self._parse_vm_configuration(self.path)

        for option in parsed_config:
            config_value = parsed_config[option]
            vm_disk = _get_vm_disk_name(config_value)

            if _is_disk_device(option) and vm_disk is not None:
                vm_id = self.path.stem
                name = parsed_config['name']

        
    def _parse_vm_configuration(self, conf) -> list:
        lines = conf.read_text().split("\n")
        lines.remove("") # Removes any trailing empty lines in file 
        parsed_lines = {}

        for line in lines:
            key, value = line.split(': ')
            parsed_lines[key] = value
            
        return parsed_lines

def _is_disk_device(config_value: str) -> bool | None:
    disk = re.match(r"^(sata|scsi|ide)[0-9]+$", config_value)
    return True if disk else None 

def _get_vm_disk_name(config_value: str) -> str | None:
    """Retrieves the disk device name from vm"""
    disk = re.search(r"vm-[0-9]+-disk-[0-9]+(,|.+?,)", config_value)
    return disk.group(0).replace(",", "") if disk else None