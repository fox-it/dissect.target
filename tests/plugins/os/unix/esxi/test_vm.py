from __future__ import annotations

from io import BytesIO

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.esxi._os import ESXiPlugin
from dissect.target.plugins.os.unix.esxi.vm import VirtualMachinePlugin
from dissect.target.target import Target


def test_vm() -> None:
    """Test that the ESXi VM inventory plugin yields the correct records."""
    vfs = VirtualFilesystem()
    vfs.map_file_fh(
        "/etc/vmware/hostd/vmInventory.xml",
        BytesIO(b"""
          <ConfigRoot>
            <ConfigEntry id="0000">
              <objID>1</objID>
              <secDomain/>
              <vmxCfgPath>/vmfs/volumes/6800e48c-3dcffc58-6af7-bc2411ec8065/Alpine/Alpine.vmx</vmxCfgPath>
            </ConfigEntry>
          </ConfigRoot>
        """),
    )

    # vmx not defined in vmInventory
    vfs.map_file_fh(
        "/vmfs/volumes/6800e48c-3dcffc58-6af7-bc2411ec8065/Debian/Debian.vmx", BytesIO(b'displayName = "Debian"')
    )

    target = Target()
    target._os_plugin = ESXiPlugin(target)
    target.filesystems.add(vfs)
    target.fs.mount("/", vfs)
    target.apply()

    target.add_plugin(VirtualMachinePlugin)

    records = list(target.vm.inventory())
    assert len(records) == 1
    assert str(records[0].path) == "/vmfs/volumes/6800e48c-3dcffc58-6af7-bc2411ec8065/Alpine/Alpine.vmx"

    orphaned = list(target.vm.orphaned())
    assert len(orphaned) == 1
    assert str(orphaned[0].path) == "/vmfs/volumes/6800e48c-3dcffc58-6af7-bc2411ec8065/Debian/Debian.vmx"

    assert len(list(target.vm())) == 2
