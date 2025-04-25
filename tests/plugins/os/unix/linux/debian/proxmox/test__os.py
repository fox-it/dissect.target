from io import BytesIO

from dissect.target.filesystem import VirtualFilesystem
from dissect.target.plugins.os.unix.linux.debian.proxmox._os import ProxmoxPlugin
from dissect.target.target import Target
from tests._utils import absolute_path


def test_proxmox_os(target_bare: Target) -> None:
    fs = VirtualFilesystem()

    fs.map_file_fh("/etc/hostname", BytesIO(b"pve"))
    fs.map_file(
        "/var/lib/pve-cluster/config.db", absolute_path("_data/plugins/os/unix/linux/debian/proxmox/_os/config.db")
    )
    fs.makedirs("/etc/pve")
    fs.makedirs("/var/lib/pve")

    target_bare.filesystems.add(fs)

    assert ProxmoxPlugin.detect(target_bare)
    target_bare._os_plugin = ProxmoxPlugin
    target_bare.apply()

    assert target_bare.os == "proxmox"
    assert sorted(map(str, target_bare.fs.path("/etc/pve").rglob("*"))) == [
        "/etc/pve/__version__",
        "/etc/pve/authkey.pub",
        "/etc/pve/authkey.pub.old",
        "/etc/pve/corosync.conf",
        "/etc/pve/datacenter.cfg",
        "/etc/pve/firewall",
        "/etc/pve/ha",
        "/etc/pve/local",
        "/etc/pve/lxc",
        "/etc/pve/mapping",
        "/etc/pve/nodes",
        "/etc/pve/nodes/pve",
        "/etc/pve/nodes/pve-btrfs",
        "/etc/pve/nodes/pve-btrfs/lrm_status",
        "/etc/pve/nodes/pve-btrfs/lrm_status.tmp.971",
        "/etc/pve/nodes/pve-btrfs/lxc",
        "/etc/pve/nodes/pve-btrfs/openvz",
        "/etc/pve/nodes/pve-btrfs/priv",
        "/etc/pve/nodes/pve-btrfs/pve-ssl.key",
        "/etc/pve/nodes/pve-btrfs/pve-ssl.pem",
        "/etc/pve/nodes/pve-btrfs/qemu-server",
        "/etc/pve/nodes/pve-btrfs/ssh_known_hosts",
        "/etc/pve/nodes/pve/lrm_status",
        "/etc/pve/nodes/pve/lxc",
        "/etc/pve/nodes/pve/openvz",
        "/etc/pve/nodes/pve/priv",
        "/etc/pve/nodes/pve/pve-ssl.key",
        "/etc/pve/nodes/pve/pve-ssl.pem",
        "/etc/pve/nodes/pve/qemu-server",
        "/etc/pve/nodes/pve/qemu-server/100.conf",
        "/etc/pve/nodes/pve/ssh_known_hosts",
        "/etc/pve/openvz",
        "/etc/pve/priv",
        "/etc/pve/priv/acme",
        "/etc/pve/priv/authkey.key",
        "/etc/pve/priv/authorized_keys",
        "/etc/pve/priv/known_hosts",
        "/etc/pve/priv/lock",
        "/etc/pve/priv/pve-root-ca.key",
        "/etc/pve/priv/pve-root-ca.srl",
        "/etc/pve/pve-root-ca.pem",
        "/etc/pve/pve-www.key",
        "/etc/pve/qemu-server",
        "/etc/pve/sdn",
        "/etc/pve/storage.cfg",
        "/etc/pve/user.cfg",
        "/etc/pve/virtual-guest",
        "/etc/pve/vzdump.cron",
    ]

    vmlist = list(target_bare.vmlist())
    assert len(vmlist) == 1
    assert vmlist[0].path == "/etc/pve/qemu-server/100.conf"
