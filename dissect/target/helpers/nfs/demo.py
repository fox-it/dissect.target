import argparse

from dissect.target.helpers.nfs.client import Client as NfsClient
from dissect.target.helpers.nfs.nfs3 import EntryPlus3, GetPortProc, MountOK, MountProc
from dissect.target.helpers.nfs.serializer import MountResultDeserializer
from dissect.target.helpers.sunrpc.client import Client, auth_null, auth_unix
from dissect.target.helpers.sunrpc.serializer import (
    PortMappingSerializer,
    StringSerializer,
    UInt32Serializer,
)
from dissect.target.helpers.sunrpc.sunrpc import PortMapping, Protocol

NFS_PROGRAM = 100003
NFS_V3 = 3


# NFS client demo, showing how to connect to an NFS server and list the contents of a directory
# Note: some nfs servers require connecting using a low port number (use --port)
def main():
    parser = argparse.ArgumentParser(description="NFS Client")
    parser.add_argument("root", type=str, help="The root directory to mount")
    parser.add_argument("--hostname", type=str, default="localhost", help="The hostname of the NFS server")
    parser.add_argument("--port", type=int, default=0, help="The local port to bind to (default: 0)")
    parser.add_argument("--uid", type=int, default=1000, help="The user id to use for authentication")
    parser.add_argument("--gid", type=int, default=1000, help="The group id to use for authentication")
    parser.add_argument("--index", type=int, default=-1, help="The index of the file to read (starting at 1)")
    args = parser.parse_args()

    # RdJ: Perhaps move portmapper to nfs client and cache the mapping
    with Client.connect_port_mapper(args.hostname) as port_mapper_client:
        params_mount = PortMapping(program=MountProc.program, version=MountProc.version, protocol=Protocol.TCP)
        mount_port = port_mapper_client.call(GetPortProc, params_mount, PortMappingSerializer(), UInt32Serializer())
        params_nfs = PortMapping(program=NFS_PROGRAM, version=NFS_V3, protocol=Protocol.TCP)
        nfs_port = port_mapper_client.call(GetPortProc, params_nfs, PortMappingSerializer(), UInt32Serializer())

    # RdJ: Encapsualte in dedicated mount client? Or move to nfs client.
    with Client.connect(args.hostname, mount_port, auth_null(), args.port) as mount_client:
        mount_result = mount_client.call(MountProc, args.root, StringSerializer(), MountResultDeserializer())
        if not isinstance(mount_result, MountOK):
            print(f"Failed to mount {args.root} with error code {mount_result}")
            return

    auth = auth_unix("twigtop", args.uid, args.gid, [])
    with NfsClient.connect(args.hostname, nfs_port, auth, args.port) as nfs_client:
        readdir_result = nfs_client.readdirplus(mount_result.filehandle)
        for index, entry in enumerate(readdir_result.entries, start=1):
            if entry.attributes:
                print(f"{index:<5} {entry.name:<30} {entry.attributes.size:<10}")

        if args.index < 0:
            return
        file_entry: EntryPlus3 = readdir_result.entries[args.index - 1]
        if file_entry.attributes:
            file_contents = nfs_client.readfile_by_handle(file_entry.handle)
            with open(file_entry.name, "wb") as f:
                for chunk in file_contents:
                    f.write(chunk)


if __name__ == "__main__":
    main()
