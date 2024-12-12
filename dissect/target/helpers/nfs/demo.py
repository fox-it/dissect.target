import argparse
from dissect.target.helpers.sunrpc.client import Client, auth_null, auth_unix
from dissect.target.helpers.nfs.serializer import MountResultDeserializer
from dissect.target.helpers.nfs.client import Client as NfsClient
from dissect.target.helpers.sunrpc.serializer import (
    PortMappingSerializer,
    StringSerializer,
    UInt32Serializer,
)
from dissect.target.helpers.sunrpc.sunrpc import PortMapping, Protocol

MOUNT_PROGRAM = 100005
MOUNT_V3 = 3
MOUNT = 1

NFS_PROGRAM = 100003
NFS_V3 = 3

hostname = "localhost"
root = "/home/roel"


# NFS client demo, showing how to connect to an NFS server and list the contents of a directory
# Note: some nfs servers require connecting using a low port number (use --port)
def main():
    parser = argparse.ArgumentParser(description="NFS Client")
    parser.add_argument("root", type=str, help="The root directory to mount")
    parser.add_argument("--hostname", type=str, default="localhost", help="The hostname of the NFS server")
    parser.add_argument("--port", type=int, default=0, help="The local port to bind to (default: 0)")
    parser.add_argument("--uid", type=int, default=1000, help="The user id to use for authentication")
    parser.add_argument("--gid", type=int, default=1000, help="The group id to use for authentication")
    args = parser.parse_args()

    # RdJ: Perhaps move portmapper to nfs client and cache the mapping
    port_mapper_client = Client.connectPortMapper(args.hostname)
    params_mount = PortMapping(program=MOUNT_PROGRAM, version=MOUNT_V3, protocol=Protocol.TCP)
    mount_port = port_mapper_client.call(100000, 2, 3, params_mount, PortMappingSerializer(), UInt32Serializer())
    params_nfs = PortMapping(program=NFS_PROGRAM, version=NFS_V3, protocol=Protocol.TCP)
    nfs_port = port_mapper_client.call(100000, 2, 3, params_nfs, PortMappingSerializer(), UInt32Serializer())

    mount_client = Client.connect(hostname, mount_port, auth_null(), args.port)
    mount_result = mount_client.call(
        MOUNT_PROGRAM, MOUNT_V3, MOUNT, args.root, StringSerializer(), MountResultDeserializer()
    )
    mount_client.close()

    auth = auth_unix("twigtop", args.uid, args.gid, [])
    nfs_client = NfsClient.connect(hostname, nfs_port, auth, args.port)
    readdir_result = nfs_client.readdirplus(mount_result.filehandle)
    print(readdir_result)


if __name__ == "__main__":
    main()
