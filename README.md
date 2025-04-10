# dissect.target

The Dissect module tying all other Dissect modules together. It provides a programming API and command line tools which
allow easy access to various data sources inside disk images or file collections (a.k.a. targets). For more information,
please see [the documentation](https://docs.dissect.tools/en/latest/projects/dissect.target/index.html).

## Requirements

This project is part of the Dissect framework and requires Python.

Information on the supported Python versions can be found in the Getting Started section of [the documentation](https://docs.dissect.tools/en/latest/index.html#getting-started).

## Installation

`dissect.target` is available on [PyPI](https://pypi.org/project/dissect.target/).

```bash
pip install dissect.target
```

This module is also automatically installed if you install the `dissect` package.

If you wish to use the YARA plugin (`target-query -f yara`), you can install `dissect.target[yara]` to automatically 
install the `yara-python` dependency.

## Tools inside this project

### target-query
`target-query` is a tool used to query specific data inside one or more targets.
These queries are available in the form of functions that reside within [plugins](https://docs.dissect.tools/en/latest/advanced/plugins.html).
Each plugin is focussed on providing specific functionality.

This functionality can range from parsing log sources, such as command history logs (i.e. bash history,
PowerShell history, etc.), to returning the hostname and operating system version.

The most basic basic usage of `target-query` is to execute a function on a target:

```bash
target-query -f <FUNCTION_NAME> /example_path/target.vmdk
```

You can also use basic path expansion to execute functions over multiple targets. For example, to execute a function
on all ``.vmdk`` files in a directory:

```
target-query -f <FUNCTION_NAME> /example_path/*.vmdk
```

Not every target plugin will function on every target, they are OS specific.
More information on how to use `target-query` is found in [the documentation](https://docs.dissect.tools/en/latest/tools/target-query.html).

### target-shell
`target-shell` gives you the ability to access a target using a virtual shell environment. Once a shell is opened
on a target, type `help` to list the available commands. To see the documentation of each command,
you can use `help [COMMAND]`.

Opening a shell on a target is straight-forward. You can do so by specifying a path to a target as follows:

```bash
    target-shell targets/EXAMPLE.vmx
    WIN-EXAMPLE:/$ help

    Documented commands (type help <topic>):
    ========================================
    attr   cls    enter        find     info  man       registry  volumes
    cat    cyber  exit         hash     less  pwd       save      zcat   
    cd     debug  file         help     ll    python    stat      zless  
    clear  disks  filesystems  hexdump  ls    readlink  tree    

    WIN-EXAMPLE:/$ ls
    $fs$
    c:
    efi
    sysvol
```

Further interacting with the target can be done using the commands listed above.
You can exit the shell by running `exit` or by pressing `CTRL+D`.

More information on how to use `target-shell` is found in [the documentation](https://docs.dissect.tools/en/latest/tools/target-shell.html).

### target-fs
With `target-fs` you can interact with the filesystem of a target using a set of familiar Unix commands.

The basic structure of a `target-fs` command is as follows:

```bash
target-fs <path_to_target> <command> <path_for_command>
```

**NOTE:** As with any shell command, you have to properly escape backlashes and spaces. Unless you use single or double quotes (`'`, `"`).

More information on how to use `target-fs` is found in [the documentation](https://docs.dissect.tools/en/latest/tools/target-fs.html).

### target-reg
With `target-reg` you can easily query the registry of Windows targets and print the results in a tree. A `+` symbol indicates that it is a registry key (i.e. may have subkeys). A `-` symbol indicates a registry value.

```bash
user@dissect~$ target-reg targets/EXAMPLE.E01 -k "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft"
+ 'Microsoft' (last-modified-date-shows-here)
    + '.NETFramework' (last-modified-date-shows-here)
    - 'Enable64Bit' value-shows-here
[...]
```

More information on how to use `target-reg` is found in [the documentation](https://docs.dissect.tools/en/latest/tools/target-reg.html).

### target-dump
With `target-dump` you can export records of a specific `function` used in target-query to a file.

The basic structure of a `target-dump` command is as follows:

```bash
target-dump -f <comma_seperated_functions> <path_to_target>
```

Futhermore, the tool can apply certain compression algorithms to the dump, to create small archives of the output.

More information on how to use `target-dump` is found in [the documentation](https://docs.dissect.tools/en/latest/tools/target-dump.html).

### target-dd
With `target-dd` you can export (a part of) a target to a file or to stdout. At the moment, `target-dd` can be used for targets that have only one disk.

The basic structure of a `target-dd` command is as follows:

```bash
target-dd --write <output_file> --offset <offset_on_target_in_bytes> --bytes <nr_of_bytes_to_read> <path_to_target>
```

More information on how to use `target-dd` is found in [the documentation](https://docs.dissect.tools/en/latest/tools/target-dd.html).

### target-mount
With `target-mount` you can mount the filesystem of a target to any arbitrary directory on your analysis machine, similar to the `mount` command on Unix systems.
To perform this function, we use `fusepy` to mount a filesystem in linux and mac.
This interacts with `fuselib` to mount disk images in linux userspace, so no administrative access is required.

`target-mount` has two required positional arguments:

* `TARGET` - Target to mount
* `MOUNT` - Directory to mount the target's filesystem on


The following example command can be used to mount a target to the directory ``mnt``:

```bash
user@dissect~$ target-mount targets/EXAMPLE.vmx ~/mnt/EXAMPLE
user@dissect~$ ls ~/mnt/EXAMPLE/
disks   fs   volumes
```

When mounting a target using `target-mount` the process is kept in the foreground. This will occupy your current
terminal session. It is recommended to either open a second terminal, let this command run in the background by
appending `&` to the command or use a terminal multiplexer like `tmux` to start a second session. Using one
of these methods enables you to interact with the mountpoint.

More information on how to use `target-mount` is found in [the documentation](https://docs.dissect.tools/en/latest/tools/target-mount.html).

## Build and test instructions

This project uses `tox` to build source and wheel distributions. Run the following command from the root folder to build
these:

```bash
tox -e build
```

The build artifacts can be found in the `dist/` directory.

`tox` is also used to run linting and unit tests in a self-contained environment. To run both linting and unit tests
using the default installed Python version, run:

```bash
tox
```

For a more elaborate explanation on how to build and test the project, please see [the
documentation](https://docs.dissect.tools/en/latest/contributing/tooling.html).

## Contributing

The Dissect project encourages any contribution to the codebase. To make your contribution fit into the project, please
refer to [the development guide](https://docs.dissect.tools/en/latest/contributing/developing.html).

## Copyright and license

Dissect is released as open source by Fox-IT (<https://www.fox-it.com>) part of NCC Group Plc
(<https://www.nccgroup.com>).

Developed by the Dissect Team (<dissect@fox-it.com>) and made available at <https://github.com/fox-it/dissect>.

License terms: AGPL3 (<https://www.gnu.org/licenses/agpl-3.0.html>). For more information, see the LICENSE file.
