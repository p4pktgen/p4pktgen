# p4pktgen


## Introduction

p4pktgen is a tool for generating input packets for P4 programs that
cover all paths of the program.

* [P4 language features supported](README-P4-language-features.md)
* [Tips & tricks](docs/tips-and-tricks.md#p4-programs-with-meters-or-hash-functions)
* [Installation instructions](##installing-and-running-p4pktgen)


## Prerequisites

- Python 2.7, pip
- p4c
- simple_switch from the behavioral-model project

For installing p4c and simple-switch, there is a
[script](https://github.com/jafingerhut/p4-guide/blob/master/bin/install-p4dev.sh)
by Andy Fingerhut.  Make sure that simple_switch is in your path.

Note: this software has been developed and tested on Ubuntu 16.04
and likely requires changes to run on other operating systems.


## Installing and running p4pktgen

Running p4pktgen currently requires root privileges because Linux
does not allow unprivileged users to send raw Ethernet packets.

Run p4pktgen's install script as follows:
```bash
% ./tools/install.sh
```

The basic command to run p4pktgen is as follows:

```bash
% p4pktgen <json file>
```

The flag `-d` prints additional debug information.  The `-h` option
gives help on other command line options available.
