# p4pktgen


## Introduction

p4pktgen is a tool for generating input packets for P4 programs that
cover all paths of the program.


## Prerequisites

- Python 2.7, pip
- p4c
- simple_switch from the behavioral-model project

For installing p4c and simple-switch, there is a
[script](https://github.com/jafingerhut/p4-guide/blob/master/bin/install-p4dev.sh)
by Andy Fingerhut.  Make sure that simple_switch is in your path.

Note: this software has been developed and tested on Ubuntu 16.04
and likely requires changes to run on other operating systems.


## Running p4pktgen

Before running p4pktgen, make sure that you created a couple of virtual
ethernet interfaces. This can be done using the [veth_setup
script](https://github.com/p4lang/behavioral-model/blob/595bb7935d9f478f8e36befa24a48f77665c6639/tools/veth_setup.sh).

Running p4pktgen currently requires root privileges because Linux
does not allow unprivileged users to send raw ethernet packets.

The basic command to run p4pktgen is as follows:

```
p4pktgen <json file>
```

The flag `-d` prints additional debug information.
