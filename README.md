# p4pktgen


## Introduction

p4pktgen is a tool for generating input packets and table entries for
P4 programs that cover all paths of the program.

It supports programs written in either the P4_14 or P4_16 variants of
the language, as long as the program can be compiled using the open
source `p4c-bm2-ss` compiler (part of the
[`p4c`](https://github.com/p4lang/p4c) repository), compiled to a bmv2
JSON file for use with the `simple_switch` software switch (part of
the [`behavioral-model`](https://github.com/p4lang/behavioral-model)
repository).

It currently covers all combinations of execution paths through the
parser and ingress control block, but ignores the egress control
block.  It runs the test cases in `simple_switch` to check that the
packet follows the expected path of execution, and also writes out a
data file describing the test cases, which should be useful in
executing the test cases on other P4 implementations (additional work
is required to adapt the test cases to run on other implementations).

* [Installation instructions](#installing-and-running-p4pktgen)
* [Running p4pktgen for the first time](docs/p4pktgen-intro-by-example.md)
* [P4 language features supported](docs/p4-language-feature-support.md)
* [Tips & tricks](docs/tips-and-tricks.md)
* [Bugs found using p4pktgen](docs/success-stories.md)
* [Reference for contents of test case JSON files](docs/reference-test-cases-file.md)


## Prerequisites

- Python 3.6, pip
- [p4c](https://github.com/p4lang/p4c)
- `simple_switch` from the [behavioral-model](https://github.com/p4lang/behavioral-model) project

For installing `p4c` and `simple_switch`, there is a
[script](https://github.com/jafingerhut/p4-guide/blob/master/bin/install-p4dev.sh)
by Andy Fingerhut.  Make sure that `simple_switch` is in your path before running
p4pktgen.

Note: this software has been developed and tested on Ubuntu 16.04
and likely requires changes to run on other operating systems.


## Installing and running p4pktgen

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
