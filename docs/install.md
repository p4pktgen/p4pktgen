# Detailed setup instructions


## Clone a copy of the p4pktgen repository from bitbucket.org

As of 2017-Oct-03, the latest greatest version of the code is in the
`master` branch.

```bash
% git clone https://github.com/p4pktgen/p4pktgen
% cd p4pktgen
```


## Install required Ubuntu packages

Starting from a default Ubuntu 16.04 installation, the only additional
packages required may be installed with the command below:

```bash
% sudo apt-get install --yes virtualenv python-tk graphviz
```


## Verify that you have the required Python installation

```bash
% python -V
Python 2.7.12  (any 2.7.x with x >= 10 is probably good enough)

% pip --version
pip 9.0.1 from /home/jafinger/.local/lib/python2.7/site-packages (python 2.7)

% virtualenv --version
15.1.0
```


## One-time setup: Create Python venv for p4pktgen

A 'venv' is a Python virtual environment.  Creating one helps to keep separate
the set of Python modules you need to install for that project, from other
projects, or from your system-wide Python installation.

One-time setup to create a local Python venv, activate it, and install
Python packages required for p4pktgen in it.

When creating the virtual environment it is advisable to inherit global
site-packages with the `--system-site-packages` flag. This will make it easier
to include the Python files of the behavioral-model.

If you want more detail on Python virtual environments,
[this guide](http://docs.python-guide.org/en/latest/dev/virtualenvs/)
seems well written and up to date.

First, the short version, with all command output removed:

```bash
% virtualenv my-venv --system-site-packages
% source my-venv/bin/activate
% pip install -r requirements.txt
% python setup.py develop
```

Next, a longer and more detailed version, with a few extra commands to
see what is happening at some of the steps.

```bash
% pwd
/home/jafinger/p4pktgen

[ Your directory name will likely be different. ]

% virtualenv my-venv --system-site-packages
New python executable in /home/jafinger/p4pktgen/my-venv/bin/python
Installing setuptools, pip, wheel...done.

[ That created a directory my-venv with about 15 MB of files in it. ]

% which python
/usr/bin/python

[ Currently the system-wide python executable is first in the shell's
command path. ]

% source my-venv/bin/activate

[ Note: This activate step must be done in any new shell you start,
where you wish to run p4pktgen. ]

% which python
/home/jafinger/p4pktgen/my-venv/bin/python

[ After activation of the new venv, the command path is changed to use
the new venv.  The source command above also assigns a value to the
VIRTUAL_ENV shell env variable.  In my bash shell, it also created
bash functions named deactivate and pydoc. ]

% pip list
pip (9.0.1)
setuptools (36.4.0)
wheel (0.30.0)

[ The initial list of Python packages installed in the venv is quite
short.  Next add the ones needed for p4pktgen. ]

% pip install -r requirements.txt
[ long output deleted ]

[ That caused directory my-venv contents to increase to 195 MB, most
of that from numpy, matplotlib, and z3 packages. ]

% pip list
cycler (0.10.0)
decorator (4.0.11)
enum34 (1.1.6)
functools32 (3.2.3.post2)
graphviz (0.8)
matplotlib (2.0.2)
networkx (1.11)
numpy (1.13.1)
pip (9.0.1)
pyparsing (2.2.0)
python-dateutil (2.6.1)
pytz (2017.2)
scapy (2.3.3)
setuptools (36.4.0)
six (1.10.0)
subprocess32 (3.2.7)
thrift (0.10.0)
wheel (0.30.0)
yapf (0.16.3)
z3-solver (4.5.1.0.post2)

% python setup.py develop

[ That caused the executable file my-venv/bin/p4pktgen to be created ]
```


## One-time setup: Install P4 compiler and behavioral model

For installing p4c and simple-switch, there is a
[script](https://github.com/jafingerhut/p4-guide/blob/master/bin/install-p4dev.sh)
by Andy Fingerhut. Make sure that `simple_switch` is in your path.

Note: this software has been developed and tested on Ubuntu 16.04 and
likely requires changes to run on other operating systems.


## Any time you reboot your machine

Before running p4pktgen, make sure that you created the necesary
virtual ethernet interfaces.  This can be done using the following
command from the top level p4pktgen directory:

```bash
% sudo ./tools/veth_setup.sh
```


## Any time you create a new shell and want to run p4pktgen

In any new shell you create, you will need to activate the Python venv
you created during the one-time setup above.  This can be done by the
following command from the top level p4pktgen directory:

```bash
% source my-venv/bin/activate
```

Make sure `simple_switch` is in your path.
