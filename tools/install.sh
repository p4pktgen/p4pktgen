#! /bin/bash

if [ ! -d examples -o ! -d tools -o ! -d docs ]
then
    1>&2 echo "You should run this script inside the root directory of"
    1>&2 echo "your copy of the p4pktgen repository."
    exit 1
fi

INSTALL_DIR=${PWD}

simple_switch --help >& /dev/null
if [ $? != 0 ]
then
    1>&2 echo "No simple_switch in your command path."
    curl -fsSL https://raw.github.com/jafingerhut/p4-guide/master/bin/install-p4dev.sh > ${INSTALL_DIR}/tools/install-p4dev.sh
    if [ $? != 0 ]
    then
        1>&2 echo "Some error occurred trying to get install-p4dev.sh script from github.com"
        exit 1
    fi
    chmod 755 ${INSTALL_DIR}/tools/install-p4dev.sh
    1>&2 echo ""
    1>&2 echo "If you have installed simple_switch, make sure it is in"
    1>&2 echo "your command path and try again."
    1>&2 echo ""
    1>&2 echo "If you have not installed simple_switch yet, consider"
    1>&2 echo "running the script:"
    1>&2 echo "    ${INSTALL_DIR}/tools/install-p4dev.sh"
    1>&2 echo ""
    1>&2 echo "It requires Internet access, takes about 1 to 2 hours"
    1>&2 echo "to download, compile, and install all of the necessary"
    1>&2 echo "code, and requires your user account to be able to run"
    1>&2 echo "commands with root privileges via 'sudo', for which it"
    1>&2 echo "will ask you for your password near the end of the"
    1>&2 echo "process."
    exit 0
fi

warning() {
    1>&2 echo "This software has only been tested on these systems so far:"
    1>&2 echo "    Ubuntu 16.04"
    1>&2 echo "    Ubuntu 18.04"
    1>&2 echo "    Ubuntu 20.04"
    1>&2 echo "Proceed installing manually at your own risk of"
    1>&2 echo "significant time spent figuring out how to make it all work, or"
    1>&2 echo "consider getting VirtualBox and creating a virtual machine with"
    1>&2 echo "a supported operating system."
}

lsb_release >& /dev/null
if [ $? != 0 ]
then
    1>&2 echo "No 'lsb_release' found in your command path."
    warning
    exit 1
fi

distributor_id=`lsb_release -si`
release=`lsb_release -sr`
if [ "${distributor_id}" = "Ubuntu" -a \( "${release}" = "16.04" -o "${release}" = "18.04" -o "${release}" = "20.04" \) ]
then
    echo "Found distributor '${distributor_id}' release '${release}'.  Continuing with installation."
else
    warning
    1>&2 echo ""
    1>&2 echo "Here is what command 'lsb_release -a' shows this OS to be:"
    lsb_release -a
    exit 1
fi

set -ex
sudo apt-get install --yes virtualenv graphviz
virtualenv my-venv --python=python3 --system-site-packages
source my-venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
python setup.py develop
set +ex

echo ""
echo ""
echo "If there were no errors above, you should be ready to"
echo "set up your command path and environment variables for"
echo "running p4pktgen by running this command:"
echo ""
echo "    source my-venv/bin/activate"
echo ""
echo "This command must be done in any new command shell you"
echo "create, to set up its command path and environment variables."
