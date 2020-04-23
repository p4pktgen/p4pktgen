#!/bin/bash

set -e

git clone -b 0.12.0 https://github.com/apache/thrift.git thrift-0.12.0
cd thrift-0.12.0
./bootstrap.sh
./configure \
    --with-c_glib=no \
    --with-cpp=yes \
    --with-erlang=no \
    --with-go=no \
    --with-java=no \
    --with-lua=no \
    --with-nodejs=no \
    --with-php=no \
    --with-ruby=no
make -j "$(nproc)"
sudo make install
cd lib/py
sudo python setup.py install
