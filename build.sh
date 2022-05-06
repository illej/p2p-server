#!/bin/bash

set -e

ENET=enet-1.3.17
ENET_TAR=$ENET.tar.gz
EXT_PATH=$PWD/external
BUILD_FILE=.build

if [ ! -f $ENET_TAR ]; then
    echo "downloading $ENET"

    URL=http://enet.bespin.org/download/$ENET_TAR
    OPTS="--show-error --progress-bar"
    curl $OPTS $URL -o $ENET_TAR
fi

if [ ! -f $BUILD_FILE ]; then
    echo "building $ENET"

    if [ ! -d $EXT_PATH ]; then
        mkdir -p $EXT_PATH/{lib,include}
    fi

    tar -xzf $ENET_TAR

    cd $ENET
    ./configure --prefix=$EXT_PATH && make && sudo make install
    cd ..
    touch $BUILD_FILE
fi

# LIB_PATH=/usr/local/lib

echo "building server"
gcc p2p-server.c -Wl,-rpath $EXT_PATH/lib -I include -o p2p-server -lenet

echo "building client"
gcc p2p-client.c -rdynamic -Wl,-rpath $EXT_PATH/lib -I include -o p2p-client -lenet

echo "done"
