#!/bin/bash

set -e

ENET=enet-1.3.17
ENET_TAR=$ENET.tar.gz
EXT=$PWD/external
BUILD_FILE=.build

if [ ! -f $ENET_TAR ]; then
    echo "downloading $ENET"

    URL=http://enet.bespin.org/download/$ENET_TAR
    OPTS="--show-error --progress-bar"
    curl $OPTS $URL -o $ENET_TAR
fi

if [ ! -f $BUILD_FILE ]; then
    echo "building $ENET"

    if [ ! -d $EXT ]; then
        mkdir -p $EXT/{lib,include}
    fi

    tar -xzf $ENET_TAR

    cd $ENET
    ./configure --prefix=$EXT && make && sudo make install
    cd ..

    echo $ENET > $BUILD_FILE
fi

# -Wl       : send comma-separated options to linker
# -rpath    : run-time library search path
# -rdynamic : export symbols
# -L        : compile-time library search path
# -I        : compile-time include search path

echo "building server"
gcc p2p-server.c -Wl,-rpath $EXT/lib -L $EXT/lib -I $EXT/include -I include -o p2p-server -lenet

echo "building client"
gcc p2p-client.c -rdynamic -Wl,-rpath $EXT/lib -L $EXT/lib -I $EXT/include -I include -o p2p-client -lenet

echo "done"
