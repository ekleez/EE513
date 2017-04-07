#! /bin/bash

LINK=https://github.com/libevent/libevent/releases/download/release-2.1.8-stable/libevent-2.1.8-stable.tar.gz

mkdir libevent
cd libevent

wget $LINK

tar -xvf libevent-2.1.8-stable.tar.gz

cd libevent-2.1.8-stable

./configure --prefix=/usr --disable-static && make

make install
