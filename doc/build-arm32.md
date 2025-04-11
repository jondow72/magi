CROSS COMPILATION FOR 32-BIT arm32 ON LINUX
==============================================

The steps below can be performed on debian:

    apt install cmake curl make patch git
    apt install bison g++ pkgconf python3 xz-utils
    apt install git build-essential wget pkg-config curl libtool autotools-dev autoconf automake
    apt install g++-arm-linux-gnueabihf binutils-arm-linux-gnueabihf
    git clone --branch depends https://github.com/magi-dev/magi.git
    cd magi
    cd depends
    make HOST=arm-linux-gnueabihf -j4
    mv ~/magi/depends/tmp/* ~/magi/depends/work/build/arm-linux-gnueabihf/qt
    cd ..
    ~/magi/depends/work/build/arm-linux-gnueabihf/qt/5.15.3-*/qtbase/bin/qmake m-wallet-arm32.pro USE_QRCODE=1 USE_UPNP=0 USE_DBUS=1
    make -j4
    cd src
    make -j4 -f makefile.arm32
    arm-linux-gnueabihf-strip magid
<br/>

m-wallet is in magi/release<br/>
magid is in magi/src<br/>

jondow

