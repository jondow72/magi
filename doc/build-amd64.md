CROSS COMPILATION FOR 64-BIT amd64 ON LINUX
==============================================

The steps below can be performed on debian:

    apt install cmake curl make patch git
    apt install bison g++ pkgconf python3 xz-utils
    apt install git build-essential wget pkg-config curl libtool autotools-dev autoconf automake
    apt install g++-x86-64-linux-gnu binutils-x86-64-linux-gnu
    git clone --branch depends https://github.com/magi-dev/magi.git
    cd magi
    cd depends
    make HOST=x86_64-pc-linux-gnu -j4
    mv ~/magi/depends/tmp/* ~/magi/depends/work/build/x86_64-pc-linux-gnu/qt
    cd ..
    ~/magi/depends/work/build/x86_64-pc-linux-gnu/qt/5.15.3-*/qtbase/bin/qmake m-wallet-amd64.pro USE_QRCODE=1 USE_UPNP=0 USE_DBUS=1
    make -j4
    cd src
    make -j4 -f makefile.amd64
    x86_64-linux-gnu-strip magid
<br/>

m-wallet is in magi/release<br/>
magid is in magi/src<br/>

jondow

