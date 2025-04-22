CROSS COMPILATION FOR 64-BIT AMD64 ON LINUX
==============================================

The steps below can be performed on debian:

    sudo apt update
    sudo apt upgrade
    sudo apt install build-essential autotools-dev xz-utils git make automake pkg-config cmake curl g++-multilib gcc-multilib libtool binutils bsdmainutils pkg-config python3 patch bison
    sudo apt install g++-x86-64-linux-gnu binutils-x86-64-linux-gnu
    git clone https://github.com/magi-dev/magi.git
    cd magi
    cd depends
    make HOST=x86_64-pc-linux-gnu -j4
    cd ..
    ~/magi/depends/work/build/x86_64-pc-linux-gnu/qt/5.15.3-*/qtbase/bin/qmake cross-compilation.pro USE_QRCODE=1 USE_UPNP=0 USE_DBUS=1 HOST=x86_64-pc-linux-gnu
    make -j4
    cd src
    make -j4 -f makefile.amd64
    x86_64-linux-gnu-strip magid
<br/>

m-wallet is in magi/release<br/>
magid is in magi/src<br/>

Michiel Meijer