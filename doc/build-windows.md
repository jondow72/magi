CROSS COMPILATION FOR 64-BIT WINDOWS ON LINUX
==============================================

The steps below can be performed on debian:

    debootstrap --no-check-gpg --no-check-certificate jessie jessie http://archive.debian.org/debian/
    chroot /root/jessie
    cd root
    apt install cmake curl make patch git
    apt install bison g++ pkgconf python3 xz-utils
    apt install git build-essential wget pkg-config curl libtool autotools-dev autoconf automake
    apt install mingw-w64
    update-alternatives --config x86_64-w64-mingw32-g++ (1 postix)
    git clone --branch v1.4.8.1 https://github.com/jondow72/magi.git
    cd magi
    cd depends
    make HOST=x86_64-w64-mingw32 -j4
    cd ..
    ~/magi/depends/work/build/x86_64-w64-mingw32/qtwin/5.2.1-*/qtbase/bin/qmake m-wallet.pro USE_QRCODE=1 USE_UPNP=0
    make -j4
    cd src
    make -j4 -f makefile.mingw
    x86_64-w64-mingw32-strip magid.exe
<br/>

m-wallet.exe is in magi/release<br/>
magid.exe is in magi/src<br/>

jondow