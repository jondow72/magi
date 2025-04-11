CROSS COMPILATION FOR 64-BIT WINDOWS ON LINUX
==============================================

The steps below can be performed on debian:

    apt install cmake curl make patch git
    apt install bison g++ pkgconf python3 xz-utils
    apt install git build-essential wget pkg-config curl libtool autotools-dev autoconf automake
    apt install mingw-w64
    update-alternatives --config x86_64-w64-mingw32-g++ (1 postix)
    git clone --branch depends https://github.com/magi-dev/magi.git
    cd magi
    cd depends
    make HOST=x86_64-w64-mingw32 -j4
    mv ~/magi/depends/tmp/* ~/magi/depends/work/build/x86_64-w64-mingw32/qtwin
    cd ..
    ~/magi/depends/work/build/x86_64-w64-mingw32/qtwin/5.15.3-*/qtbase/bin/qmake m-wallet-windows64.pro USE_QRCODE=1 USE_UPNP=0
    make -j4
    cd src
    make -j4 -f makefile.windows64
    x86_64-w64-mingw32-strip magid.exe
<br/>

m-wallet.exe is in magi/release<br/>
magid.exe is in magi/src<br/>

jondow

Footnotes
---------

<a name="footnote1">1</a>: Starting from Ubuntu Xenial 16.04, both the 32 and 64 bit Mingw-w64 packages install two different
compiler options to allow a choice between either posix or win32 threads. The default option is win32 threads which is the more
efficient since it will result in binary code that links directly with the Windows kernel32.lib. Unfortunately, the headers
required to support win32 threads conflict with some of the classes in the C++11 standard library, in particular std::mutex.
It's not possible to build the Bitcoin Core code using the win32 version of the Mingw-w64 cross compilers (at least not without
modifying headers in the Bitcoin Core source code).