CROSS COMPILATION FOR 64-BIT WINDOWS ON LINUX
==============================================

The steps below can be performed on debian:

    sudo apt update
    sudo apt upgrade
    sudo apt install build-essential libtool autotools-dev automake pkg-config bsdmainutils curl git
    sudo apt install g++-mingw-w64-x86-64-posix
    sudo update-alternatives --config x86_64-w64-mingw32-g++ (1 postix)
    git clone https://github.com/magi-dev/magi.git
    cd magi
    PATH=$(echo "$PATH" | sed -e 's/:\/mnt.*//g') # strip out problematic Windows %PATH% imported var
    sudo bash -c "echo 0 > /proc/sys/fs/binfmt_misc/status" # Disable WSL support for Win32 applications.
    cd depends
    make HOST=x86_64-w64-mingw32 -j4
    cd ..
    ~/magi/depends/work/build/x86_64-w64-mingw32/qt/5.15.3-*/qtbase/bin/qmake cross-compilation.pro USE_QRCODE=1 USE_UPNP=0 HOST=x86_64-w64-mingw32
    make -j4
    cd src
    make -j4 -f makefile.cross-compilation HOST=x86_64-w64-mingw32
    x86_64-w64-mingw32-strip magid.exe
<br/>

m-wallet.exe is in magi/release<br/>
magid.exe is in magi/src<br/>

jondow