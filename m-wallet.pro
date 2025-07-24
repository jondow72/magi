TEMPLATE = app
TARGET = m-wallet
macx:TARGET = "m-wallet"
VERSION = 1.4.0
INCLUDEPATH += src src/json src/qt
DEFINES += QT_GUI BOOST_THREAD_USE_LIB BOOST_SPIRIT_THREADSAFE
CONFIG += no_include_pwd
CONFIG += thread
CONFIG += static
QT += core gui network
greaterThan(QT_MAJOR_VERSION, 4) {
    QT += widgets
}

# Define reusable function to handle architecture and dependency configuration
defineTest(configureArchitecture) {
    ARCH = $$1
    DEPS_DIR = $$2
    POSSIBLE_SUFFIXES = $$3
    SSE2_ENABLED = $$4

    message(Configuring for architecture: $$ARCH)
    message(Checking directory: $$DEPS_DIR)
    exists($$DEPS_DIR) {
        message(Dependency directory $$DEPS_DIR found)
        # List Boost libraries for debugging
        message(Libraries in $$DEPS_DIR/lib: $$system(ls $$DEPS_DIR/lib/libboost* 2>/dev/null || echo "No Boost libraries found"))

        # Set include and library paths
        BOOST_INCLUDE_PATH = $$DEPS_DIR/include/boost
        BOOST_LIB_PATH = $$DEPS_DIR/lib
        BDB_INCLUDE_PATH = $$DEPS_DIR/include
        BDB_LIB_PATH = $$DEPS_DIR/lib
        OPENSSL_INCLUDE_PATH = $$DEPS_DIR/include
        OPENSSL_LIB_PATH = $$DEPS_DIR/lib
        MINIUPNPC_INCLUDE_PATH = $$DEPS_DIR/include/miniupnpc
        MINIUPNPC_LIB_PATH = $$DEPS_DIR/lib
        QRENCODE_INCLUDE_PATH = $$DEPS_DIR/include
        QRENCODE_LIB_PATH = $$DEPS_DIR/lib
        GMP_INCLUDE_PATH = $$DEPS_DIR/include
        GMP_LIB_PATH = $$DEPS_DIR/lib

        # Verify include paths exist
        exists($$BOOST_INCLUDE_PATH) { message(Found BOOST_INCLUDE_PATH: $$BOOST_INCLUDE_PATH) } else { message(Warning: BOOST_INCLUDE_PATH $$BOOST_INCLUDE_PATH not found) }
        exists($$BDB_INCLUDE_PATH/db.h) { message(Found BDB_INCLUDE_PATH: $$BDB_INCLUDE_PATH) } else { message(Warning: BDB_INCLUDE_PATH $$BDB_INCLUDE_PATH/db.h not found) }
        exists($$OPENSSL_INCLUDE_PATH/openssl/ssl.h) { message(Found OPENSSL_INCLUDE_PATH: $$OPENSSL_INCLUDE_PATH) } else { message(Warning: OPENSSL_INCLUDE_PATH $$OPENSSL_INCLUDE_PATH/openssl/ssl.h not found) }
        exists($$MINIUPNPC_INCLUDE_PATH/miniupnpc.h) { message(Found MINIUPNPC_INCLUDE_PATH: $$MINIUPNPC_INCLUDE_PATH) } else { message(Warning: MINIUPNPC_INCLUDE_PATH $$MINIUPNPC_INCLUDE_PATH/miniupnpc.h not found) }
        exists($$QRENCODE_INCLUDE_PATH/qrencode.h) { message(Found QRENCODE_INCLUDE_PATH: $$QRENCODE_INCLUDE_PATH) } else { message(Warning: QRENCODE_INCLUDE_PATH $$QRENCODE_INCLUDE_PATH/qrencode.h not found) }
        exists($$GMP_INCLUDE_PATH/gmp.h) { message(Found GMP_INCLUDE_PATH: $$GMP_INCLUDE_PATH) } else { message(Warning: GMP_INCLUDE_PATH $$GMP_INCLUDE_PATH/gmp.h not found) }

        # Initialize Boost suffix variables
        BOOST_LIB_SUFFIX =
        BOOST_THREAD_LIB_SUFFIX =

        # Loop through possible Boost suffixes
        for(suffix, POSSIBLE_SUFFIXES) {
            exists($$DEPS_DIR/lib/libboost_system$${suffix}.a) || exists($$DEPS_DIR/lib/libboost_system$${suffix}.so) {
                BOOST_LIB_SUFFIX = $${suffix}
                BOOST_THREAD_LIB_SUFFIX = $${suffix}
                message(Detected Boost library suffix: $${suffix})
                break()
            }
        }

        # Check if a valid Boost suffix was found
        isEmpty(BOOST_LIB_SUFFIX) {
            message(No valid Boost library suffix found in $$DEPS_DIR/lib. Tried suffixes: $$POSSIBLE_SUFFIXES)
            warning(Falling back to system libraries.)
            # Fallback to system include and library paths
            INCLUDEPATH += /usr/include /usr/local/include
            LIBS += -L/usr/lib -L/usr/local/lib
            LIBS += -lboost_system -lboost_filesystem -lboost_program_options -lboost_thread -lboost_chrono
            LIBS += -ldb_cxx -lssl -lcrypto -lminiupnpc -lqrencode -lgmp
        } else {
            message(Using Boost library suffix: $$BOOST_LIB_SUFFIX)
            # Add include paths
            INCLUDEPATH += $$BOOST_INCLUDE_PATH $$BDB_INCLUDE_PATH $$OPENSSL_INCLUDE_PATH $$MINIUPNPC_INCLUDE_PATH $$QRENCODE_INCLUDE_PATH $$GMP_INCLUDE_PATH
            # Add library paths and libraries
            LIBS += -L$$BOOST_LIB_PATH -L$$BDB_LIB_PATH -L$$OPENSSL_LIB_PATH -L$$MINIUPNPC_LIB_PATH -L$$QRENCODE_LIB_PATH -L$$GMP_LIB_PATH
            LIBS += -lboost_system$$BOOST_LIB_SUFFIX -lboost_filesystem$$BOOST_LIB_SUFFIX -lboost_program_options$$BOOST_LIB_SUFFIX -lboost_thread$$BOOST_THREAD_LIB_SUFFIX -lboost_chrono$$BOOST_LIB_SUFFIX
            LIBS += -ldb_cxx -lssl -lcrypto -lminiupnpc -lqrencode -lgmp
        }
    } else {
        message(Dependency directory $$DEPS_DIR does not exist)
        warning(Dependency directory $$DEPS_DIR not found. Falling back to system libraries.)
        # Fallback to system include and library paths
        INCLUDEPATH += /usr/include /usr/local/include
        LIBS += -L/usr/lib -L/usr/local/lib
        LIBS += -lboost_system -lboost_filesystem -lboost_program_options -lboost_thread -lboost_chrono
        LIBS += -ldb_cxx -lssl -lcrypto -lminiupnpc -lqrencode -lgmp
    }

    # Set SSE2 flags if enabled
    equals(SSE2_ENABLED, true) {
        message(Building with SSE2 support for $$ARCH)
        QMAKE_CXXFLAGS += -msse2
        QMAKE_CFLAGS += -msse2
    } else {
        message(Building without SSE2 support for $$ARCH)
    }

    # Export variables to parent scope
    export(BOOST_LIB_SUFFIX)
    export(BOOST_THREAD_LIB_SUFFIX)
    export(INCLUDEPATH)
    export(LIBS)
    export(QMAKE_CXXFLAGS)
    export(QMAKE_CFLAGS)
    return(true)
}

# Debug architecture and project directory
message(QMAKE_CPU_ARCH: $$QMAKE_CPU_ARCH)
message(HOST: $$QMAKE_HOST.host)
message(Project directory: $$PWD)

# Try to use qmake's arch detection, fallback to uname -m if empty
QMAKE_CPU_ARCH = $$QMAKE_HOST.arch
isEmpty(QMAKE_CPU_ARCH) {
    QMAKE_CPU_ARCH = $$system(uname -m)
}

# Default: disable SSE2, clear vars
SSE2 = false
DEPSDIR =
BOOST_LIB_SUFFIX =
BOOST_THREAD_LIB_SUFFIX =

# Common Boost suffixes
BOOST_SUFFIXES = -mt-x64 -mt -x64 "" -mt-s-x64 -mt-a64 -mt-a32 -mt-p64 -mt-r64 -mt-s64

# x86 64-bit Linux
contains(QMAKE_CPU_ARCH, "x86_64") {
    configureArchitecture(x86_64, $$PWD/depends/x86_64-pc-linux-gnu, $$BOOST_SUFFIXES, true)
}
# x86 32-bit Linux
else:contains(QMAKE_CPU_ARCH, "i686")|contains(QMAKE_CPU_ARCH, "i386") {
    configureArchitecture(i686, /depends/i686-pc-linux-gnu, $$BOOST_SUFFIXES, true)
}
# x86_64 Windows (MinGW)
else:contains(HOST, "x86_64-w64-mingw32") {
    configureArchitecture(x86_64-w64-mingw32, /depends/x86_64-w64-mingw32, $$BOOST_SUFFIXES, true)
}
# i686 Windows (MinGW)
else:contains(HOST, "i686-w64-mingw32") {
    configureArchitecture(i686-w64-mingw32, /depends/i686-w64-mingw32, $$BOOST_SUFFIXES, true)
}
# Mac x86_64
else:contains(QMAKE_CPU_ARCH, "x86_64")|contains(HOST, "x86_64-apple-darwin") {
    configureArchitecture(x86_64-apple-darwin, /depends/x86_64-apple-darwin, $$BOOST_SUFFIXES, true)
}
# Mac arm64 (Apple Silicon)
else:contains(QMAKE_CPU_ARCH, "arm64")|contains(HOST, "arm64-apple-darwin") {
    configureArchitecture(arm64-apple-darwin, /depends/arm64-apple-darwin, $$BOOST_SUFFIXES, false)
}
# Linux ARM 32
else:contains(QMAKE_CPU_ARCH, "arm")|contains(HOST, "arm-linux-gnueabihf") {
    configureArchitecture(arm-linux-gnueabihf, /depends/arm-linux-gnueabihf, $$BOOST_SUFFIXES, false)
}
# Linux ARM 64
else:contains(QMAKE_CPU_ARCH, "aarch64")|contains(HOST, "aarch64-linux-gnu") {
    configureArchitecture(aarch64-linux-gnu, /depends/aarch64-linux-gnu, $$BOOST_SUFFIXES, false)
}
# PowerPC64
else:contains(QMAKE_CPU_ARCH, "powerpc64")|contains(HOST, "powerpc64-linux-gnu") {
    configureArchitecture(powerpc64-linux-gnu, /depends/powerpc64-linux-gnu, $$BOOST_SUFFIXES, false)
}
# PowerPC64le
else:contains(HOST, "powerpc64le-linux-gnu") {
    configureArchitecture(powerpc64le-linux-gnu, /depends/powerpc64le-linux-gnu, $$BOOST_SUFFIXES, false)
}
# RISC-V 32
else:contains(QMAKE_CPU_ARCH, "riscv32")|contains(HOST, "riscv32-linux-gnu") {
    configureArchitecture(riscv32-linux-gnu, /depends/riscv32-linux-gnu, $$BOOST_SUFFIXES, false)
}
# RISC-V 64
else:contains(QMAKE_CPU_ARCH, "riscv64")|contains(HOST, "riscv64-linux-gnu") {
    configureArchitecture(riscv64-linux-gnu, /depends/riscv64-linux-gnu, $$BOOST_SUFFIXES, false)
}
# S390x
else:contains(QMAKE_CPU_ARCH, "s390x")|contains(HOST, "s390x-linux-gnu") {
    configureArchitecture(s390x-linux-gnu, /depends/s390x-linux-gnu, $$BOOST_SUFFIXES, false)
}
# Android ARM (32)
else:contains(HOST, "armv7a-linux-android") {
    configureArchitecture(armv7a-linux-android, /depends/armv7a-linux-android, $$BOOST_SUFFIXES, false)
}
# Android ARM64
else:contains(HOST, "aarch64-linux-android") {
    configureArchitecture(aarch64-linux-android, /depends/aarch64-linux-android, $$BOOST_SUFFIXES, false)
}
# Android x86_64
else:contains(HOST, "x86_64-linux-android") {
    configureArchitecture(x86_64-linux-android, /depends/x86_64-linux-android, $$BOOST_SUFFIXES, true)
}
else {
    error("Unknown or unsupported architecture ($$QMAKE_CPU_ARCH / $$HOST) -- please add to autodetect block")
}

# for boost > 1.37, add -mt to the boost libraries
# use: qmake BOOST_LIB_SUFFIX=-mt
# for boost thread win32 with _win32 sufix
# use: BOOST_THREAD_LIB_SUFFIX=_win32-...
# when linking against a specific BerkelyDB version: BDB_LIB_SUFFIX=-4.8

# Dependency library locations can be customized using following settings 
# winbuild dependencies
win32:!cross_compile {
    # Native Windows build
#    BOOST_LIB_SUFFIX=-mgw49-mt-s-1_58
    BOOST_INCLUDE_PATH=$$DEPSDIR/boost_1_58_0
    BOOST_LIB_PATH=$$DEPSDIR/boost_1_58_0/stage/lib
    BDB_INCLUDE_PATH=$$DEPSDIR/db-4.8.30.NC/build_unix
    BDB_LIB_PATH=$$DEPSDIR/db-4.8.30.NC/build_unix
    OPENSSL_INCLUDE_PATH=$$DEPSDIR/openssl-1.0.2j/include
    OPENSSL_LIB_PATH=$$DEPSDIR/openssl-1.0.2j
    MINIUPNPC_INCLUDE_PATH=$$DEPSDIR/miniupnpc
    MINIUPNPC_LIB_PATH=$$DEPSDIR/miniupnpc
    QRENCODE_INCLUDE_PATH=$$DEPSDIR/qrencode-3.4.3
    QRENCODE_LIB_PATH=$$DEPSDIR/qrencode-3.4.3/.libs
    GMP_INCLUDE_PATH=$$DEPSDIR/gmp-6.0.0
    GMP_LIB_PATH=$$DEPSDIR/gmp-6.0.0/.libs
} else {
    # Everything else (Linux, cross-compile, etc)
    BOOST_INCLUDE_PATH=$$DEPSDIR/include/boost
    BOOST_LIB_PATH=$$DEPSDIR/lib
    BDB_INCLUDE_PATH=$$DEPSDIR/include
    BDB_LIB_PATH=$$DEPSDIR/lib
    OPENSSL_INCLUDE_PATH=$$DEPSDIR/include
    OPENSSL_LIB_PATH=$$DEPSDIR/lib
    MINIUPNPC_INCLUDE_PATH=$$DEPSDIR/include/miniupnpc
    MINIUPNPC_LIB_PATH=$$DEPSDIR/lib
    QRENCODE_INCLUDE_PATH=$$DEPSDIR/include
    QRENCODE_LIB_PATH=$$DEPSDIR/lib
    GMP_INCLUDE_PATH=$$DEPSDIR/include
    GMP_LIB_PATH=$$DEPSDIR/lib
}

OBJECTS_DIR = build
MOC_DIR = build
UI_DIR = build

# use: qmake "RELEASE=1"
contains(RELEASE, 1) {
    # Mac: compile for maximum compatibility (10.5, 64-bit)
    macx:QMAKE_CXXFLAGS += -mmacosx-version-min=10.5 -arch x86_64 -isysroot $(xcode-select --print-path)/Platforms/MacOSX.platform/Developer/SDKs/MacOSX10.5.sdk

    !windows:!macx {
        # Linux: static link
        LIBS += -Wl,-Bstatic
    }
}

!win32 {
# for extra security against potential buffer overflows: enable GCCs Stack Smashing Protection
QMAKE_CXXFLAGS *= -fstack-protector-all --param ssp-buffer-size=1
QMAKE_LFLAGS *= -fstack-protector-all --param ssp-buffer-size=1
# We need to exclude this for Windows cross compile with MinGW 4.2.x, as it will result in a non-working executable!
# This can be enabled for Windows, when we switch to MinGW >= 4.4.x.
}
# for extra security on Windows: enable ASLR and DEP via GCC linker flags
#win32:QMAKE_LFLAGS *= -Wl,--dynamicbase -Wl,--nxcompat -Wl,--large-address-aware -static
win32:QMAKE_LFLAGS *= -Wl,--dynamicbase -Wl,--nxcompat -static
win32:QMAKE_LFLAGS += -static-libgcc -static-libstdc++

# use: qmake "USE_QRCODE=1"
# libqrencode (http://fukuchi.org/works/qrencode/index.en.html) must be installed for support
contains(USE_QRCODE, 1) {
    message(Building with QRCode support)
    DEFINES += USE_QRCODE
    LIBS += -lqrencode
}

# use: qmake "USE_UPNP=1" ( enabled by default; default)
#  or: qmake "USE_UPNP=0" (disabled by default)
#  or: qmake "USE_UPNP=-" (not supported)
# miniupnpc (http://miniupnp.free.fr/files/) must be installed for support
contains(USE_UPNP, -) {
    message(Building without UPNP support)
} else {
    message(Building with UPNP support)
    count(USE_UPNP, 0) {
        USE_UPNP=1
    }
    DEFINES += USE_UPNP=$$USE_UPNP STATICLIB MINIUPNP_STATICLIB
    INCLUDEPATH += $$MINIUPNPC_INCLUDE_PATH
    LIBS += $$join(MINIUPNPC_LIB_PATH,,-L,) -lminiupnpc
    win32:LIBS += -liphlpapi
}


# use: qmake "USE_DBUS=1"
contains(USE_DBUS, 1) {
    message(Building with DBUS (Freedesktop notifications) support)
    DEFINES += USE_DBUS
    QT += dbus
}

# use: qmake "USE_IPV6=1" ( enabled by default; default)
#  or: qmake "USE_IPV6=0" (disabled by default)
#  or: qmake "USE_IPV6=-" (not supported)
contains(USE_IPV6, -) {
    message(Building without IPv6 support)
} else {
    message(Building with IPv6 support)
    count(USE_IPV6, 0) {
        USE_IPV6=1
    }
    DEFINES += USE_IPV6=$$USE_IPV6
}

contains(BITCOIN_NEED_QT_PLUGINS, 1) {
    DEFINES += BITCOIN_NEED_QT_PLUGINS
    QTPLUGIN += qcncodecs qjpcodecs qtwcodecs qkrcodecs qtaccessiblewidgets
}

INCLUDEPATH += src/leveldb/include src/leveldb/helpers
LIBS += $$PWD/src/leveldb/libleveldb.a $$PWD/src/leveldb/libmemenv.a
SOURCES += src/txdb.cpp \
    src/qt/magi.cpp \
    src/qt/magiaddressvalidator.cpp \
    src/qt/magiamountfield.cpp \
    src/qt/magigui.cpp \
    src/qt/magistrings.cpp \
    src/qt/magiunits.cpp \
    src/magirpc.cpp \
    src/clientversion.cpp \
    src/qt/utilitydialog.cpp
!win32 {
    # we use QMAKE_CXXFLAGS_RELEASE even without RELEASE=1 because we use RELEASE to indicate linking preferences not -O preferences
    genleveldb.commands = cd $$PWD/src/leveldb && CC=$$QMAKE_CC CXX=$$QMAKE_CXX $(MAKE) OPT=\"$$QMAKE_CXXFLAGS $$QMAKE_CXXFLAGS_RELEASE\" libleveldb.a libmemenv.a
} else {
    # make an educated guess about what the ranlib command is called
    isEmpty(QMAKE_RANLIB) {
        QMAKE_RANLIB = $$replace(QMAKE_STRIP, strip, ranlib)
    }
    LIBS += -lshlwapi
    genleveldb.commands = cd $$PWD/src/leveldb && CC=$$QMAKE_CC CXX=$$QMAKE_CXX TARGET_OS=OS_WINDOWS_CROSSCOMPILE $(MAKE) OPT=\"$$QMAKE_CXXFLAGS $$QMAKE_CXXFLAGS_RELEASE\" libleveldb.a libmemenv.a && $$QMAKE_RANLIB $$PWD/src/leveldb/libleveldb.a && $$QMAKE_RANLIB $$PWD/src/leveldb/libmemenv.a
}

genleveldb.target = $$PWD/src/leveldb/libleveldb.a
genleveldb.depends = FORCE
PRE_TARGETDEPS += $$PWD/src/leveldb/libleveldb.a
QMAKE_EXTRA_TARGETS += genleveldb
# Gross ugly hack that depends on qmake internals, unfortunately there is no other way to do it.
QMAKE_CLEAN += $$PWD/src/leveldb/libleveldb.a; cd $$PWD/src/leveldb ; $(MAKE) clean

# regenerate src/build.h
!windows|contains(USE_BUILD_INFO, 1) {
    genbuild.depends = FORCE
    genbuild.commands = cd $$PWD; /bin/sh share/genbuild.sh $$OUT_PWD/build/build.h
    genbuild.target = $$OUT_PWD/build/build.h
    PRE_TARGETDEPS += $$OUT_PWD/build/build.h
    QMAKE_EXTRA_TARGETS += genbuild
    DEFINES += HAVE_BUILD_INFO
}

QMAKE_CXXFLAGS_WARN_ON = -fdiagnostics-show-option -Wall -Wextra -Wformat -Wformat-security -Wno-unused-parameter -Wstack-protector

# Input
DEPENDPATH += src src/json src/qt
HEADERS += \
    src/qt/transactiontablemodel.h \
    src/qt/addresstablemodel.h \
    src/qt/optionsdialog.h \
    src/qt/coincontroldialog.h \
    src/qt/coincontroltreewidget.h \
    src/qt/sendcoinsdialog.h \
    src/qt/addressbookpage.h \
    src/qt/signverifymessagedialog.h \
    src/qt/editaddressdialog.h \
    src/alert.h \
    src/addrman.h \
    src/base58.h \
    src/bignum.h \
    src/checkpoints.h \
    src/compat.h \
    src/coincontrol.h \
    src/sync.h \
    src/util.h \
    src/hash.h \
    src/uint256.h \
    src/kernel.h \
    src/scrypt_mine.h \
    src/pbkdf2.h \
    src/serialize.h \
    src/main.h \
    src/net.h \
    src/key.h \
    src/db.h \
    src/txdb.h \
    src/walletdb.h \
    src/script.h \
    src/init.h \
    src/mruset.h \
    src/magimath.h \
    src/json/json_spirit_writer_template.h \
    src/json/json_spirit_writer.h \
    src/json/json_spirit_value.h \
    src/json/json_spirit_utils.h \
    src/json/json_spirit_stream_reader.h \
    src/json/json_spirit_reader_template.h \
    src/json/json_spirit_reader.h \
    src/json/json_spirit_error_position.h \
    src/json/json_spirit.h \
    src/qt/clientmodel.h \
    src/qt/guiutil.h \
    src/qt/transactionrecord.h \
    src/qt/guiconstants.h \
    src/qt/optionsmodel.h \
    src/qt/monitoreddatamapper.h \
    src/qt/transactiondesc.h \
    src/qt/transactiondescdialog.h \
    src/qt/updatecheck.h \
    src/wallet.h \
    src/keystore.h \
    src/qt/transactionfilterproxy.h \
    src/qt/transactionview.h \
    src/qt/walletmodel.h \
    src/qt/overviewpage.h \
    src/qt/csvmodelwriter.h \
    src/crypter.h \
    src/qt/sendcoinsentry.h \
    src/qt/qvalidatedlineedit.h \
    src/qt/qvaluecombobox.h \
    src/qt/askpassphrasedialog.h \
    src/qt/trafficgraphwidget.h \
    src/protocol.h \
    src/qt/notificator.h \
    src/qt/qtipcserver.h \
    src/allocators.h \
    src/ui_interface.h \
    src/qt/console.h \
    src/qt/rpcconsole.h \
    src/version.h \
    src/netbase.h \
    src/clientversion.h \
    src/hash_magi.h \
    src/hash/sph_types.h \
    src/hash/sph_keccak.h \
    src/hash/sph_haval.h \
    src/hash/sph_ripemd.h \
    src/hash/sph_sha2.h \
    src/hash/sph_tiger.h \
    src/hash/sph_whirlpool.h \
    src/qt/magiaddressvalidator.h \
    src/qt/magiamountfield.h \
    src/qt/magigui.h \
    src/qt/magiunits.h \
    src/magirpc.h \
    src/qt/utilitydialog.h

SOURCES += \
    src/qt/transactiontablemodel.cpp \
    src/qt/addresstablemodel.cpp \
    src/qt/optionsdialog.cpp \
    src/qt/sendcoinsdialog.cpp \
    src/qt/coincontroldialog.cpp \
    src/qt/coincontroltreewidget.cpp \
    src/qt/addressbookpage.cpp \
    src/qt/signverifymessagedialog.cpp \
    src/qt/editaddressdialog.cpp \
    src/qt/trafficgraphwidget.cpp \
    src/alert.cpp \
    src/sync.cpp \
    src/util.cpp \
    src/hash.cpp \
    src/netbase.cpp \
    src/key.cpp \
    src/script.cpp \
    src/main.cpp \
    src/init.cpp \
    src/net.cpp \
    src/checkpoints.cpp \
    src/addrman.cpp \
    src/db.cpp \
    src/walletdb.cpp \
    src/magimath.cpp \
    src/qt/clientmodel.cpp \
    src/qt/guiutil.cpp \
    src/qt/transactionrecord.cpp \
    src/qt/optionsmodel.cpp \
    src/qt/monitoreddatamapper.cpp \
    src/qt/transactiondesc.cpp \
    src/qt/transactiondescdialog.cpp \
    src/qt/updatecheck.cpp \
    src/wallet.cpp \
    src/keystore.cpp \
    src/qt/transactionfilterproxy.cpp \
    src/qt/transactionview.cpp \
    src/qt/walletmodel.cpp \
    src/rpcdump.cpp \
    src/rpcnet.cpp \
    src/rpcmining.cpp \
    src/rpcwallet.cpp \
    src/rpcblockchain.cpp \
    src/rpcrawtransaction.cpp \
    src/qt/overviewpage.cpp \
    src/qt/csvmodelwriter.cpp \
    src/crypter.cpp \
    src/qt/sendcoinsentry.cpp \
    src/qt/qvalidatedlineedit.cpp \
    src/qt/qvaluecombobox.cpp \
    src/qt/askpassphrasedialog.cpp \
    src/protocol.cpp \
    src/qt/notificator.cpp \
    src/qt/qtipcserver.cpp \
    src/qt/console.cpp \
    src/qt/rpcconsole.cpp \
    src/noui.cpp \
    src/kernel.cpp \
    src/pbkdf2.cpp \
    src/hash/keccak.cpp \
    src/hash/haval.cpp \
    src/hash/ripemd.cpp \
    src/hash/sha2.cpp \
    src/hash/sha2big.cpp \
    src/hash/tiger.cpp \
    src/hash/whirlpool.cpp

RESOURCES += \
    src/qt/magi.qrc

FORMS += \
    src/qt/forms/coincontroldialog.ui \
    src/qt/forms/sendcoinsdialog.ui \
    src/qt/forms/addressbookpage.ui \
    src/qt/forms/signverifymessagedialog.ui \
    src/qt/forms/editaddressdialog.ui \
    src/qt/forms/transactiondescdialog.ui \
    src/qt/forms/overviewpage.ui \
    src/qt/forms/sendcoinsentry.ui \
    src/qt/forms/askpassphrasedialog.ui \
    src/qt/forms/rpcconsole.ui \
    src/qt/forms/optionsdialog.ui \
    src/qt/forms/console.ui \
    src/qt/forms/helpmessagedialog.ui

contains(USE_QRCODE, 1) {
HEADERS += src/qt/qrcodedialog.h
SOURCES += src/qt/qrcodedialog.cpp
FORMS += src/qt/forms/qrcodedialog.ui
}

contains(BITCOIN_QT_TEST, 1) {
SOURCES += src/qt/test/test_main.cpp \
    src/qt/test/uritests.cpp
HEADERS += src/qt/test/uritests.h
DEPENDPATH += src/qt/test
QT += testlib
TARGET = m-wallet_test
DEFINES += BITCOIN_QT_TEST
}

CODECFORTR = UTF-8

# for lrelease/lupdate
# also add new translations to src/qt/magi.qrc under translations/
TRANSLATIONS = $$files(src/qt/locale/bitcoin_*.ts)

win32:!cross_compile {
    # Native Windows build
    QMAKE_LRELEASE = $$[QT_INSTALL_BINS]\\lrelease.exe
} else {
    # Everything else (Linux, cross-compile, etc)
    QMAKE_LRELEASE = $$[QT_INSTALL_BINS]/lrelease
}
isEmpty(QM_DIR):QM_DIR = $$PWD/src/qt/locale
# automatically build translations, so they can be included in resource file
TSQM.name = lrelease ${QMAKE_FILE_IN}
TSQM.input = TRANSLATIONS
TSQM.output = $$QM_DIR/${QMAKE_FILE_BASE}.qm
TSQM.commands = $$QMAKE_LRELEASE ${QMAKE_FILE_IN} -qm ${QMAKE_FILE_OUT}
TSQM.CONFIG = no_link
QMAKE_EXTRA_COMPILERS += TSQM

# "Other files" to show in Qt Creator
OTHER_FILES += README.md \
    doc/*.rst \
    doc/*.txt doc/README \
    src/qt/res/magi-qt.rc \
    src/test/*.cpp \
    src/test/*.h \
    src/qt/test/*.cpp \
    src/qt/test/*.h

# platform specific defaults, if not overridden on command line
isEmpty(BOOST_LIB_SUFFIX) {
    macx:BOOST_LIB_SUFFIX = -mt-s
    windows:BOOST_LIB_SUFFIX = -mgw49-mt-s-1_58
}

isEmpty(BOOST_THREAD_LIB_SUFFIX) {
    BOOST_THREAD_LIB_SUFFIX = $$BOOST_LIB_SUFFIX
}

isEmpty(BDB_LIB_PATH) {
    macx:BDB_LIB_PATH = /opt/local/lib/db48
}

isEmpty(BDB_LIB_SUFFIX) {
    macx:BDB_LIB_SUFFIX = -4.8
}

isEmpty(BDB_INCLUDE_PATH) {
    macx:BDB_INCLUDE_PATH = /opt/local/include/db48
}

isEmpty(BOOST_LIB_PATH) {
    macx:BOOST_LIB_PATH = /opt/local/lib
}

isEmpty(BOOST_INCLUDE_PATH) {
    macx:BOOST_INCLUDE_PATH = /opt/local/include
}

windows:DEFINES += WIN32
windows:RC_FILE = src/qt/res/magi-qt.rc

windows:!contains(MINGW_THREAD_BUGFIX, 0) {
    # At least qmake's win32-g++-cross profile is missing the -lmingwthrd
    # thread-safety flag. GCC has -mthreads to enable this, but it doesn't
    # work with static linking. -lmingwthrd must come BEFORE -lmingw, so
    # it is prepended to QMAKE_LIBS_QT_ENTRY.
    # It can be turned off with MINGW_THREAD_BUGFIX=0, just in case it causes
    # any problems on some untested qmake profile now or in the future.
    DEFINES += _MT
    QMAKE_LIBS_QT_ENTRY = -lmingwthrd $$QMAKE_LIBS_QT_ENTRY
}

!windows:!macx {
    DEFINES += LINUX
    LIBS += -lrt
}

macx:HEADERS += src/qt/macdockiconhandler.h src/qt/macnotificationhandler.h
macx:OBJECTIVE_SOURCES += src/qt/macdockiconhandler.mm src/qt/macnotificationhandler.mm
macx:LIBS += -framework Foundation -framework ApplicationServices -framework AppKit -framework CoreServices
macx:DEFINES += MAC_OSX MSG_NOSIGNAL=0
macx:ICON = src/qt/res/icons/magi.icns
macx:QMAKE_CFLAGS_THREAD += -pthread
macx:QMAKE_LFLAGS_THREAD += -pthread
macx:QMAKE_CXXFLAGS_THREAD += -pthread

# Set libraries and includes at end, to use platform-defined defaults if not overridden
INCLUDEPATH += $$OPT_INCLUDE_PATH $$BOOST_INCLUDE_PATH $$BDB_INCLUDE_PATH $$OPENSSL_INCLUDE_PATH $$QRENCODE_INCLUDE_PATH $$GMP_INCLUDE_PATH
LIBS += $$join(OPT_LIB_PATH,,-L,) $$join(BOOST_LIB_PATH,,-L,) $$join(BDB_LIB_PATH,,-L,) $$join(OPENSSL_LIB_PATH,,-L,) $$join(QRENCODE_LIB_PATH,,-L,) $$join(GMP_LIB_PATH,,-L,)
LIBS += -lssl -lgmp -lcrypto -ldb_cxx$$BDB_LIB_SUFFIX
LIBS += $$OPT_LIBS
# -lgdi32 has to happen after -lcrypto (see  #681)
windows:LIBS += -lws2_32 -lshlwapi -lmswsock -lole32 -loleaut32 -luuid -lgdi32
LIBS += -lboost_system$$BOOST_LIB_SUFFIX -lboost_filesystem$$BOOST_LIB_SUFFIX -lboost_program_options$$BOOST_LIB_SUFFIX -lboost_thread$$BOOST_THREAD_LIB_SUFFIX -lboost_chrono$$BOOST_LIB_SUFFIX
windows:LIBS += -lboost_chrono$$BOOST_LIB_SUFFIX

contains(RELEASE, 1) {
    !windows:!macx {
        # Linux: turn dynamic linking back on for c/c++ runtime libraries
        LIBS += -Wl,-Bdynamic
    }
}

system($$QMAKE_LRELEASE -silent $$TRANSLATIONS)
