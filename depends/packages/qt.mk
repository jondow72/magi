package=qt
$(package)_version=5.15.3
$(package)_download_path=https://download.qt.io/official_releases/qt/5.15/$($(package)_version)/submodules
$(package)_suffix=everywhere-opensource-src-$($(package)_version).tar.xz
$(package)_file_name=qtbase-$($(package)_suffix)
$(package)_sha256_hash=26394ec9375d52c1592bd7b689b1619c6b8dbe9b6f91fdd5c355589787f3a0b6
$(package)_linux_dependencies=freetype fontconfig libxcb libxkbcommon libxcb_util libxcb_util_render libxcb_util_keysyms libxcb_util_image libxcb_util_wm
$(package)_qt_libs=corelib network widgets gui plugins testlib
$(package)_linguist_tools = lrelease lupdate lconvert
$(package)_patches = qt.pro qttools_src.pro
$(package)_patches += fix_qt_pkgconfig.patch mac-qmake.conf fix_no_printer.patch no-xlib.patch
$(package)_patches += dont_hardcode_x86_64.patch fix_montery_include.patch
$(package)_patches += fix_android_jni_static.patch dont_hardcode_pwd.patch
$(package)_patches += qtbase-moc-ignore-gcc-macro.patch fix_limits_header.patch
$(package)_patches += use_android_ndk23.patch
$(package)_patches += rcc_hardcode_timestamp.patch

$(package)_qttranslations_file_name=qttranslations-$($(package)_suffix)
$(package)_qttranslations_sha256_hash=5d7869f670a135ad0986e266813b9dd5bbae2b09577338f9cdf8904d4af52db0

$(package)_qttools_file_name=qttools-$($(package)_suffix)
$(package)_qttools_sha256_hash=463b2fe71a085e7ab4e39333ae360ab0ec857b966d7a08f752c427e5df55f90d

$(package)_extra_sources  = $($(package)_qttranslations_file_name)
$(package)_extra_sources += $($(package)_qttools_file_name)

define $(package)_set_vars
$(package)_config_opts_release = -release
$(package)_config_opts_release += -silent
$(package)_config_opts_debug = -debug
$(package)_config_opts_debug += -optimized-tools
$(package)_config_opts += -bindir $(build_prefix)/bin
$(package)_config_opts += -c++std c++17
$(package)_config_opts += -confirm-license
$(package)_config_opts += -hostprefix $(build_prefix)
$(package)_config_opts += -no-compile-examples
$(package)_config_opts += -no-cups
$(package)_config_opts += -no-egl
$(package)_config_opts += -no-eglfs
$(package)_config_opts += -no-evdev
$(package)_config_opts += -no-gif
$(package)_config_opts += -no-glib
$(package)_config_opts += -no-icu
$(package)_config_opts += -no-ico
$(package)_config_opts += -no-iconv
$(package)_config_opts += -no-kms
$(package)_config_opts += -no-linuxfb
$(package)_config_opts += -no-libjpeg
$(package)_config_opts += -no-libproxy
$(package)_config_opts += -no-libudev
$(package)_config_opts += -no-mtdev
$(package)_config_opts += -no-openssl
$(package)_config_opts += -no-openvg
$(package)_config_opts += -no-reduce-relocations
$(package)_config_opts += -no-schannel
$(package)_config_opts += -no-sctp
$(package)_config_opts += -no-securetransport
$(package)_config_opts += -no-sql-db2
$(package)_config_opts += -no-sql-ibase
$(package)_config_opts += -no-sql-oci
$(package)_config_opts += -no-sql-tds
$(package)_config_opts += -no-sql-mysql
$(package)_config_opts += -no-sql-odbc
$(package)_config_opts += -no-sql-psql
$(package)_config_opts += -no-sql-sqlite
$(package)_config_opts += -no-sql-sqlite2
$(package)_config_opts += -no-system-proxies
$(package)_config_opts += -no-use-gold-linker
$(package)_config_opts += -no-zstd
$(package)_config_opts += -nomake examples
$(package)_config_opts += -nomake tests
$(package)_config_opts += -nomake tools
$(package)_config_opts += -opensource
$(package)_config_opts += -pkg-config
$(package)_config_opts += -prefix $(host_prefix)
$(package)_config_opts += -qt-libpng
$(package)_config_opts += -qt-pcre
$(package)_config_opts += -qt-harfbuzz
$(package)_config_opts += -qt-zlib
$(package)_config_opts += -static
$(package)_config_opts += -v
$(package)_config_opts += -no-feature-bearermanagement
$(package)_config_opts += -no-feature-colordialog
$(package)_config_opts += -no-feature-commandlineparser
$(package)_config_opts += -no-feature-concurrent
$(package)_config_opts += -no-feature-dial
$(package)_config_opts += -no-feature-fontcombobox
$(package)_config_opts += -no-feature-ftp
$(package)_config_opts += -no-feature-http
$(package)_config_opts += -no-feature-image_heuristic_mask
$(package)_config_opts += -no-feature-keysequenceedit
$(package)_config_opts += -no-feature-lcdnumber
$(package)_config_opts += -no-feature-networkdiskcache
$(package)_config_opts += -no-feature-networkproxy
$(package)_config_opts += -no-feature-pdf
$(package)_config_opts += -no-feature-printdialog
$(package)_config_opts += -no-feature-printer
$(package)_config_opts += -no-feature-printpreviewdialog
$(package)_config_opts += -no-feature-printpreviewwidget
$(package)_config_opts += -no-feature-sessionmanager
$(package)_config_opts += -no-feature-socks5
$(package)_config_opts += -no-feature-sql
$(package)_config_opts += -no-feature-sqlmodel
$(package)_config_opts += -no-feature-statemachine
$(package)_config_opts += -no-feature-syntaxhighlighter
$(package)_config_opts += -no-feature-textbrowser
$(package)_config_opts += -no-feature-textmarkdownwriter
$(package)_config_opts += -no-feature-textodfwriter
$(package)_config_opts += -no-feature-topleveldomain
$(package)_config_opts += -no-feature-udpsocket
$(package)_config_opts += -no-feature-undocommand
$(package)_config_opts += -no-feature-undogroup
$(package)_config_opts += -no-feature-undostack
$(package)_config_opts += -no-feature-undoview
$(package)_config_opts += -no-feature-vnc
$(package)_config_opts += -no-feature-wizard
$(package)_config_opts += -no-feature-xml

$(package)_config_opts_darwin = -no-dbus
$(package)_config_opts_darwin += -no-opengl
$(package)_config_opts_darwin += -pch
$(package)_config_opts_darwin += -no-feature-corewlan
$(package)_config_opts_darwin += -no-freetype
$(package)_config_opts_darwin += QMAKE_MACOSX_DEPLOYMENT_TARGET=$(OSX_MIN_VERSION)

ifneq ($(build_os),darwin)
$(package)_config_opts_darwin += -xplatform macx-clang-linux
$(package)_config_opts_darwin += -device-option MAC_SDK_PATH=$(OSX_SDK)
$(package)_config_opts_darwin += -device-option MAC_SDK_VERSION=$(OSX_SDK_VERSION)
$(package)_config_opts_darwin += -device-option CROSS_COMPILE="$(host)-"
$(package)_config_opts_darwin += -device-option MAC_TARGET=$(host)
$(package)_config_opts_darwin += -device-option XCODE_VERSION=$(XCODE_VERSION)
endif

ifneq ($(build_arch),$(host_arch))
$(package)_config_opts_aarch64_darwin += -device-option QMAKE_APPLE_DEVICE_ARCHS=arm64
$(package)_config_opts_x86_64_darwin += -device-option QMAKE_APPLE_DEVICE_ARCHS=x86_64
endif

$(package)_config_opts_linux = -xcb
$(package)_config_opts_linux += -no-xcb-xlib
$(package)_config_opts_linux += -no-feature-xlib
$(package)_config_opts_linux += -system-freetype
$(package)_config_opts_linux += -fontconfig
$(package)_config_opts_linux += -no-opengl
$(package)_config_opts_linux += -no-feature-vulkan
$(package)_config_opts_linux += -dbus-runtime
$(package)_config_opts_arm_linux += -platform linux-g++ -xplatform bitcoin-linux-g++
$(package)_config_opts_i686_linux  = -xplatform linux-g++-32
ifneq (,$(findstring -stdlib=libc++,$($(1)_cxx)))
$(package)_config_opts_x86_64_linux = -xplatform linux-clang-libc++
else
$(package)_config_opts_x86_64_linux = -xplatform linux-g++-64
endif
$(package)_config_opts_aarch64_linux = -xplatform linux-aarch64-gnu-g++
$(package)_config_opts_powerpc64_linux = -platform linux-g++ -xplatform bitcoin-linux-g++
$(package)_config_opts_powerpc64le_linux = -platform linux-g++ -xplatform bitcoin-linux-g++
$(package)_config_opts_riscv64_linux = -platform linux-g++ -xplatform bitcoin-linux-g++
$(package)_config_opts_s390x_linux = -platform linux-g++ -xplatform bitcoin-linux-g++

$(package)_config_opts_mingw32 = -no-opengl
$(package)_config_opts_mingw32 += -no-dbus
$(package)_config_opts_mingw32 += -no-freetype
$(package)_config_opts_mingw32 += -xplatform win32-g++
$(package)_config_opts_mingw32 += "QMAKE_CFLAGS = '$($(package)_cflags) $($(package)_cppflags)'"
$(package)_config_opts_mingw32 += "QMAKE_CXX = '$($(package)_cxx)'"
$(package)_config_opts_mingw32 += "QMAKE_CXXFLAGS = '$($(package)_cflags) $($(package)_cppflags)'"
$(package)_config_opts_mingw32 += "QMAKE_LFLAGS = '$($(package)_ldflags)'"
$(package)_config_opts_mingw32 += -device-option CROSS_COMPILE="$(host)-"
$(package)_config_opts_mingw32 += -pch

$(package)_config_opts_android = -xplatform android-clang
$(package)_config_opts_android += -android-sdk $(ANDROID_SDK)
$(package)_config_opts_android += -android-ndk $(ANDROID_NDK)
$(package)_config_opts_android += -android-ndk-platform android-$(ANDROID_API_LEVEL)
$(package)_config_opts_android += -egl
$(package)_config_opts_android += -no-dbus
$(package)_config_opts_android += -opengl es2
$(package)_config_opts_android += -qt-freetype
$(package)_config_opts_android += -no-fontconfig
$(package)_config_opts_android += -L $(host_prefix)/lib
$(package)_config_opts_android += -I $(host_prefix)/include
$(package)_config_opts_android += -pch
$(package)_config_opts_android += -no-feature-vulkan

$(package)_config_opts_aarch64_android += -android-arch arm64-v8a
$(package)_config_opts_armv7a_android += -android-arch armeabi-v7a
$(package)_config_opts_x86_64_android += -android-arch x86_64
endef

define $(package)_fetch_cmds
$(call fetch_file,$(package),$($(package)_download_path),$($(package)_download_file),$($(package)_file_name),$($(package)_sha256_hash)) && \
$(call fetch_file,$(package),$($(package)_download_path),$($(package)_qttranslations_file_name),$($(package)_qttranslations_file_name),$($(package)_qttranslations_sha256_hash)) && \
$(call fetch_file,$(package),$($(package)_download_path),$($(package)_qttools_file_name),$($(package)_qttools_file_name),$($(package)_qttools_sha256_hash))
endef

define $(package)_extract_cmds
  mkdir -p $($(package)_extract_dir) && \
  echo "$($(package)_sha256_hash)  $($(package)_source)" > $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  echo "$($(package)_qttranslations_sha256_hash)  $($(package)_source_dir)/$($(package)_qttranslations_file_name)" >> $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  echo "$($(package)_qttools_sha256_hash)  $($(package)_source_dir)/$($(package)_qttools_file_name)" >> $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  $(build_SHA256SUM) -c $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  mkdir qtbase && \
  $(build_TAR) --no-same-owner --strip-components=1 -xf $($(package)_source) -C qtbase && \
  mkdir qttranslations && \
  $(build_TAR) --no-same-owner --strip-components=1 -xf $($(package)_source_dir)/$($(package)_qttranslations_file_name) -C qttranslations && \
  mkdir qttools && \
  $(build_TAR) --no-same-owner --strip-components=1 -xf $($(package)_source_dir)/$($(package)_qttools_file_name) -C qttools
endef

# Preprocessing steps work as follows:
#
# 1. Apply our patches to the extracted source. See each patch for more info.
#
# 2. Create a macOS-Clang-Linux mkspec using our mac-qmake.conf.
#
# 3. After making a copy of the mkspec for the linux-arm-gnueabi host, named
# bitcoin-linux-g++, replace instances of linux-arm-gnueabi with $(host). This
# way we can generically support hosts like riscv64-linux-gnu, which Qt doesn't
# ship a mkspec for. See it's usage in config_opts_* above.
#
# 4. Put our C, CXX and LD FLAGS into gcc-base.conf. Only used for non-host builds.
#
# 5. Do similar for the win32-g++ mkspec.
#
# 6. In clang.conf, swap out clang & clang++, for our compiler + flags. See #17466.
#
# 7. Adjust a regex in toolchain.prf, to accommodate Guix's usage of
# CROSS_LIBRARY_PATH. See #15277.
define $(package)_preprocess_cmds
  cp $($(package)_patch_dir)/qt.pro qt.pro && \
  cp $($(package)_patch_dir)/qttools_src.pro qttools/src/src.pro && \
  patch -p1 -i $($(package)_patch_dir)/dont_hardcode_pwd.patch && \
  patch -p1 -i $($(package)_patch_dir)/fix_qt_pkgconfig.patch && \
  patch -p1 -i $($(package)_patch_dir)/fix_no_printer.patch && \
  patch -p1 -i $($(package)_patch_dir)/fix_android_jni_static.patch && \
  patch -p1 -i $($(package)_patch_dir)/no-xlib.patch && \
  patch -p1 -i $($(package)_patch_dir)/dont_hardcode_x86_64.patch && \
  patch -p1 -i $($(package)_patch_dir)/qtbase-moc-ignore-gcc-macro.patch && \
  patch -p1 -i $($(package)_patch_dir)/fix_limits_header.patch && \
  patch -p1 -i $($(package)_patch_dir)/fix_montery_include.patch && \
  patch -p1 -i $($(package)_patch_dir)/use_android_ndk23.patch && \
  patch -p1 -i $($(package)_patch_dir)/rcc_hardcode_timestamp.patch && \
  mkdir -p qtbase/mkspecs/macx-clang-linux &&\
  cp -f qtbase/mkspecs/macx-clang/qplatformdefs.h qtbase/mkspecs/macx-clang-linux/ &&\
  cp -f $($(package)_patch_dir)/mac-qmake.conf qtbase/mkspecs/macx-clang-linux/qmake.conf && \
  cp -r qtbase/mkspecs/linux-arm-gnueabi-g++ qtbase/mkspecs/bitcoin-linux-g++ && \
  sed -i.old "s/arm-linux-gnueabi-/$(host)-/g" qtbase/mkspecs/bitcoin-linux-g++/qmake.conf && \
  echo "!host_build: QMAKE_CFLAGS     += $($(package)_cflags) $($(package)_cppflags)" >> qtbase/mkspecs/common/gcc-base.conf && \
  echo "!host_build: QMAKE_CXXFLAGS   += $($(package)_cxxflags) $($(package)_cppflags)" >> qtbase/mkspecs/common/gcc-base.conf && \
  echo "!host_build: QMAKE_LFLAGS     += $($(package)_ldflags)" >> qtbase/mkspecs/common/gcc-base.conf && \
  sed -i.old "s|QMAKE_CC                = \$$$$\$$$${CROSS_COMPILE}clang|QMAKE_CC                = $($(package)_cc)|" qtbase/mkspecs/common/clang.conf && \
  sed -i.old "s|QMAKE_CXX               = \$$$$\$$$${CROSS_COMPILE}clang++|QMAKE_CXX               = $($(package)_cxx)|" qtbase/mkspecs/common/clang.conf && \
  sed -i.old "s/LIBRARY_PATH/(CROSS_)?\0/g" qtbase/mkspecs/features/toolchain.prf
endef

define $(package)_config_cmds
  export PKG_CONFIG_SYSROOT_DIR=/ && \
  export PKG_CONFIG_LIBDIR=$(host_prefix)/lib/pkgconfig && \
  export QT_MAC_SDK_NO_VERSION_CHECK=1 && \
  cd qtbase && \
  ./configure -top-level $($(package)_config_opts)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) -C qtbase INSTALL_ROOT=$($(package)_staging_dir) install && \
  $(MAKE) -C qttools/src/linguist INSTALL_ROOT=$($(package)_staging_dir) $(addsuffix -install_subtargets,$(addprefix sub-,$($(package)_linguist_tools))) && \
  $(MAKE) -C qttranslations INSTALL_ROOT=$($(package)_staging_dir) install_subtargets && \
  mkdir -p $($(package)_staging_dir)/share/qt5 && \
  cp -r $($(package)_extract_dir)/qtbase/mkspecs $($(package)_staging_dir)/share/qt5/
endef

define $(package)_postprocess_cmds
  rm -rf native/lib/ lib/cmake/ && \
  rm -f lib/lib*.la
endef
