package=gmp
$(package)_version=6.2.1
$(package)_download_path=https://gmplib.org/download/gmp
$(package)_file_name=$(package)-$($(package)_version).tar.bz2
$(package)_sha256_hash=eae9326beb4158c386e39a356818031bd28f3124cf915f8c5b1dc4c7a36b4d7c

define $(package)_preprocess_cmds

endef

define $(package)_set_vars
  $(package)_config_opts=--disable-shared --enable-cxx CC_FOR_BUILD=$(build_CC)
  $(package)_config_opts_linux=--with-pic
  $(package)_config_opts_freebsd=--with-pic
  $(package)_config_opts_netbsd=--with-pic
  $(package)_config_opts_openbsd=--with-pic
  $(package)_config_opts_android=--with-pic
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
