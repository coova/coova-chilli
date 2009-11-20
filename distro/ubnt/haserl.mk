.PHONY: haserl haserl-install haserl-clean

haserl_cflags=${build_cflags}
haserl_ldflags=${build_ldflags}
haserl_version=haserl

$(haserl_version)/.configured:
	( cd $(haserl_version) && touch configure && rm -f config.cache && \
	  LDFLAGS="${haserl_ldflags}" \
	  CFLAGS="${haserl_cflags}" \
	  CC="${build_toolchain_prefix}gcc" \
	  AR="${build_toolchain_prefix}ar" \
	  LD="${build_toolchain_prefix}ld" \
	  CXX="${build_toolchain_prefix}g++" \
	  RANLIB="${build_toolchain_prefix}ranlib" \
	  PREFIX=${build_install_directory} \
	  EPREFIX=${build_install_directory} \
	  ./configure --prefix= \
	  --host=mips-linux \
	  --build=i686-linux \
         && touch .configured)


haserl: $(haserl_version)/.configured
	$(MAKE) -C $(haserl_version)

haserl-clean:
	rm -f $(haserl_version)/.configured	
	rm -rf $(haserl_version)/install
	$(MAKE) -C $(haserl_version) distclean || echo "Ignoring errors"

haserl-install: haserl
	${build_toolchain_prefix}strip $(haserl_version)/src/haserl
	mkdir -p $(build_install_directory)/usr/bin
	cp -f $(haserl_version)/src/haserl $(build_install_directory)/usr/bin/
