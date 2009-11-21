.PHONY: coova-chilli coova-chilli-install coova-chilli-clean

coova_chilli_cflags=${build_cflags}
coova_chilli_ldflags=${build_ldflags}
coova_chilli_version=coova-chilli
startuplist=$(build_install_directory)/usr/etc/startup.list

$(coova_chilli_version)/.configured:
	( cd $(coova_chilli_version) && touch configure && rm -f config.cache && \
	  LDFLAGS="${coova_chilli_ldflags}" \
	  CFLAGS="${coova_chilli_cflags}" \
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
	  --enable-shared \
	  --enable-chilliproxy \
	  --enable-miniportal \
         && touch .configured)


coova-chilli: $(coova_chilli_version)/.configured
	$(MAKE) -C $(coova_chilli_version)

coova-chilli-clean:
	rm -f $(coova_chilli_version)/.configured	
	rm -rf $(coova_chilli_version)/install
	$(MAKE) -C $(coova_chilli_version) distclean || echo "Ignoring errors"

coova-chilli-install: coova-chilli
	$(MAKE) -C $(coova_chilli_version) DESTDIR=$(shell pwd)/$(coova_chilli_version)/install install
	${build_toolchain_prefix}strip $(coova_chilli_version)/install/sbin/chilli*
	${build_toolchain_prefix}strip $(coova_chilli_version)/install/lib/lib*.so.0.0.0
	cp -f $(coova_chilli_version)/install/sbin/chilli* $(build_install_directory)/sbin/
	cp -f $(coova_chilli_version)/install/lib/libchilli* $(build_install_directory)/lib/
	cp -f $(coova_chilli_version)/install/lib/libbstring* $(build_install_directory)/lib/
	mkdir -p $(build_install_directory)/usr/etc/init.d
	cp -rf $(coova_chilli_version)/install/etc/* $(build_install_directory)/usr/etc/
	cp -f $(coova_chilli_version)/distro/ubnt/chilli.init $(build_install_directory)/usr/etc/init.d/chilli
	cp -f $(coova_chilli_version)/distro/ubnt/wwwsh $(build_install_directory)/usr/etc/chilli/
	cp -f $(coova_chilli_version)/distro/ubnt/config $(build_install_directory)/usr/etc/chilli/
	cp -f $(coova_chilli_version)/distro/ubnt/ipup.sh $(build_install_directory)/usr/etc/chilli/
	cp -f $(coova_chilli_version)/distro/ubnt/ipdown.sh $(build_install_directory)/usr/etc/chilli/
	cp -f $(coova_chilli_version)/distro/ubnt/chilli.rc $(build_install_directory)/usr/etc/chilli/rc
	if [ "$(grep chilli $startuplist)" = "" ]; then \
		echo "chilli" >> $startuplist; \
	fi
