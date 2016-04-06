KERNEL_DIR ?= /usr/src/linux-headers-$(shell uname -r)

obj-m += xt_coova.o

all: libxt_coova.so
	make -C ${KERNEL_DIR} M=$$PWD;

modules:
	make -C ${KERNEL_DIR} M=$$PWD $@;

modules_install:
	make -C ${KERNEL_DIR} M=$$PWD $@;

modules_clean:
	make -C ${KERNEL_DIR} M=$$PWD $@;

clean:
	rm -f *.o *~ *.ko *.mod.c Module.markers modules.order Module.symvers libxt_coova.so

lib%.so: lib%.o
	$(CC) $(CFLAGS) -shared -o $@ $^;

lib%.o: lib%.c
	$(CC) $(CFLAGS) -D_INIT=lib$*_init -c -o $@ $<;

install: modules_install libxt_coova.so
	mkdir -p $(DESTDIR)/usr/lib/iptables/
	cp libxt_coova.so $(DESTDIR)/usr/lib/iptables/

distdir:

distclean: clean
