AUTOMAKE_OPTIONS=foreign

EXTRA_DIST = cmdline.ggo cmdline.patch \
linux/Makefile linux/xt_coova.c linux/xt_coova.h \
linux/ipt_coova.h linux/libxt_coova.c

chilliincludedir = $(includedir)/chilli
chilliinclude_HEADERS = \
chilli.h session.h cmdsock.h garden.h radius.h options.h \
tun.h ippool.h md5.h redir.h dhcp.h syserr.h iphash.h \
radius_wispr.h radius_chillispot.h ssl.h dns.h net.h \
pkt.h conn.h lookup.h chilli_limits.h cmdline.h \
radius_pkt.h ../bstring/bstrlib.h ../config.h system.h 

lib_LTLIBRARIES = libchilli.la
noinst_PROGRAMS = test_dhcp
sbin_PROGRAMS = \
chilli chilli_response chilli_radconfig chilli_query chilli_opt 

suid_programs =

libchilli_la_SOURCES = \
chilli.c tun.c ippool.c radius.c md5.c redir.c dhcp.c syserr.c \
iphash.c lookup3.c sfhash.c lookup.c system.h cmdsock.c util.c \
garden.c ssl.c dns.c session.c pkt.c chksum.c net.c \
ms_chap.c options.c statusfile.c conn.c 

AM_CFLAGS = -D_GNU_SOURCE -Wall -Werror -fno-builtin -fno-strict-aliasing \
  -O2 -fomit-frame-pointer -funroll-loops -pipe \
 -DDEFCHILLICONF='"$(sysconfdir)/chilli.conf"'\
 -DDEFPIDFILE='"$(localstatedir)/run/chilli.pid"'\
 -DDEFSTATEDIR='"$(localstatedir)/run"'\
 -DSBINDIR='"$(sbindir)"' -I$(top_builddir)/bstring 

cmdline_sources=cmdline.c 

chilli_SOURCES= main.c
chilli_radconfig_SOURCES = main-radconfig.c 
chilli_response_SOURCES = main-response.c 
chilli_query_SOURCES = main-query.c 
chilli_opt_SOURCES = main-opt.c ${cmdline_sources}
#queue_SOURCES = queue_test.c 
#test_radius_SOURCES = test-radius.c 
test_dhcp_SOURCES = test-dhcp.c 

LDADD = libchilli.la $(top_builddir)/bstring/libbstring.la ${LIBRT}

if WITH_OPENSSL
LDADD += ${LIBSSL}
endif

if WITH_MATRIXSSL
libchilli_la_SOURCES += matrixssl.c matrixssl.h
#LDADD += ${LIBSSL}
LDADD += -lmatrixssl
endif

if WITH_NETFILTER_QUEUE
libchilli_la_SOURCES += queue.c
LDADD += ${LIBNETFILTER_QUEUE}
endif

# add -pg to enable gprof
if WITH_NETNAT
libchilli_la_SOURCES += nat.c nat.h
endif

if WITH_PCAP
LDADD += ${LIBPCAP}
endif

if WITH_RTMON
#sbin_PROGRAMS += chilli_rtmon
#chilli_rtmon_SOURCES = main-rtmon.c 
libchilli_la_SOURCES += rtmon.c rtmon.h
endif

if WITH_CHILLIPROXY
sbin_PROGRAMS += chilli_proxy
chilli_proxy_SOURCES = main-proxy.c 
chilli_proxy_LDADD = ${LDADD}
if WITH_CURL
chilli_proxy_LDADD += -lcurl -lz 
endif
endif

if WITH_CHILLIRADSEC
sbin_PROGRAMS += chilli_radsec
chilli_radsec_SOURCES = main-radsec.c 
chilli_radsec_LDADD = ${LDADD}
endif

if WITH_CHILLISCRIPT
sbin_PROGRAMS += chilli_script
suid_programs += chilli_script
chilli_script_SOURCES = main-script.c 
chilli_script_LDADD = ${LDADD}
endif

if WITH_CHILLIREDIR
sbin_PROGRAMS += chilli_redir
chilli_redir_SOURCES = main-redir.c 
chilli_redir_LDADD = ${LDADD}
if WITH_CURL
chilli_redir_LDADD += -lcurl -lz 
endif
endif

if WITH_NETFILTER_COOVA
SUBDIRS = linux
libchilli_la_SOURCES += kcoova.c
endif

install-exec-hook:
	@for f in $(suid_programs); do \
		echo "Setting SUID on $(DESTDIR)$(sbindir)/$$f !"; \
		chown root $(DESTDIR)$(sbindir)/$$f; \
		chmod u+s $(DESTDIR)$(sbindir)/$$f; \
	done

cmdline.c cmdline.h: cmdline.ggo cmdline.patch
	gengetopt -C < cmdline.ggo 
	patch -p0 < cmdline.patch
