AUTOMAKE_OPTIONS=foreign

lib_LTLIBRARIES = libchilli.la
sbin_PROGRAMS = chilli chilli_response chilli_radconfig chilli_query chilli_opt

if WITH_CHILLIPROXY
sbin_PROGRAMS += chilli_proxy
chilli_proxy_SOURCES = main-proxy.c 
chilli_proxy_LDADD = libchilli.la $(top_builddir)/bstring/libbstring.la ${LIBOPENSSL} ${LIBPCAP}
if WITH_CURL
chilli_proxy_LDADD += -lcurl -lz 
endif
endif

if WITH_CHILLIREDIR
sbin_PROGRAMS += chilli_redir
chilli_redir_SOURCES = main-redir.c 
chilli_redir_LDADD = libchilli.la $(top_builddir)/bstring/libbstring.la ${LIBOPENSSL} ${LIBPCAP}
if WITH_CURL
chilli_redir_LDADD += -lcurl -lz 
endif
endif

if WITH_RTMON
sbin_PROGRAMS += chilli_rtmon
chilli_rtmon_SOURCES = main-rtmon.c 
endif

# add -pg to enable gprof
AM_CFLAGS = -D_GNU_SOURCE -Wall -fno-builtin -fstrict-aliasing \
  -O2 -fomit-frame-pointer -funroll-loops -pipe \
 -DDEFCHILLICONF='"$(sysconfdir)/chilli.conf"'\
 -DDEFPIDFILE='"$(localstatedir)/run/chilli.pid"'\
 -DDEFSTATEDIR='"$(localstatedir)/run"'\
 -DDEFCMDSOCK='"$(localstatedir)/run/chilli.sock"'\
 -DSBINDIR='"$(sbindir)"' -I$(top_builddir)/bstring 

cmdline_sources=cmdline.c cmdline.h 

libchilli_la_SOURCES = \
chilli.c tun.c tun.h ippool.c ippool.h radius.h radius.c \
md5.c md5.h redir.h redir.c dhcp.c dhcp.h syserr.c syserr.h \
iphash.c iphash.h lookup3.c sfhash.c lookup.c lookup.h \
system.h cmdsock.c cmdsock.h radius_wispr.h radius_chillispot.h \
chilli.h options.h util.c garden.c garden.h ssl.h ssl.c \
dns.c dns.h session.c session.h limits.h pkt.h pkt.c \
chksum.c net.h net.c ms_chap.c options.c statusfile.c

# AM_LDFLAGS = -lchilli

chilli_SOURCES= main.c
chilli_radconfig_SOURCES = main-radconfig.c 
chilli_response_SOURCES = main-response.c 
chilli_query_SOURCES = main-query.c 
chilli_opt_SOURCES = main-opt.c ${cmdline_sources}
#test_radius_SOURCES = test-radius.c 
#test_dhcp_SOURCES = test-dhcp.c 

LDADD = libchilli.la $(top_builddir)/bstring/libbstring.la 
if WITH_OPENSSL
LDADD += ${LIBOPENSSL}
endif
if WITH_PCAP
LDADD += ${LIBPCAP}
endif
