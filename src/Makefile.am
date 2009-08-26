lib_LTLIBRARIES = libchilli.la
sbin_PROGRAMS = chilli chilli_response chilli_radconfig \
chilli_query chilli_opt chilli_dog chilli_rtmon

# add -pg to enable gprof
AM_CFLAGS = -D_GNU_SOURCE -Wall -fno-builtin -fstrict-aliasing -ansi\
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
chilli.h options.h util.c garden.c garden.h \
dns.c dns.h session.c session.h limits.h pkt.h pkt.c \
chksum.c net.h net.c ms_chap.c options.c 

# AM_LDFLAGS = -lchilli

chilli_SOURCES= main.c
chilli_radconfig_SOURCES = main-radconfig.c 
chilli_response_SOURCES = main-response.c 
chilli_query_SOURCES = main-query.c 
chilli_opt_SOURCES = main-opt.c ${cmdline_sources}
chilli_rtmon_SOURCES = main-rtmon.c 
chilli_dog_SOURCES = main-dog.c 
#test_radius_SOURCES = test-radius.c 
#test_dhcp_SOURCES = test-dhcp.c 

LDADD = libchilli.la $(top_builddir)/bstring/libbstring.la 
