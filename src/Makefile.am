lib_LTLIBRARIES = libchilli.la
sbin_PROGRAMS = chilli chilli_response chilli_radconfig chilli_query test_radius

# add -pg to enable gprof
AM_CFLAGS = -D_GNU_SOURCE -Wall -fno-builtin -fstrict-aliasing -ansi\
 -DDEFCHILLICONF='"$(sysconfdir)/chilli.conf"'\
 -DDEFPIDFILE='"$(localstatedir)/run/chilli.pid"'\
 -DDEFSTATEDIR='"$(localstatedir)/run"'\
 -DDEFCMDSOCK='"$(localstatedir)/run/chilli.sock"'\
 -DSBINDIR='"$(sbindir)"' -I$(top_builddir)/bstring

libchilli_la_SOURCES = \
chilli.c options.c tun.c tun.h cmdline.c cmdline.h ippool.c ippool.h radius.h radius.c \
md5.c md5.h redir.h redir.c dhcp.c dhcp.h syserr.c syserr.h iphash.c iphash.h lookup3.c lookup.c lookup.h \
system.h cmdsock.c cmdsock.h radius_wispr.h radius_chillispot.h chilli.h options.h util.c garden.c garden.h\
dns.c session.c

# AM_LDFLAGS = -lchilli

chilli_SOURCES= main.c
chilli_radconfig_SOURCES = main-radconfig.c 
chilli_response_SOURCES = main-response.c 
chilli_query_SOURCES = main-query.c 
test_radius_SOURCES = test-radius.c 

LDADD = libchilli.la $(top_builddir)/bstring/libbstring.la 
