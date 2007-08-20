sbin_PROGRAMS = chilli chilli_response chilli_radconfig chilli_query test_radius

# add -pg to enable gprof
AM_CFLAGS = -D_GNU_SOURCE -Wall -fno-builtin -fstrict-aliasing -ansi\
 -DDEFCHILLICONF='"$(sysconfdir)/chilli.conf"'\
 -DDEFPIDFILE='"$(localstatedir)/run/chilli.pid"'\
 -DDEFSTATEDIR='"$(localstatedir)/run"'\
 -DDEFCMDSOCK='"$(localstatedir)/run/chilli.sock"'\
 -DSBINDIR='"$(sbindir)"' -I$(top_builddir)/bstring

chilli_SOURCES = \
main.c chilli.c options.c tun.c tun.h cmdline.c cmdline.h ippool.c ippool.h radius.h radius.c \
md5.c md5.h redir.h redir.c dhcp.c dhcp.h syserr.c syserr.h iphash.c iphash.h lookup3.c lookup.c lookup.h \
system.h cmdsock.h radius_wispr.h radius_chillispot.h chilli.h options.h util.c garden.c garden.h

chilli_LDFLAGS = 

chilli_radconfig_SOURCES = main-radconfig.c options.c cmdline.c radius.c md5.c syserr.c system.h garden.c
chilli_response_SOURCES = main-response.c md5.c
chilli_query_SOURCES = main-query.c cmdsock.h

test_radius_SOURCES = test-radius.c options.c cmdline.c radius.c md5.c syserr.c system.h garden.c

LDADD = $(top_builddir)/bstring/libbstring.la
