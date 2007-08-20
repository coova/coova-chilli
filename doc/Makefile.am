man_MANS = chilli.8 chilli.conf.5 chilli_query.1 chilli_response.1 \
chilli_radconfig.1 chilli-radius.5

man_aux = $(man_MANS:=.in)
EXTRA_DIST = $(man_aux) \
dictionary.chillispot hotspotlogin.cgi attributes fmttxt.pl

edit = sed \
	-e 's,@SBINDIR\@,$(sbindir),g' \
	-e 's,@INITDIR\@,$(sysconfdir)/init.d,g' \
	-e 's,@VARRUN\@,$(localstatedir)/run,g' \
	-e 's,@ETCCHILLI\@,$(sysconfdir)/chilli,g' \
	-e 's,@SYSCONFDIR\@,$(sysconfdir),g' \
	-e 's,@PREFIX\@,$(prefix),g'

chilli.8: Makefile chilli.8.in
	rm -f chilli.8 chilli.8.tmp
	$(edit) chilli.8.in >chilli.8.tmp
	mv chilli.8.tmp chilli.8

chilli.conf.5: Makefile chilli.conf.5.in
	rm -f chilli.conf.5 chilli.conf.5.tmp
	$(edit) chilli.conf.5.in >chilli.conf.5.tmp
	mv chilli.conf.5.tmp chilli.conf.5

chilli_query.1: Makefile chilli_query.1.in
	rm -f chilli_query.1 chilli_query.1.tmp
	$(edit) chilli_query.1.in >chilli_query.1.tmp
	mv chilli_query.1.tmp chilli_query.1

chilli_response.1: Makefile chilli_response.1.in
	rm -f chilli_response.1 chilli_response.1.tmp
	$(edit) chilli_response.1.in >chilli_response.1.tmp
	mv chilli_response.1.tmp chilli_response.1

chilli-radius.5: Makefile fmttxt.pl chilli-radius.5.in attributes
	rm -f chilli-radius.5 chilli-radius.5.tmp
	$(edit) chilli-radius.5.in >chilli-radius.5.tmp
	perl fmttxt.pl chilli-radius < attributes > chilli-radius.5
	rm -f chilli-radius.5.tmp

chilli_radconfig.1: Makefile chilli_radconfig.1.in
	rm -f chilli_radconfig.1 chilli_radconfig.1.tmp
	$(edit) chilli_radconfig.1.in >chilli_radconfig.1.tmp
	mv chilli_radconfig.1.tmp chilli_radconfig.1


